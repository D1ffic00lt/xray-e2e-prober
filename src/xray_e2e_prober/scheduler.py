"""Bounded asyncio scheduler with per-check overlap protection."""

from __future__ import annotations

import asyncio
import hashlib
import logging
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from time import monotonic
from typing import Any

logger = logging.getLogger(__name__)


class SchedulerAdmissionError(RuntimeError):
    """A manual cycle could not enter the bounded scheduler."""


@dataclass(frozen=True, slots=True)
class ScheduledCheck:
    check_id: str
    generation: str | int
    interval_seconds: float
    payload: Any = field(compare=False, default=None)


@dataclass(slots=True)
class _WorkItem:
    check: ScheduledCheck
    future: asyncio.Future[Any] | None = None


class Scheduler:
    def __init__(
        self,
        runner: Callable[[ScheduledCheck], Awaitable[Any]],
        *,
        concurrency: int,
        max_queue: int,
        on_error: Callable[[ScheduledCheck, str], Awaitable[None] | None] | None = None,
    ) -> None:
        if concurrency < 1 or max_queue < 1:
            raise ValueError("scheduler limits must be positive")
        self._runner = runner
        self._on_error = on_error
        self._queue: asyncio.Queue[_WorkItem] = asyncio.Queue(maxsize=max_queue)
        self._concurrency = concurrency
        self._jobs: dict[str, ScheduledCheck] = {}
        self._producers: dict[str, asyncio.Task[None]] = {}
        self._workers: list[asyncio.Task[None]] = []
        self._queued: set[str] = set()
        self._running: set[str] = set()
        self._queued_generations: dict[str, str | int] = {}
        self._running_generations: dict[str, str | int] = {}
        self._known_generations: dict[str, str | int | None] = {}
        self._started = False
        self._stopping = False

    @property
    def queue_size(self) -> int:
        return self._queue.qsize()

    @property
    def running(self) -> frozenset[str]:
        return frozenset(self._running)

    async def start(self) -> None:
        if self._started:
            return
        self._started = True
        self._stopping = False
        self._workers = [
            asyncio.create_task(self._worker(), name=f"prober-worker-{index}")
            for index in range(self._concurrency)
        ]
        for job in self._jobs.values():
            self._start_producer(job)

    async def update(self, checks: Iterable[ScheduledCheck]) -> None:
        desired = {check.check_id: check for check in checks}
        current_task = asyncio.current_task()
        cancelled_producers: list[asyncio.Task[None]] = []
        for check_id, previous in self._jobs.items():
            current = desired.get(check_id)
            if current is None or current.generation != previous.generation:
                self._known_generations[check_id] = (
                    current.generation if current is not None else None
                )
        for check in desired.values():
            self._known_generations[check.check_id] = check.generation
        for check_id, task in list(self._producers.items()):
            if check_id not in desired or self._jobs.get(check_id) != desired[check_id]:
                self._producers.pop(check_id, None)
                if task is not current_task:
                    task.cancel()
                    cancelled_producers.append(task)
        self._jobs = desired
        for check_id, generation in list(self._known_generations.items()):
            if (
                generation is None
                and check_id not in self._queued
                and check_id not in self._running
            ):
                self._known_generations.pop(check_id, None)
        if self._started:
            for check in desired.values():
                if check.check_id not in self._producers:
                    self._start_producer(check)
        # A producer can be inside an async error callback when it is replaced.
        # Do not let it become an untracked background task that can write state
        # after scheduler shutdown.  A producer updating its own schedule cannot
        # await itself; it observes the changed job at the top of its next loop
        # iteration and exits there instead.
        if cancelled_producers:
            drain = asyncio.gather(*cancelled_producers, return_exceptions=True)
            cancellation: asyncio.CancelledError | None = None
            while True:
                try:
                    await asyncio.shield(drain)
                    break
                except asyncio.CancelledError as exc:
                    if drain.done():
                        drain.result()
                        raise
                    cancellation = exc
                    continue
            if cancellation is not None:
                raise cancellation

    async def run_once(self, check: ScheduledCheck) -> Any:
        if check.check_id in self._running or check.check_id in self._queued:
            if self._conflicts_with_same_generation(check):
                await self._report_error(check, "scheduler")
            raise SchedulerAdmissionError(
                f"check {check.check_id} is already scheduled"
            )
        loop = asyncio.get_running_loop()
        future: asyncio.Future[Any] = loop.create_future()
        try:
            self._queue.put_nowait(_WorkItem(check=check, future=future))
        except asyncio.QueueFull as exc:
            await self._report_error(check, "scheduler")
            raise SchedulerAdmissionError("scheduler queue is full") from exc
        self._queued.add(check.check_id)
        self._queued_generations[check.check_id] = check.generation
        return await future

    async def stop(self) -> None:
        if not self._started:
            return
        self._stopping = True
        tasks = [*self._producers.values(), *self._workers]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._producers.clear()
        self._workers.clear()
        while not self._queue.empty():
            item = self._queue.get_nowait()
            if item.future and not item.future.done():
                item.future.cancel()
            self._queue.task_done()
        self._queued.clear()
        self._running.clear()
        self._queued_generations.clear()
        self._running_generations.clear()
        self._known_generations.clear()
        self._started = False

    def _start_producer(self, check: ScheduledCheck) -> None:
        self._producers[check.check_id] = asyncio.create_task(
            self._produce(check), name=f"prober-schedule-{check.check_id}"
        )

    async def _produce(self, check: ScheduledCheck) -> None:
        interval = max(0.1, check.interval_seconds)
        digest = hashlib.sha256(check.check_id.encode()).digest()
        initial_delay = int.from_bytes(digest[:4], "big") / 2**32 * min(interval, 5.0)
        try:
            await asyncio.sleep(initial_delay)
            next_at = monotonic()
            while True:
                if self._jobs.get(check.check_id) != check:
                    return
                delay = next_at - monotonic()
                if delay > 0:
                    await asyncio.sleep(delay)
                current = self._jobs.get(check.check_id)
                if current == check:
                    await self._enqueue_scheduled(check)
                next_at += interval
                if next_at < monotonic() - interval:
                    next_at = monotonic() + interval
        except asyncio.CancelledError:
            raise

    async def _enqueue_scheduled(self, check: ScheduledCheck) -> None:
        if check.check_id in self._queued or check.check_id in self._running:
            # An old generation draining during update is not an overlap error
            # for the newly configured check. The next periodic tick may enqueue
            # it once the obsolete item has left the worker.
            if self._conflicts_with_same_generation(check):
                await self._report_error(check, "scheduler")
            return
        try:
            self._queue.put_nowait(_WorkItem(check=check))
            self._queued.add(check.check_id)
            self._queued_generations[check.check_id] = check.generation
        except asyncio.QueueFull:
            await self._report_error(check, "scheduler")

    async def _worker(self) -> None:
        try:
            while True:
                item = await self._queue.get()
                check = item.check
                self._queued.discard(check.check_id)
                if self._queued_generations.get(check.check_id) == check.generation:
                    self._queued_generations.pop(check.check_id, None)
                if self._is_obsolete(item):
                    if item.future and not item.future.done():
                        item.future.set_exception(
                            SchedulerAdmissionError(
                                f"check {check.check_id} generation is obsolete"
                            )
                        )
                    self._queue.task_done()
                    self._forget_removed_generation(check.check_id)
                    continue
                self._running.add(check.check_id)
                self._running_generations[check.check_id] = check.generation
                try:
                    result = await self._runner(check)
                except asyncio.CancelledError:
                    if item.future and not item.future.done():
                        item.future.cancel()
                    raise
                except Exception as exc:  # runner boundary must keep the worker alive
                    if not self._is_obsolete(item):
                        # Runner exceptions can contain untrusted profile data;
                        # the public log records only the bounded category.
                        logger.error(
                            "scheduled check failed",
                            extra={"check_id": check.check_id, "reason": "internal"},
                        )
                        try:
                            await self._report_error(check, "internal")
                        except asyncio.CancelledError:
                            if item.future and not item.future.done():
                                item.future.cancel()
                            raise
                    if item.future and not item.future.done():
                        item.future.set_exception(exc)
                else:
                    if item.future and not item.future.done():
                        item.future.set_result(result)
                finally:
                    self._running.discard(check.check_id)
                    if self._running_generations.get(check.check_id) == check.generation:
                        self._running_generations.pop(check.check_id, None)
                    self._queue.task_done()
                    self._forget_removed_generation(check.check_id)
        except asyncio.CancelledError:
            raise

    def _is_obsolete(self, item: _WorkItem) -> bool:
        check = item.check
        if check.check_id in self._known_generations:
            return self._known_generations[check.check_id] != check.generation
        if item.future is not None:
            # One-shot work is valid without a periodic job (offline CLI mode).
            return False
        current = self._jobs.get(check.check_id)
        return current is None or current.generation != check.generation

    def _conflicts_with_same_generation(self, check: ScheduledCheck) -> bool:
        return (
            self._queued_generations.get(check.check_id) == check.generation
            or self._running_generations.get(check.check_id) == check.generation
        )

    def _forget_removed_generation(self, check_id: str) -> None:
        if (
            self._known_generations.get(check_id) is None
            and check_id not in self._jobs
            and check_id not in self._queued
            and check_id not in self._running
        ):
            self._known_generations.pop(check_id, None)

    async def _report_error(self, check: ScheduledCheck, reason: str) -> None:
        if self._on_error is None:
            return
        try:
            result = self._on_error(check, reason)
            if result is not None:
                await result
        except asyncio.CancelledError:
            task = asyncio.current_task()
            if task is not None and task.cancelling():
                raise
            logger.error(
                "scheduler error callback raised cancellation",
                extra={"check_id": check.check_id, "reason": reason},
            )
        except Exception:
            logger.error(
                "scheduler error callback failed",
                extra={"check_id": check.check_id, "reason": reason},
            )
