"""Resource-bound fresh and persistent runtime ownership."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from .inventory import CompiledCheck
from .runtime import XrayRuntime, XrayRuntimeManager, XrayStartError


@dataclass(slots=True)
class _Persistent:
    runtime: XrayRuntime
    generation: str
    stable_after: float


@dataclass(frozen=True, slots=True)
class _RestartBackoff:
    failures: int
    delay: float
    retry_at: float


class RuntimePool:
    def __init__(
        self,
        manager: XrayRuntimeManager,
        *,
        limit: int,
        restart_backoff_initial: float = 1.0,
        restart_backoff_max: float = 60.0,
        observatory_warmup_delay: float = 5.0,
        observatory_warmup_timeout: float = 30.0,
    ) -> None:
        if limit < 1:
            raise ValueError("runtime limit must be positive")
        if restart_backoff_initial < 0:
            raise ValueError("initial runtime restart backoff must not be negative")
        if restart_backoff_max < restart_backoff_initial:
            raise ValueError("maximum runtime restart backoff is too small")
        if observatory_warmup_delay < 0:
            raise ValueError("observatory warm-up delay must not be negative")
        if observatory_warmup_timeout <= 0:
            raise ValueError("observatory warm-up timeout must be positive")
        if observatory_warmup_delay > observatory_warmup_timeout:
            raise ValueError("observatory warm-up delay exceeds its timeout")
        self.manager = manager
        self.limit = limit
        self.restart_backoff_initial = restart_backoff_initial
        self.restart_backoff_max = restart_backoff_max
        self.observatory_warmup_delay = observatory_warmup_delay
        self.observatory_warmup_timeout = observatory_warmup_timeout
        self._slots = asyncio.Semaphore(limit)
        self._persistent: dict[tuple[str, str, str | None, str | None], _Persistent] = {}
        self._locks: dict[tuple[str, str, str | None, str | None], asyncio.Lock] = {}
        self._start_locks: dict[
            tuple[str, str, str | None, str | None, str], asyncio.Lock
        ] = {}
        self._restart_backoffs: dict[
            tuple[str, str, str | None, str | None, str], _RestartBackoff
        ] = {}
        # ``None`` means that no inventory has been reconciled yet. Once the
        # scheduler publishes an inventory, an in-flight persistent start must
        # still prove that its generation is desired before it can be retained.
        self._desired_persistent: dict[
            tuple[str, str, str | None, str | None], str
        ] | None = None
        self._closed = False

    @property
    def active_count(self) -> int:
        return len(self.manager.active)

    @staticmethod
    def _key(check: CompiledCheck) -> tuple[str, str, str | None, str | None]:
        definition = check.definition
        return (
            definition.entry_id,
            definition.mode.value,
            definition.outbound_tag,
            definition.inbound_tag,
        )

    @classmethod
    def _effective_key(
        cls, check: CompiledCheck
    ) -> tuple[str, str, str | None, str | None, str]:
        return (*cls._key(check), check.definition.generation)

    @asynccontextmanager
    async def acquire(self, check: CompiledCheck) -> AsyncIterator[XrayRuntime]:
        if self._closed:
            raise RuntimeError("runtime pool is closed")
        lifecycle = check.definition.runtime_lifecycle
        if lifecycle is not None and lifecycle.value == "persistent":
            runtime = await self._persistent_runtime(check)
            try:
                runtime.ensure_running()
                await self.manager.ensure_ready(runtime, timeout=1.0)
            except asyncio.CancelledError:
                raise
            except BaseException:
                await self._retire_persistent(check, runtime, unexpected=True)
                raise
            try:
                yield runtime
            except BaseException:
                if not runtime.alive:
                    await self._retire_persistent(check, runtime, unexpected=True)
                raise
            else:
                if not await self._finish_persistent_cycle(check, runtime):
                    runtime.ensure_running()
            return

        runtime: XrayRuntime | None = None
        try:
            runtime = await self._start_runtime(check)
            yield runtime
        finally:
            if runtime is not None:
                try:
                    await runtime.stop()
                finally:
                    self._slots.release()

    async def _persistent_runtime(self, check: CompiledCheck) -> XrayRuntime:
        key = self._key(check)
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            if self._closed or not self._persistent_is_desired(check):
                raise XrayStartError("Xray runtime request is no longer current")
            current = self._persistent.get(key)
            if current is not None:
                if current.generation == check.definition.generation and current.runtime.alive:
                    self._reset_if_stable(key, current)
                    return current.runtime
                await self._remove_persistent_locked(
                    key,
                    current,
                    unexpected=(
                        current.generation == check.definition.generation
                        and not current.runtime.alive
                    ),
                )
            effective_key = self._effective_key(check)
            backoff = self._restart_backoffs.get(effective_key)
            runtime = await self._start_runtime(check)
            if self._closed or not self._persistent_is_desired(check):
                # Reconciliation may have replaced or removed this generation
                # while Xray was starting. Never publish the obsolete child or
                # leak the semaphore slot it owns.
                try:
                    await self._discard_runtime(runtime)
                finally:
                    self._slots.release()
                raise XrayStartError("Xray runtime request is no longer current")
            self._persistent[key] = _Persistent(
                runtime=runtime,
                generation=check.definition.generation,
                stable_after=(
                    asyncio.get_running_loop().time()
                    + (backoff.delay if backoff is not None else 0.0)
                ),
            )
            return runtime

    def _persistent_is_desired(self, check: CompiledCheck) -> bool:
        desired = self._desired_persistent
        return desired is None or desired.get(self._key(check)) == check.definition.generation

    async def _retire_persistent(
        self,
        check: CompiledCheck,
        runtime: XrayRuntime,
        *,
        unexpected: bool,
    ) -> None:
        key = self._key(check)
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            current = self._persistent.get(key)
            if current is None or current.runtime is not runtime:
                return
            await self._remove_persistent_locked(key, current, unexpected=unexpected)

    async def _remove_persistent_locked(
        self,
        key: tuple[str, str, str | None, str | None],
        current: _Persistent,
        *,
        unexpected: bool,
    ) -> None:
        try:
            await current.runtime.stop()
        finally:
            if self._persistent.get(key) is current:
                self._persistent.pop(key, None)
                self._slots.release()
            if unexpected:
                self._record_restart_failure((*key, current.generation))

    async def _finish_persistent_cycle(
        self, check: CompiledCheck, runtime: XrayRuntime
    ) -> bool:
        key = self._key(check)
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            current = self._persistent.get(key)
            if current is None or current.runtime is not runtime:
                return False
            if not runtime.alive:
                await self._remove_persistent_locked(key, current, unexpected=True)
                return False
            self._reset_if_stable(key, current)
            return True

    def _reset_if_stable(
        self,
        key: tuple[str, str, str | None, str | None],
        current: _Persistent,
    ) -> None:
        if asyncio.get_running_loop().time() >= current.stable_after:
            self._restart_backoffs.pop((*key, current.generation), None)

    async def _start_runtime(self, check: CompiledCheck) -> XrayRuntime:
        key = self._effective_key(check)
        lock = self._start_locks.setdefault(key, asyncio.Lock())
        async with lock:
            self._enforce_restart_backoff(key)
            await self._slots.acquire()
            runtime: XrayRuntime | None = None
            try:
                runtime = await self.manager.start_for(
                    check.entry,
                    check.definition.mode,
                    outbound_tag=check.definition.outbound_tag,
                    inbound_tag=check.definition.inbound_tag,
                )
                await self._warm_observatory(check, runtime)
            except asyncio.CancelledError:
                try:
                    await self._discard_runtime(runtime)
                finally:
                    self._slots.release()
                raise
            except Exception:
                self._record_restart_failure(key)
                try:
                    await self._discard_runtime(runtime)
                finally:
                    self._slots.release()
                raise
            except BaseException:
                try:
                    await self._discard_runtime(runtime)
                finally:
                    self._slots.release()
                raise
            lifecycle = check.definition.runtime_lifecycle
            if lifecycle is None or lifecycle.value != "persistent":
                self._restart_backoffs.pop(key, None)
            return runtime

    def _enforce_restart_backoff(
        self, key: tuple[str, str, str | None, str | None, str]
    ) -> None:
        state = self._restart_backoffs.get(key)
        if state is None:
            return
        remaining = state.retry_at - asyncio.get_running_loop().time()
        if remaining > 0:
            raise XrayStartError("Xray runtime restart backoff is active")

    def _record_restart_failure(
        self, key: tuple[str, str, str | None, str | None, str]
    ) -> None:
        previous = self._restart_backoffs.get(key)
        if previous is None:
            failures = 1
            delay = self.restart_backoff_initial
        else:
            failures = previous.failures + 1
            delay = min(self.restart_backoff_max, previous.delay * 2)
        self._restart_backoffs[key] = _RestartBackoff(
            failures=failures,
            delay=delay,
            retry_at=asyncio.get_running_loop().time() + delay,
        )

    async def _warm_observatory(
        self, check: CompiledCheck, runtime: XrayRuntime
    ) -> None:
        if not self._uses_observatory(check):
            return

        async def wait_while_alive() -> None:
            deadline = (
                asyncio.get_running_loop().time() + self.observatory_warmup_delay
            )
            while True:
                runtime.ensure_running()
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    return
                await asyncio.sleep(min(0.1, remaining))

        try:
            async with asyncio.timeout(self.observatory_warmup_timeout):
                await wait_while_alive()
        except TimeoutError as exc:
            raise XrayStartError("Xray observatory warm-up timed out") from exc

    @staticmethod
    def _uses_observatory(check: CompiledCheck) -> bool:
        if check.definition.mode.value != "profile":
            return False
        profile: Any = check.entry.profile
        if not isinstance(profile, dict) and isinstance(check.entry.payload, dict):
            profile = check.entry.payload
        return isinstance(profile, dict) and any(
            name in profile for name in ("observatory", "burstObservatory")
        )

    @staticmethod
    async def _discard_runtime(runtime: XrayRuntime | None) -> None:
        if runtime is None:
            return
        try:
            await runtime.stop()
        except Exception:
            # Preserve the startup/warm-up error. The manager still owns the
            # child and its close path will make another bounded cleanup attempt.
            pass

    async def reconcile(self, inventory: Iterable[CompiledCheck]) -> None:
        checks = list(inventory)
        desired = {
            self._key(item): item.definition.generation
            for item in checks
            if item.definition.runtime_lifecycle
            and item.definition.runtime_lifecycle.value == "persistent"
        }
        # Publish desired state before waiting on per-key locks. An in-flight
        # start re-checks this mapping after manager.start_for() returns.
        self._desired_persistent = desired
        keys = set(self._persistent).union(self._locks)
        for key in keys:
            lock = self._locks.setdefault(key, asyncio.Lock())
            async with lock:
                current = self._persistent.get(key)
                if current is None:
                    continue
                desired_generation = desired.get(key)
                if desired_generation == current.generation and current.runtime.alive:
                    self._reset_if_stable(key, current)
                    continue
                await self._remove_persistent_locked(
                    key,
                    current,
                    unexpected=(
                        desired_generation == current.generation
                        and not current.runtime.alive
                    ),
                )
        effective_keys = {self._effective_key(item) for item in checks}
        for key in set(self._restart_backoffs).difference(effective_keys):
            self._restart_backoffs.pop(key, None)
        for key in set(self._start_locks).difference(effective_keys):
            lock = self._start_locks[key]
            if not lock.locked():
                self._start_locks.pop(key, None)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._desired_persistent = {}
        for key in set(self._persistent).union(self._locks):
            lock = self._locks.setdefault(key, asyncio.Lock())
            async with lock:
                current = self._persistent.get(key)
                if current is not None:
                    await self._remove_persistent_locked(key, current, unexpected=False)
        self._persistent.clear()
        self._locks.clear()
        self._start_locks.clear()
        self._restart_backoffs.clear()
        await self.manager.close()
