import asyncio

import pytest

from xray_e2e_prober.scheduler import ScheduledCheck, Scheduler


@pytest.mark.asyncio
async def test_run_once_prevents_overlap() -> None:
    gate = asyncio.Event()
    entered = asyncio.Event()

    async def runner(check: ScheduledCheck) -> str:
        entered.set()
        await gate.wait()
        return check.check_id

    scheduler = Scheduler(runner, concurrency=1, max_queue=2)
    await scheduler.start()
    check = ScheduledCheck("c1", 1, 60)
    first = asyncio.create_task(scheduler.run_once(check))
    await entered.wait()
    with pytest.raises(RuntimeError, match="already scheduled"):
        await scheduler.run_once(check)
    gate.set()
    assert await first == "c1"
    await scheduler.stop()


@pytest.mark.asyncio
async def test_skipped_period_while_running_is_reported() -> None:
    gate = asyncio.Event()
    entered = asyncio.Event()
    reported = asyncio.Event()
    errors: list[tuple[str, str]] = []

    async def runner(check: ScheduledCheck) -> None:
        entered.set()
        await gate.wait()

    async def on_error(check: ScheduledCheck, reason: str) -> None:
        errors.append((check.check_id, reason))
        reported.set()

    scheduler = Scheduler(runner, concurrency=1, max_queue=2, on_error=on_error)
    await scheduler.update([ScheduledCheck("c1", 1, 0.1)])
    await scheduler.start()
    try:
        await asyncio.wait_for(entered.wait(), timeout=1)
        await asyncio.wait_for(reported.wait(), timeout=1)
        assert ("c1", "scheduler") in errors
    finally:
        gate.set()
        await scheduler.stop()


@pytest.mark.asyncio
async def test_queue_overflow_is_reported() -> None:
    gate = asyncio.Event()
    errors: list[tuple[str, str]] = []

    async def runner(check: ScheduledCheck) -> None:
        await gate.wait()

    async def on_error(check: ScheduledCheck, reason: str) -> None:
        errors.append((check.check_id, reason))

    scheduler = Scheduler(runner, concurrency=1, max_queue=1, on_error=on_error)
    # Before start, one item can be queued and the second must fail deterministically.
    first = asyncio.create_task(scheduler.run_once(ScheduledCheck("c1", 1, 60)))
    await asyncio.sleep(0)
    with pytest.raises(RuntimeError, match="queue is full"):
        await scheduler.run_once(ScheduledCheck("c2", 1, 60))
    assert errors == [("c2", "scheduler")]
    await scheduler.start()
    gate.set()
    await first
    await scheduler.stop()


@pytest.mark.asyncio
async def test_obsolete_queued_manual_item_finishes_without_internal_error() -> None:
    calls: list[tuple[str, int]] = []
    errors: list[tuple[str, str]] = []

    async def runner(check: ScheduledCheck) -> None:
        calls.append((check.check_id, int(check.generation)))

    async def on_error(check: ScheduledCheck, reason: str) -> None:
        errors.append((check.check_id, reason))

    scheduler = Scheduler(runner, concurrency=1, max_queue=2, on_error=on_error)
    old = ScheduledCheck("c1", 1, 60)
    new = ScheduledCheck("c1", 2, 60)
    await scheduler.update([old])
    pending = asyncio.create_task(scheduler.run_once(old))
    await asyncio.sleep(0)
    await scheduler.update([new])
    await scheduler.start()
    try:
        with pytest.raises(RuntimeError, match="obsolete"):
            await asyncio.wait_for(pending, timeout=1)
        assert calls == []
        assert errors == []
    finally:
        await scheduler.stop()


@pytest.mark.asyncio
async def test_obsolete_running_failure_does_not_report_internal() -> None:
    entered = asyncio.Event()
    release = asyncio.Event()
    errors: list[tuple[str, str]] = []

    async def runner(check: ScheduledCheck) -> None:
        entered.set()
        await release.wait()
        raise RuntimeError("old generation failed")

    async def on_error(check: ScheduledCheck, reason: str) -> None:
        errors.append((check.check_id, reason))

    scheduler = Scheduler(runner, concurrency=1, max_queue=2, on_error=on_error)
    old = ScheduledCheck("c1", 1, 60)
    new = ScheduledCheck("c1", 2, 60)
    await scheduler.update([old])
    await scheduler._enqueue_scheduled(old)
    await scheduler.start()
    try:
        await asyncio.wait_for(entered.wait(), timeout=1)
        await scheduler.update([new])
        release.set()
        await asyncio.wait_for(scheduler._queue.join(), timeout=1)
        assert errors == []
    finally:
        release.set()
        await scheduler.stop()


@pytest.mark.asyncio
async def test_new_generation_waiting_for_old_queue_is_not_reported_as_overlap() -> None:
    errors: list[tuple[str, str]] = []

    async def runner(check: ScheduledCheck) -> None:
        return None

    async def on_error(check: ScheduledCheck, reason: str) -> None:
        errors.append((check.check_id, reason))

    scheduler = Scheduler(runner, concurrency=1, max_queue=2, on_error=on_error)
    old = ScheduledCheck("c1", 1, 60)
    new = ScheduledCheck("c1", 2, 60)
    await scheduler.update([old])
    await scheduler._enqueue_scheduled(old)
    await scheduler.update([new])
    await scheduler._enqueue_scheduled(new)
    assert errors == []
    await scheduler.start()
    try:
        await asyncio.wait_for(scheduler._queue.join(), timeout=1)
        await scheduler._enqueue_scheduled(new)
        await asyncio.wait_for(scheduler._queue.join(), timeout=1)
        assert errors == []
    finally:
        await scheduler.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("callback_error", [RuntimeError, asyncio.CancelledError])
async def test_error_callback_failure_isolated_and_manual_future_finishes(
    callback_error: type[BaseException],
) -> None:
    async def runner(check: ScheduledCheck) -> str:
        if check.check_id == "fails":
            raise ValueError("runner failed")
        return check.check_id

    async def on_error(check: ScheduledCheck, reason: str) -> None:
        raise callback_error("callback failed")

    scheduler = Scheduler(runner, concurrency=1, max_queue=2, on_error=on_error)
    await scheduler.start()
    try:
        with pytest.raises(ValueError, match="runner failed"):
            await asyncio.wait_for(
                scheduler.run_once(ScheduledCheck("fails", 1, 60)), timeout=1
            )
        assert await asyncio.wait_for(
            scheduler.run_once(ScheduledCheck("works", 1, 60)), timeout=1
        ) == "works"
    finally:
        await scheduler.stop()


@pytest.mark.asyncio
async def test_update_waits_for_cancelled_producer_to_finish() -> None:
    async def runner(check: ScheduledCheck) -> None:
        return None

    scheduler = Scheduler(runner, concurrency=1, max_queue=2)
    check = ScheduledCheck("c1", 1, 60)
    await scheduler.update([check])
    await scheduler.start()
    producer = scheduler._producers[check.check_id]

    await scheduler.update([])

    assert producer.done()
    assert check.check_id not in scheduler._producers
    await scheduler.stop()


@pytest.mark.asyncio
async def test_producer_can_remove_its_own_schedule_without_self_await() -> None:
    async def runner(check: ScheduledCheck) -> None:
        return None

    scheduler = Scheduler(runner, concurrency=1, max_queue=2)
    check = ScheduledCheck("c1", 1, 60)
    await scheduler.update([check])
    returned = asyncio.Event()

    async def update_from_producer() -> None:
        scheduler._producers[check.check_id] = asyncio.current_task()  # type: ignore[assignment]
        await scheduler.update([])
        returned.set()

    producer = asyncio.create_task(update_from_producer())
    await asyncio.wait_for(returned.wait(), timeout=1)
    await producer
    assert check.check_id not in scheduler._producers


@pytest.mark.asyncio
async def test_cancelled_update_still_drains_removed_producer() -> None:
    async def runner(check: ScheduledCheck) -> None:
        return None

    scheduler = Scheduler(runner, concurrency=1, max_queue=2)
    check = ScheduledCheck("c1", 1, 60)
    await scheduler.update([check])
    cleanup_started = asyncio.Event()
    cleanup_release = asyncio.Event()

    async def producer_with_cleanup() -> None:
        try:
            await asyncio.Event().wait()
        finally:
            cleanup_started.set()
            await cleanup_release.wait()

    producer = asyncio.create_task(producer_with_cleanup())
    scheduler._producers[check.check_id] = producer
    update = asyncio.create_task(scheduler.update([]))
    await asyncio.wait_for(cleanup_started.wait(), timeout=1)
    update.cancel()
    await asyncio.sleep(0)
    assert not update.done()

    cleanup_release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(update, timeout=1)
    assert producer.done()
