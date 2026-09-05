import asyncio
from types import SimpleNamespace

import pytest

from xray_e2e_prober.inventory import CompiledCheck
from xray_e2e_prober.models import (
    CheckDefinition,
    EntryRecord,
    SchedulerConfig,
    TargetSetConfig,
)
from xray_e2e_prober.runtime import XrayStartError
from xray_e2e_prober.runtime_pool import RuntimePool


class FakeRuntime:
    def __init__(self, stopped):
        self.alive = True
        self.socks_host = "127.0.0.1"
        self.socks_port = 1234
        self._stopped = stopped
        self.ensure_calls = 0

    def ensure_running(self):
        self.ensure_calls += 1
        if not self.alive:
            raise RuntimeError

    async def stop(self):
        if self.alive:
            self.alive = False
            self._stopped.append(self)


class FakeManager:
    def __init__(self):
        self.started = []
        self.stopped = []

    @property
    def active(self):
        return tuple(item for item in self.started if item.alive)

    async def start_for(self, *args, **kwargs):
        runtime = FakeRuntime(self.stopped)
        self.started.append(runtime)
        return runtime

    async def ensure_ready(self, runtime, *, timeout=1.0):
        runtime.ensure_running()

    async def close(self):
        for item in self.started:
            await item.stop()


class FlakyManager(FakeManager):
    def __init__(self, failures: int):
        super().__init__()
        self.failures = failures
        self.attempted_at = []

    async def start_for(self, *args, **kwargs):
        self.attempted_at.append(asyncio.get_running_loop().time())
        if self.failures:
            self.failures -= 1
            raise RuntimeError("start failed")
        return await super().start_for(*args, **kwargs)


class DyingManager(FakeManager):
    async def start_for(self, *args, **kwargs):
        runtime = await super().start_for(*args, **kwargs)
        asyncio.get_running_loop().call_later(
            0.01, setattr, runtime, "alive", False
        )
        return runtime


class HangingManager(FakeManager):
    def __init__(self):
        super().__init__()
        self.unresponsive = False

    async def ensure_ready(self, runtime, *, timeout=1.0):
        if self.unresponsive:
            raise XrayStartError("SOCKS readiness timed out")
        await super().ensure_ready(runtime, timeout=timeout)


class SlowManager(FakeManager):
    def __init__(self):
        super().__init__()
        self.starting = asyncio.Event()
        self.release_start = asyncio.Event()

    async def start_for(self, *args, **kwargs):
        self.starting.set()
        await self.release_start.wait()
        return await super().start_for(*args, **kwargs)


def _compiled(generation="g1", mode="profile"):
    entry = EntryRecord(
        entry_id="e1",
        source_id="s1",
        name="profile",
        mode=mode,
        generation=generation,
        profile={"outbounds": [{"protocol": "vless"}]},
    )
    definition = CheckDefinition(
        check_id="c1",
        entry_id="e1",
        source_id="s1",
        target_set_id="ts1",
        mode=mode,
        generation=generation,
    )
    target_set = TargetSetConfig(
        target_set_id="ts1",
        name="targets",
        quorum=1,
        targets=[{"target_id": "t1", "name": "one", "url": "https://example.test"}],
    )
    return CompiledCheck(definition, entry, target_set, (), "test")


async def _wait_out_backoff(pool: RuntimePool, key) -> None:
    remaining = pool._restart_backoffs[key].retry_at - asyncio.get_running_loop().time()
    if remaining > 0:
        await asyncio.sleep(remaining + 0.002)


@pytest.mark.asyncio
async def test_persistent_runtime_is_reused_and_generation_change_stops_old() -> None:
    manager = FakeManager()
    pool = RuntimePool(manager, limit=1)
    first = _compiled("g1")
    async with pool.acquire(first) as runtime1:
        pass
    async with pool.acquire(first) as runtime2:
        pass
    assert runtime1 is runtime2

    second = _compiled("g2")
    await pool.reconcile([second])
    assert not runtime1.alive
    async with pool.acquire(second) as runtime3:
        assert runtime3 is not runtime1
    await pool.close()


@pytest.mark.asyncio
async def test_reconcile_discards_an_obsolete_inflight_persistent_start() -> None:
    manager = SlowManager()
    pool = RuntimePool(manager, limit=1, observatory_warmup_delay=0)
    check = _compiled("g1")

    async def acquire_once() -> None:
        async with pool.acquire(check):
            pytest.fail("obsolete runtime must not be yielded")

    acquiring = asyncio.create_task(acquire_once())
    await manager.starting.wait()
    reconciling = asyncio.create_task(pool.reconcile([]))
    await asyncio.sleep(0)
    manager.release_start.set()

    with pytest.raises(XrayStartError, match="no longer current"):
        await acquiring
    await reconciling
    assert pool._persistent == {}
    assert manager.active == ()
    assert pool._slots._value == 1
    await pool.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["connection", "profile"])
async def test_start_failure_backoff_applies_and_resets_after_success(mode: str) -> None:
    manager = FlakyManager(failures=1)
    pool = RuntimePool(
        manager,
        limit=1,
        restart_backoff_initial=0.01,
        restart_backoff_max=0.02,
        observatory_warmup_delay=0,
    )
    check = _compiled(mode=mode)
    key = pool._effective_key(check)

    with pytest.raises(RuntimeError, match="start failed"):
        async with pool.acquire(check):
            pass
    assert pool._slots._value == 1
    assert pool._restart_backoffs[key].failures == 1
    assert pool._restart_backoffs[key].delay == pytest.approx(0.01)

    attempts = len(manager.attempted_at)
    with pytest.raises(XrayStartError, match="backoff"):
        async with pool.acquire(check):
            pass
    assert len(manager.attempted_at) == attempts

    await _wait_out_backoff(pool, key)
    async with pool.acquire(check):
        if mode == "profile":
            await asyncio.sleep(0.012)
    assert key not in pool._restart_backoffs

    # Remove a successful persistent instance before forcing another start.
    await pool.reconcile([])
    await pool.reconcile([check])
    manager.failures = 1
    with pytest.raises(RuntimeError, match="start failed"):
        async with pool.acquire(check):
            pass
    assert pool._restart_backoffs[key].delay == pytest.approx(0.01)
    await pool.close()


@pytest.mark.asyncio
async def test_restart_backoff_is_exponential_and_bounded() -> None:
    manager = FlakyManager(failures=3)
    pool = RuntimePool(
        manager,
        limit=1,
        restart_backoff_initial=0.01,
        restart_backoff_max=0.015,
        observatory_warmup_delay=0,
    )
    check = _compiled(mode="connection")
    key = pool._effective_key(check)

    for failures, expected_delay in ((1, 0.01), (2, 0.015), (3, 0.015)):
        if key in pool._restart_backoffs:
            await _wait_out_backoff(pool, key)
        with pytest.raises(RuntimeError, match="start failed"):
            async with pool.acquire(check):
                pass
        state = pool._restart_backoffs[key]
        assert state.failures == failures
        assert state.delay == pytest.approx(expected_delay)
    await pool.close()


@pytest.mark.asyncio
async def test_observatory_profile_waits_for_configured_live_warmup() -> None:
    manager = FakeManager()
    pool = RuntimePool(
        manager,
        limit=1,
        observatory_warmup_delay=0.02,
        observatory_warmup_timeout=0.05,
    )
    check = _compiled(mode="profile")
    check.entry.profile["observatory"] = {"probeInterval": "1s"}

    started = asyncio.get_running_loop().time()
    async with pool.acquire(check) as runtime:
        assert runtime.ensure_calls >= 1
    assert asyncio.get_running_loop().time() - started >= 0.018
    await pool.close()


@pytest.mark.asyncio
async def test_observatory_warmup_fails_if_process_dies() -> None:
    manager = DyingManager()
    pool = RuntimePool(
        manager,
        limit=1,
        restart_backoff_initial=0,
        restart_backoff_max=0,
        observatory_warmup_delay=0.05,
        observatory_warmup_timeout=0.1,
    )
    check = _compiled(mode="profile")
    check.entry.profile["burstObservatory"] = {"pingConfig": {}}
    key = pool._effective_key(check)

    with pytest.raises(RuntimeError):
        async with pool.acquire(check):
            pass
    assert pool._restart_backoffs[key].failures == 1
    assert manager.active == ()
    await pool.close()


@pytest.mark.asyncio
async def test_persistent_crash_increases_backoff_until_runtime_is_stable() -> None:
    manager = FakeManager()
    pool = RuntimePool(
        manager,
        limit=1,
        restart_backoff_initial=0.01,
        restart_backoff_max=0.02,
        observatory_warmup_delay=0,
    )
    check = _compiled(mode="profile")
    key = pool._effective_key(check)

    async with pool.acquire(check) as first:
        pass
    first.alive = False

    with pytest.raises(XrayStartError, match="backoff"):
        async with pool.acquire(check):
            pass
    assert pool._restart_backoffs[key].failures == 1
    assert pool._restart_backoffs[key].delay == pytest.approx(0.01)
    assert len(manager.started) == 1

    await _wait_out_backoff(pool, key)
    with pytest.raises(RuntimeError):
        async with pool.acquire(check) as second:
            second.alive = False
    assert pool._restart_backoffs[key].failures == 2
    assert pool._restart_backoffs[key].delay == pytest.approx(0.02)

    await _wait_out_backoff(pool, key)
    async with pool.acquire(check):
        await asyncio.sleep(0.022)
    assert key not in pool._restart_backoffs
    await pool.close()


@pytest.mark.asyncio
async def test_unresponsive_persistent_socks_is_retired_and_backed_off() -> None:
    manager = HangingManager()
    pool = RuntimePool(
        manager,
        limit=1,
        restart_backoff_initial=0.01,
        restart_backoff_max=0.02,
        observatory_warmup_delay=0,
    )
    check = _compiled(mode="profile")
    key = pool._effective_key(check)

    async with pool.acquire(check) as runtime:
        pass
    manager.unresponsive = True
    with pytest.raises(XrayStartError, match="readiness"):
        async with pool.acquire(check):
            pass

    assert runtime.alive is False
    assert manager.active == ()
    assert pool._slots._value == 1
    assert pool._restart_backoffs[key].failures == 1
    await pool.close()


def test_scheduler_runtime_timing_aliases_and_bounds() -> None:
    config = SchedulerConfig.model_validate(
        {
            "runtime_restart_backoff_initial_seconds": 2,
            "runtime_restart_backoff_max_seconds": 8,
            "observatory_warmup_delay_seconds": 3,
            "observatory_warmup_timeout_seconds": 4,
        }
    )
    assert config.runtime_restart_backoff_initial == 2
    assert config.runtime_restart_backoff_max == 8
    assert config.observatory_warmup_delay == 3
    assert config.observatory_warmup_timeout == 4

    with pytest.raises(ValueError, match="restart backoff"):
        SchedulerConfig(
            runtime_restart_backoff_initial=2,
            runtime_restart_backoff_max=1,
        )
    with pytest.raises(ValueError, match="warm-up"):
        SchedulerConfig(
            observatory_warmup_delay=2,
            observatory_warmup_timeout=1,
        )
