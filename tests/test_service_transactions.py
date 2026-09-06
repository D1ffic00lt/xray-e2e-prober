import asyncio
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

import xray_e2e_prober.service as service_module
from xray_e2e_prober.inventory import compile_inventory
from xray_e2e_prober.identity import IdentityRegistry
from xray_e2e_prober.models import (
    AppConfig,
    CycleResult,
    EgressResult,
    EgressState,
    EntryRecord,
    ReachabilityResult,
    ReachabilityState,
    Reason,
    SourceGeneration,
)
from xray_e2e_prober.scheduler import ScheduledCheck
from xray_e2e_prober.service import (
    ProberService,
    ServiceError,
    SourceStatus,
    _critical_to_thread,
    _config_revision,
    load_app_config,
    save_app_config,
)
from xray_e2e_prober.storage import StorageError


@pytest.mark.asyncio
async def test_committed_cleanup_propagates_internal_cancellation() -> None:
    async def cancel_self() -> None:
        task = asyncio.current_task()
        assert task is not None
        task.cancel()
        await asyncio.sleep(0)

    with pytest.raises(asyncio.CancelledError):
        await service_module._finish_committed(cancel_self())


@pytest.mark.asyncio
async def test_critical_thread_operation_survives_repeated_cancellation() -> None:
    entered = threading.Event()
    release = threading.Event()
    completed = threading.Event()

    def writer() -> None:
        entered.set()
        if not release.wait(timeout=2):
            raise RuntimeError("test writer was not released")
        completed.set()

    writing = asyncio.create_task(_critical_to_thread(writer))
    assert await asyncio.to_thread(entered.wait, 1)
    writing.cancel()
    await asyncio.sleep(0)
    writing.cancel()
    await asyncio.sleep(0)
    assert completed.is_set() is False
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await writing
    assert completed.is_set() is True


def _source_config(tmp_path: Path, source_ids: tuple[str, ...] = ("src",)) -> AppConfig:
    return AppConfig.model_validate({
        "instance_id": "transaction-test",
        "sources": [{
            "source_id": source_id,
            "name": source_id,
            "kind": "file",
            "location": str(tmp_path / f"{source_id}.txt"),
            "target_set_ids": ["set"],
        } for source_id in source_ids],
        "target_sets": [{
            "target_set_id": "set", "name": "set", "quorum": 1,
            "targets": [{"target_id": "one", "name": "one", "url": "https://example.test"}],
        }],
    })


def _generation(source_id: str = "src") -> SourceGeneration:
    return SourceGeneration(
        source_id=source_id,
        generation="g1",
        entries=[EntryRecord(
            entry_id=f"entry-{source_id}", source_id=source_id, name=source_id,
            mode="connection", generation="g1", payload="vless://secret",
        )],
    )


@pytest.mark.asyncio
async def test_execute_egress_mismatch_sets_failure_state_and_status_metric(
    tmp_path: Path,
) -> None:
    raw = _source_config(tmp_path).model_dump(mode="python")
    raw["sources"][0]["egress_assertion_ids"] = ["exit"]
    raw["egress_assertions"] = [
        {
            "assertion_id": "exit",
            "name": "expected exit",
            "url": "https://example.test/ip",
            "expected_cidrs": ["192.0.2.0/24"],
        }
    ]
    config = AppConfig.model_validate(raw)
    generation = _generation()
    inventory = compile_inventory(config, {"src": generation})
    check = next(iter(inventory.values()))
    service = ProberService(tmp_path, schedule_enabled=False, control_enabled=False)
    service.config = config
    service.inventory = inventory

    class Pool:
        active_count = 0

        @asynccontextmanager
        async def acquire(self, _check):
            yield SimpleNamespace(socks_port=1080, socks_host="127.0.0.1")

    class Checker:
        async def run_cycle(self, definition, *_args, **_kwargs):
            return CycleResult(
                check_id=definition.check_id,
                generation=definition.generation,
                reachability=ReachabilityResult(
                    state=ReachabilityState.SUCCESS,
                    success_count=1,
                    quorum=1,
                    targets=[],
                ),
                egress=[
                    EgressResult(
                        assertion_id="exit",
                        state=EgressState.MISMATCH,
                        reason=Reason.EGRESS_MISMATCH,
                    )
                ],
            )

    service._pool = Pool()  # type: ignore[assignment]
    service._checker = Checker()  # type: ignore[assignment]

    result = await service.execute(check)

    assert result.state is ReachabilityState.FAILURE
    snapshot = service.check_snapshot(check.definition.check_id)
    assert snapshot is not None and snapshot["state"] == "failure"
    metrics = service.metrics.render().decode()
    assert (
        f'synthetic_check_status{{check_id="{check.definition.check_id}",'
        'instance_id="transaction-test"} 0.0'
    ) in metrics


@pytest.mark.asyncio
async def test_config_cas_is_serialized_and_rejected_file_is_rolled_back(
    tmp_path: Path,
) -> None:
    service = ProberService(
        tmp_path, schedule_enabled=False, control_enabled=False,
        xray_binary="/usr/bin/true",
    )
    old = AppConfig(instance_id="old")
    save_app_config(old, service.config_path)
    await service._apply_config(old)
    revision = _config_revision(old)
    entered = asyncio.Event()
    release = asyncio.Event()
    original_apply = service._apply_config
    first = True

    async def delayed_apply(candidate: AppConfig) -> None:
        nonlocal first
        if first:
            first = False
            entered.set()
            await release.wait()
        await original_apply(candidate)

    service._apply_config = delayed_apply  # type: ignore[method-assign]
    candidate = AppConfig(instance_id="new")
    one = asyncio.create_task(
        service.replace_config(candidate, expected_revision=revision)
    )
    await asyncio.wait_for(entered.wait(), timeout=1)
    two = asyncio.create_task(
        service.replace_config(candidate, expected_revision=revision)
    )
    release.set()
    outcomes = await asyncio.gather(one, two, return_exceptions=True)
    assert sum(item is None for item in outcomes) == 1
    assert sum(isinstance(item, ServiceError) for item in outcomes) == 1

    async def reject_apply(candidate: AppConfig) -> None:
        raise RuntimeError("injected live apply failure")

    service._apply_config = reject_apply  # type: ignore[method-assign]
    accepted_bytes = service.config_path.read_bytes()
    with pytest.raises(RuntimeError, match="injected"):
        await service.replace_config(
            AppConfig(instance_id="rejected"),
            expected_revision=_config_revision(service.config),
        )
    assert service.config_path.read_bytes() == accepted_bytes
    assert service.config is not None and service.config.instance_id == "new"
    await service.stop()


@pytest.mark.asyncio
async def test_cancellation_after_config_commit_keeps_disk_and_memory_consistent(
    tmp_path: Path,
) -> None:
    service = ProberService(
        tmp_path, schedule_enabled=False, control_enabled=False,
        xray_binary="/usr/bin/true",
    )
    old = AppConfig(instance_id="old")
    save_app_config(old, service.config_path)
    await service._apply_config(old)
    old_scheduler = service._scheduler
    assert old_scheduler is not None
    stopping = asyncio.Event()
    release_stop = asyncio.Event()
    original_stop = old_scheduler.stop

    async def delayed_stop() -> None:
        stopping.set()
        await release_stop.wait()
        await original_stop()

    old_scheduler.stop = delayed_stop  # type: ignore[method-assign]
    replacement = AppConfig(instance_id="committed")
    applying = asyncio.create_task(service.replace_config(replacement))
    await asyncio.wait_for(stopping.wait(), timeout=1)
    applying.cancel()
    release_stop.set()
    with pytest.raises(asyncio.CancelledError):
        await applying

    assert service.config is not None
    assert service.config.instance_id == "committed"
    assert service.ready is True
    assert service.config_reload_success is True
    assert service.config_path.read_text(encoding="utf-8").find("committed") >= 0
    assert old_scheduler._started is False
    await service.stop()


@pytest.mark.asyncio
async def test_config_swap_quiesces_old_executor_before_starting_new_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = ProberService(
        tmp_path,
        schedule_enabled=False,
        control_enabled=False,
        xray_binary="/usr/bin/true",
    )
    await service._apply_config(AppConfig(instance_id="old"))
    old_scheduler = service._scheduler
    old_pool = service._pool
    assert old_scheduler is not None and old_pool is not None
    events: list[str] = []
    original_stop = old_scheduler.stop
    original_close = old_pool.close
    original_start = service_module.Scheduler.start

    async def observed_stop() -> None:
        await original_stop()
        events.append("old-scheduler-stopped")

    async def observed_close() -> None:
        assert events == ["old-scheduler-stopped"]
        await original_close()
        events.append("old-pool-closed")

    async def observed_start(scheduler) -> None:
        assert events == ["old-scheduler-stopped", "old-pool-closed"]
        events.append("new-scheduler-started")
        await original_start(scheduler)

    old_scheduler.stop = observed_stop  # type: ignore[method-assign]
    old_pool.close = observed_close  # type: ignore[method-assign]
    monkeypatch.setattr(service_module.Scheduler, "start", observed_start)
    await service._apply_config(AppConfig(instance_id="new"))
    try:
        assert events == [
            "old-scheduler-stopped",
            "old-pool-closed",
            "new-scheduler-started",
        ]
        assert service.ready is True
    finally:
        await service.stop()


@pytest.mark.asyncio
async def test_source_commit_finishes_live_convergence_when_cancelled_during_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _source_config(tmp_path)
    old_generation = _generation()
    new_generation = old_generation.model_copy(
        update={
            "generation": "g2",
            "entries": [
                old_generation.entries[0].model_copy(
                    update={"generation": "g2", "payload": "vless://rotated-secret"}
                )
            ],
        }
    )
    old_registry = IdentityRegistry()
    new_registry = IdentityRegistry()
    service = ProberService(tmp_path, control_enabled=False)
    service.config = config
    service.identity = old_registry
    service.generations = {"src": old_generation}
    service.inventory = compile_inventory(config, service.generations)
    service._publish_source(old_generation, old_registry.to_model())
    new_generations = {"src": new_generation}
    new_inventory = compile_inventory(config, new_generations)

    class RecordingPool:
        def __init__(self) -> None:
            self.reconciled: list[list[str]] = []

        async def reconcile(self, checks) -> None:
            self.reconciled.append(
                [item.definition.generation for item in list(checks)]
            )

    class RecordingScheduler:
        def __init__(self) -> None:
            self.updated: list[list[str]] = []

        async def update(self, checks) -> None:
            self.updated.append([str(item.generation) for item in list(checks)])

    pool = RecordingPool()
    scheduler = RecordingScheduler()
    service._pool = pool  # type: ignore[assignment]
    service._scheduler = scheduler  # type: ignore[assignment]
    status = SourceStatus("src")
    entered = threading.Event()
    release = threading.Event()
    original_publish = service._publish_source

    def delayed_publish(generation, registry) -> None:
        entered.set()
        if not release.wait(timeout=2):
            raise RuntimeError("test publication was not released")
        original_publish(generation, registry)

    monkeypatch.setattr(service, "_publish_source", delayed_publish)
    committing = asyncio.create_task(
        service._commit_source_state(
            generation=new_generation,
            registry=new_registry,
            generations=new_generations,
            inventory=new_inventory,
            status=status,
            reconcile_executor=True,
        )
    )
    assert await asyncio.to_thread(entered.wait, 1)
    # Nothing live may move ahead of the durable source pointer.
    assert service.generations["src"].generation == "g1"
    assert pool.reconciled == []
    assert scheduler.updated == []

    committing.cancel()
    await asyncio.sleep(0)
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await committing

    persisted = service.store.load_lkg("src")
    assert persisted is not None and persisted.generation == "g2"
    assert service.identity is new_registry
    assert service.generations == new_generations
    assert service.inventory == new_inventory
    assert pool.reconciled == [["g2"]]
    assert scheduler.updated == [["g2"]]
    assert status.refresh_success is True


@pytest.mark.asyncio
async def test_source_publication_failure_keeps_entire_live_state_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _source_config(tmp_path)
    old_generation = _generation()
    new_generation = old_generation.model_copy(
        update={
            "generation": "g2",
            "entries": [
                old_generation.entries[0].model_copy(update={"generation": "g2"})
            ],
        }
    )
    old_registry = IdentityRegistry()
    new_registry = IdentityRegistry()
    service = ProberService(tmp_path, control_enabled=False)
    service.config = config
    service.identity = old_registry
    service.generations = {"src": old_generation}
    old_inventory = compile_inventory(config, service.generations)
    service.inventory = old_inventory
    service._publish_source(old_generation, old_registry.to_model())

    class UncalledPool:
        calls = 0

        async def reconcile(self, checks) -> None:
            self.calls += 1

    class UncalledScheduler:
        calls = 0

        async def update(self, checks) -> None:
            self.calls += 1

    pool = UncalledPool()
    scheduler = UncalledScheduler()
    service._pool = pool  # type: ignore[assignment]
    service._scheduler = scheduler  # type: ignore[assignment]

    def reject_publication(_generation, _registry) -> None:
        raise StorageError("injected publication failure")

    monkeypatch.setattr(service, "_publish_source", reject_publication)
    status = SourceStatus("src")
    with pytest.raises(StorageError, match="injected publication failure"):
        await service._commit_source_state(
            generation=new_generation,
            registry=new_registry,
            generations={"src": new_generation},
            inventory=compile_inventory(config, {"src": new_generation}),
            status=status,
            reconcile_executor=True,
        )

    persisted = service.store.load_lkg("src")
    assert persisted is not None and persisted.generation == "g1"
    assert service.identity is old_registry
    assert service.generations == {"src": old_generation}
    assert service.inventory is old_inventory
    assert pool.calls == 0
    assert scheduler.calls == 0
    assert status.refresh_success is None


@pytest.mark.asyncio
async def test_ambiguous_publication_error_after_pointer_commit_activates_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _source_config(tmp_path)
    generation = _generation().model_copy(
        update={
            "generation": "g2",
            "entries": [
                _generation().entries[0].model_copy(update={"generation": "g2"})
            ],
        }
    )
    service = ProberService(tmp_path, control_enabled=False)
    service.config = config
    service.generations = {}
    service.inventory = {}
    registry = IdentityRegistry()
    inventory = compile_inventory(config, {"src": generation})
    original_publish = service._publish_source

    def publish_then_report_failure(value, registry_model) -> None:
        original_publish(value, registry_model)
        raise StorageError("injected failure after pointer commit")

    monkeypatch.setattr(service, "_publish_source", publish_then_report_failure)
    status = SourceStatus("src")
    await service._commit_source_state(
        generation=generation,
        registry=registry,
        generations={"src": generation},
        inventory=inventory,
        status=status,
        reconcile_executor=False,
    )

    assert service.store.load_lkg("src") == generation
    assert service.generations == {"src": generation}
    assert service.inventory == inventory
    assert status.refresh_success is True


@pytest.mark.asyncio
@pytest.mark.parametrize("failing_component", ["pool", "scheduler"])
async def test_post_commit_executor_failure_keeps_generation_accepted_and_quiesces(
    tmp_path: Path, failing_component: str
) -> None:
    config = _source_config(tmp_path)
    old_generation = _generation()
    new_generation = old_generation.model_copy(
        update={
            "generation": "g2",
            "entries": [
                old_generation.entries[0].model_copy(update={"generation": "g2"})
            ],
        }
    )
    service = ProberService(tmp_path, control_enabled=False)
    service.config = config
    service.generations = {"src": old_generation}
    service.inventory = compile_inventory(config, service.generations)
    service.ready = True

    class FailingPool:
        calls = 0

        async def reconcile(self, checks) -> None:
            self.calls += 1
            list(checks)
            if failing_component == "pool":
                raise RuntimeError("injected pool failure")

    class FailingScheduler:
        updates = 0
        stops = 0

        async def update(self, checks) -> None:
            self.updates += 1
            list(checks)
            if failing_component == "scheduler":
                raise RuntimeError("injected scheduler failure")

        async def stop(self) -> None:
            self.stops += 1

    pool = FailingPool()
    scheduler = FailingScheduler()
    service._pool = pool  # type: ignore[assignment]
    service._scheduler = scheduler  # type: ignore[assignment]
    status = SourceStatus("src")
    new_registry = IdentityRegistry()
    new_generations = {"src": new_generation}
    new_inventory = compile_inventory(config, new_generations)

    # An executor maintenance failure occurs after the durable commit point. It
    # must not turn the accepted source into a rejected refresh or roll memory
    # back; readiness is withdrawn and periodic execution is stopped instead.
    await service._commit_source_state(
        generation=new_generation,
        registry=new_registry,
        generations=new_generations,
        inventory=new_inventory,
        status=status,
        reconcile_executor=True,
    )

    assert service.store.load_lkg("src") == new_generation
    assert service.generations == new_generations
    assert service.inventory == new_inventory
    assert service.identity is new_registry
    assert status.refresh_success is True
    assert service.ready is False
    assert pool.calls == 1
    assert scheduler.updates == (0 if failing_component == "pool" else 1)
    assert scheduler.stops == 1

    # A fresh process reconstructs the same accepted source generation from the
    # authoritative pointer even though this executor instance was degraded.
    restarted = ProberService(tmp_path, control_enabled=False)
    restarted._load_identity()
    restarted._load_generations()
    assert restarted.generations == new_generations


@pytest.mark.asyncio
async def test_config_apply_cannot_restore_readiness_after_shutdown_begins(
    tmp_path: Path,
) -> None:
    service = ProberService(
        tmp_path,
        schedule_enabled=False,
        control_enabled=False,
        xray_binary="/usr/bin/true",
    )
    await service._apply_config(AppConfig(instance_id="old"))
    old_scheduler = service._scheduler
    assert old_scheduler is not None
    entered = asyncio.Event()
    release = asyncio.Event()
    original_stop = old_scheduler.stop

    async def delayed_stop() -> None:
        entered.set()
        await release.wait()
        await original_stop()

    old_scheduler.stop = delayed_stop  # type: ignore[method-assign]

    async def mutate() -> None:
        async with service._mutation_lock:
            await service._apply_config(AppConfig(instance_id="new"))

    applying = asyncio.create_task(mutate())
    await asyncio.wait_for(entered.wait(), timeout=1)
    shutdown = asyncio.create_task(service.stop())
    for _ in range(20):
        if service._stopping:
            break
        await asyncio.sleep(0)
    assert service._stopping
    release.set()
    await asyncio.wait_for(applying, timeout=1)
    await asyncio.wait_for(shutdown, timeout=1)

    assert service.ready is False
    assert service.main_loop_alive is False
    assert service._scheduler is None
    assert service._pool is None


@pytest.mark.asyncio
async def test_cancelled_lock_acquisition_releases_locally_acquired_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = ProberService(
        tmp_path, schedule_enabled=False, control_enabled=False
    )
    entered = threading.Event()
    release = threading.Event()

    class BlockingLock:
        acquired = False
        released = False

        def acquire(self):
            entered.set()
            if not release.wait(timeout=2):
                raise RuntimeError("test lock acquisition was not released")
            self.acquired = True
            return self

        def release(self) -> None:
            self.released = True
            self.acquired = False

    data_lock = BlockingLock()
    monkeypatch.setattr(service.store, "lock", lambda **_kwargs: data_lock)
    starting = asyncio.create_task(service.start())
    assert await asyncio.to_thread(entered.wait, 1)
    starting.cancel()
    await asyncio.sleep(0)
    starting.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await starting

    assert data_lock.released is True
    assert data_lock.acquired is False
    assert service._data_lock is None
    assert service._lifecycle_lock.locked() is False
    assert service.main_loop_alive is False
    assert service.ready is False


@pytest.mark.asyncio
async def test_cancelled_startup_drains_recovery_before_releasing_data_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = ProberService(
        tmp_path, schedule_enabled=False, control_enabled=False
    )
    recovery_entered = threading.Event()
    release_recovery = threading.Event()
    events: list[str] = []

    class RecordingLock:
        acquired = False

        def acquire(self):
            self.acquired = True
            events.append("lock-acquired")
            return self

        def release(self) -> None:
            assert events[-1] == "recovery-finished"
            events.append("lock-released")
            self.acquired = False

    data_lock = RecordingLock()

    def delayed_recovery(_config_path) -> None:
        events.append("recovery-started")
        recovery_entered.set()
        if not release_recovery.wait(timeout=2):
            raise RuntimeError("test recovery was not released")
        events.append("recovery-finished")

    monkeypatch.setattr(service.store, "lock", lambda **_kwargs: data_lock)
    monkeypatch.setattr(service.store, "recover_config_replace", delayed_recovery)
    starting = asyncio.create_task(service.start())
    assert await asyncio.to_thread(recovery_entered.wait, 1)
    starting.cancel()
    await asyncio.sleep(0)
    starting.cancel()
    release_recovery.set()
    with pytest.raises(asyncio.CancelledError):
        await starting

    assert events == [
        "lock-acquired",
        "recovery-started",
        "recovery-finished",
        "lock-released",
    ]
    assert service._data_lock is None


@pytest.mark.asyncio
async def test_concurrent_starts_share_one_serialized_lifecycle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = ProberService(
        tmp_path, schedule_enabled=False, control_enabled=False
    )
    recovery_entered = threading.Event()
    release_recovery = threading.Event()
    lock_calls = 0

    class RecordingLock:
        acquired = False

        def acquire(self):
            self.acquired = True
            return self

        def release(self) -> None:
            self.acquired = False

    data_lock = RecordingLock()

    def make_lock(**_kwargs):
        nonlocal lock_calls
        lock_calls += 1
        return data_lock

    def delayed_recovery(_config_path) -> None:
        recovery_entered.set()
        if not release_recovery.wait(timeout=2):
            raise RuntimeError("test recovery was not released")

    monkeypatch.setattr(service.store, "lock", make_lock)
    monkeypatch.setattr(service.store, "recover_config_replace", delayed_recovery)
    first = asyncio.create_task(service.start())
    assert await asyncio.to_thread(recovery_entered.wait, 1)
    second = asyncio.create_task(service.start())
    await asyncio.sleep(0)
    assert lock_calls == 1
    release_recovery.set()
    await asyncio.gather(first, second)
    try:
        assert lock_calls == 1
        assert service._data_lock is data_lock
        assert data_lock.acquired is True
        assert service.main_loop_alive is True
    finally:
        await service.stop()
    assert data_lock.acquired is False


@pytest.mark.asyncio
async def test_config_removal_prunes_public_source_state(tmp_path: Path) -> None:
    service = ProberService(
        tmp_path, schedule_enabled=False, control_enabled=False,
        xray_binary="/usr/bin/true",
    )
    service.generations = {"src": _generation()}
    service.source_status = {"src": SourceStatus("src", refresh_success=True)}
    await service._apply_config(AppConfig(instance_id="empty"))
    try:
        assert service.generations == {}
        assert service.source_status == {}
        assert service.entries_snapshot() == []
    finally:
        await service.stop()


@pytest.mark.asyncio
async def test_parallel_source_refresh_keeps_both_registry_updates(tmp_path: Path) -> None:
    uri = (
        "vless://550e8400-e29b-41d4-a716-446655440000@example.test:443"
        "?encryption=none&security=tls&type=tcp&sni=example.test#entry\n"
    )
    for source_id in ("one", "two"):
        (tmp_path / f"{source_id}.txt").write_text(uri, encoding="utf-8")
    service = ProberService(
        tmp_path, schedule_enabled=False, control_enabled=False,
        xray_binary="/usr/bin/true",
    )
    await service._apply_config(_source_config(tmp_path, ("one", "two")))
    try:
        statuses = await asyncio.gather(
            service.refresh_source("one"), service.refresh_source("two")
        )
        assert all(item.refresh_success for item in statuses)
        assert set(service.generations) == {"one", "two"}
        assert set(service.identity.to_model().sources) == {"one", "two"}
    finally:
        await service.stop()


@pytest.mark.asyncio
async def test_reconciliation_revision_rejects_changed_candidates(tmp_path: Path) -> None:
    source = tmp_path / "src.txt"
    source.write_text(
        "vless://550e8400-e29b-41d4-a716-446655440000@example.test:443"
        "?encryption=none&security=tls&type=tcp&sni=example.test#one\n",
        encoding="utf-8",
    )
    service = ProberService(
        tmp_path, schedule_enabled=False, control_enabled=False,
        xray_binary="/usr/bin/true",
    )
    await service._apply_config(_source_config(tmp_path))
    try:
        preview = await service.preview_reconciliation("src")
        source.write_text(
            "vless://650e8400-e29b-41d4-a716-446655440000@example.test:443"
            "?encryption=none&security=tls&type=tcp&sni=example.test#two\n",
            encoding="utf-8",
        )
        with pytest.raises(ServiceError, match="changed concurrently"):
            await service.reconcile_source(
                "src",
                preview["assignments"],
                expected_revision=preview["revision"],
            )
    finally:
        await service.stop()


@pytest.mark.asyncio
async def test_result_persistence_failure_returns_executor_error(tmp_path: Path) -> None:
    config = _source_config(tmp_path)
    generation = _generation()
    inventory = compile_inventory(config, {"src": generation})
    check = next(iter(inventory.values()))
    service = ProberService(tmp_path, schedule_enabled=False, control_enabled=False)
    service.config = config
    service.inventory = inventory

    class Pool:
        @asynccontextmanager
        async def acquire(self, _check):
            yield SimpleNamespace(socks_port=1080, socks_host="127.0.0.1")

    class Checker:
        async def run_cycle(self, definition, *_args, **_kwargs):
            return CycleResult(
                check_id=definition.check_id,
                generation=definition.generation,
                reachability=ReachabilityResult(
                    state=ReachabilityState.SUCCESS,
                    success_count=1,
                    quorum=1,
                    targets=[],
                ),
            )

    service._pool = Pool()  # type: ignore[assignment]
    service._checker = Checker()  # type: ignore[assignment]

    def fail_save(_result) -> None:
        raise StorageError("disk full")

    service._save_result = fail_save  # type: ignore[method-assign]
    result = await service.execute(check)
    assert result.state is ReachabilityState.ERROR
    assert result.reason is Reason.INTERNAL
    assert result.error == "result persistence failed"

    scheduled = ScheduledCheck(check.definition.check_id, "g1", 60)
    await service._scheduler_error(scheduled, "scheduler")
    assert service.results[check.definition.check_id].reason is Reason.SCHEDULER


@pytest.mark.asyncio
async def test_shutdown_serializes_with_mutations_and_rejects_queued_write(
    tmp_path: Path,
) -> None:
    service = ProberService(
        tmp_path,
        schedule_enabled=False,
        control_enabled=False,
        xray_binary="/usr/bin/true",
    )
    initial = AppConfig(instance_id="initial")
    save_app_config(initial, service.config_path)
    await service.start()

    await service._mutation_lock.acquire()
    stopping = asyncio.create_task(service.stop())
    for _ in range(20):
        if service._stopping:
            break
        await asyncio.sleep(0)
    assert service._stopping
    queued_write = asyncio.create_task(
        service.replace_config(
            AppConfig(instance_id="too-late"),
            expected_revision=_config_revision(initial),
        )
    )
    service._mutation_lock.release()

    await asyncio.wait_for(stopping, timeout=1)
    with pytest.raises(ServiceError, match="stopping"):
        await asyncio.wait_for(queued_write, timeout=1)
    assert load_app_config(service.config_path).instance_id == "initial"
    assert service._data_lock is None


@pytest.mark.asyncio
async def test_cancelled_shutdown_still_completes_cleanup(tmp_path: Path) -> None:
    service = ProberService(
        tmp_path,
        schedule_enabled=False,
        control_enabled=False,
        xray_binary="/usr/bin/true",
    )
    save_app_config(AppConfig(instance_id="initial"), service.config_path)
    await service.start()
    scheduler = service._scheduler
    assert scheduler is not None
    entered = asyncio.Event()
    release = asyncio.Event()
    original_stop = scheduler.stop

    async def delayed_stop() -> None:
        entered.set()
        await release.wait()
        await original_stop()

    scheduler.stop = delayed_stop  # type: ignore[method-assign]
    shutdown = asyncio.create_task(service.stop())
    await asyncio.wait_for(entered.wait(), timeout=1)
    shutdown.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(shutdown, timeout=1)

    assert service._scheduler is None
    assert service._pool is None
    assert service._data_lock is None
    assert not service.main_loop_alive
