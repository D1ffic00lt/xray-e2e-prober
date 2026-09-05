import asyncio
from pathlib import Path

import pytest

from xray_e2e_prober.inventory import compile_inventory
from xray_e2e_prober.models import (
    AppConfig,
    EntryRecord,
    ReachabilityState,
    Reason,
    RunResult,
    SourceGeneration,
    utc_now,
)
from xray_e2e_prober.scheduler import Scheduler
from xray_e2e_prober.service import ProberService, ServiceError, save_app_config


def _config(subscription: Path) -> AppConfig:
    return AppConfig.model_validate(
        {
            "schema_version": 1,
            "instance_id": "test-instance",
            "sources": [
                {
                    "source_id": "source-one",
                    "name": "local",
                    "kind": "file",
                    "location": str(subscription),
                    "format": "auto",
                    "target_set_ids": ["default"],
                }
            ],
            "target_sets": [
                {
                    "target_set_id": "default",
                    "name": "default",
                    "quorum": 1,
                    "targets": [
                        {
                            "target_id": "example",
                            "name": "example",
                            "url": "https://example.test/",
                        }
                    ],
                }
            ],
        }
    )


@pytest.mark.asyncio
async def test_refresh_publishes_lkg_and_rejects_bad_candidate(tmp_path: Path) -> None:
    subscription = tmp_path / "subscription.txt"
    subscription.write_text(
        "vless://550e8400-e29b-41d4-a716-446655440000@example.test:443"
        "?encryption=none&security=tls&type=tcp&sni=example.test#one\n",
        encoding="utf-8",
    )
    save_app_config(_config(subscription), tmp_path / "config.yaml")
    service = ProberService(
        tmp_path, schedule_enabled=False, control_enabled=False, xray_binary="/usr/bin/true"
    )
    await service.start()
    try:
        assert service.ready
        first_status = await service.refresh_source("source-one")
        assert first_status.refresh_success is True
        assert len(service.inventory) == 1
        first_generation = service.generations["source-one"].generation

        # Identical refreshes do not manufacture a generation and erase a result.
        second_status = await service.refresh_source("source-one")
        assert second_status.refresh_success is True
        assert service.generations["source-one"].generation == first_generation

        subscription.write_text("this is not a supported subscription", encoding="utf-8")
        failed_status = await service.refresh_source("source-one")
        assert failed_status.refresh_success is False
        assert failed_status.reason == "source_parse"
        assert service.generations["source-one"].generation == first_generation
        assert len(service.inventory) == 1
    finally:
        await service.stop()

    # A new process can schedule checks from the durable last-known-good copy.
    restarted = ProberService(
        tmp_path, schedule_enabled=False, control_enabled=False, xray_binary="/usr/bin/true"
    )
    await restarted.start()
    try:
        assert restarted.ready
        assert list(restarted.generations) == ["source-one"]
        assert len(restarted.inventory) == 1
    finally:
        await restarted.stop()


@pytest.mark.asyncio
async def test_missing_configuration_is_live_but_not_ready(tmp_path: Path) -> None:
    service = ProberService(tmp_path, schedule_enabled=False, control_enabled=False)
    await service.start()
    try:
        assert service.main_loop_alive
        assert not service.ready
    finally:
        await service.stop()


@pytest.mark.asyncio
async def test_runtime_timing_config_is_propagated_to_pool(tmp_path: Path) -> None:
    service = ProberService(
        tmp_path, schedule_enabled=False, control_enabled=False
    )
    config = AppConfig.model_validate(
        {
            "instance_id": "timing-test",
            "scheduler": {
                "runtime_restart_backoff_initial": 2,
                "runtime_restart_backoff_max": 9,
                "observatory_warmup_delay": 3,
                "observatory_warmup_timeout": 7,
            },
        }
    )
    await service._apply_config(config)
    try:
        assert service._pool is not None
        assert service._pool.restart_backoff_initial == 2
        assert service._pool.restart_backoff_max == 9
        assert service._pool.observatory_warmup_delay == 3
        assert service._pool.observatory_warmup_timeout == 7
    finally:
        await service.stop()


def test_check_snapshot_keeps_disabled_and_runtime_error_children(
    tmp_path: Path,
) -> None:
    base = _config(tmp_path / "subscription.txt")
    raw = base.model_dump(mode="python")
    raw["target_sets"][0]["targets"].append(
        {
            "target_id": "disabled-target",
            "name": "disabled",
            "url": "https://disabled.example.test/",
            "enabled": False,
        }
    )
    raw["egress_assertions"] = [
        {
            "assertion_id": "disabled-egress",
            "name": "disabled",
            "url": "https://echo.example.test/",
            "expected_cidrs": ["192.0.2.0/24"],
            "enabled": False,
        }
    ]
    raw["assignments"] = [
        {
            "assignment_id": "with-egress",
            "entry_id": "entry-one",
            "target_set_ids": ["default"],
            "egress_assertion_ids": ["disabled-egress"],
        }
    ]
    config = AppConfig.model_validate(raw)
    generation = SourceGeneration(
        source_id="source-one",
        generation="gen1",
        entries=[
            EntryRecord(
                entry_id="entry-one",
                source_id="source-one",
                name="one",
                mode="connection",
                generation="gen1",
                payload="vless://secret",
            )
        ],
    )
    service = ProberService(tmp_path, schedule_enabled=False, control_enabled=False)
    service.config = config
    service.inventory = compile_inventory(config, {"source-one": generation})
    compiled = next(iter(service.inventory.values()))
    now = utc_now()
    service.results[compiled.definition.check_id] = RunResult(
        run_id="run-error",
        check_id=compiled.definition.check_id,
        instance_id=service.config.instance_id,
        source_id=compiled.definition.source_id,
        entry_id=compiled.definition.entry_id,
        mode=compiled.definition.mode,
        target_set_id=compiled.definition.target_set_id,
        generation=compiled.definition.generation,
        state=ReachabilityState.ERROR,
        started_at=now,
        completed_at=now,
        quorum=compiled.target_set.quorum,
        reason=Reason.RUNTIME_START,
        error="Xray did not start",
    )
    snapshot = service.check_snapshot(compiled.definition.check_id)
    assert snapshot is not None
    assert [item["state"] for item in snapshot["targets"]] == ["error", "disabled"]
    assert [item["state"] for item in snapshot["egress"]] == ["disabled"]


@pytest.mark.asyncio
async def test_manual_run_uses_scheduler_overlap_protection(tmp_path: Path) -> None:
    config = _config(tmp_path / "subscription.txt")
    generation = SourceGeneration(
        source_id="source-one",
        generation="gen1",
        entries=[EntryRecord(
            entry_id="entry-one", source_id="source-one", name="one",
            mode="connection", generation="gen1", payload="vless://secret",
        )],
    )
    inventory = compile_inventory(config, {"source-one": generation})
    check_id = next(iter(inventory))
    service = ProberService(tmp_path, schedule_enabled=False, control_enabled=False)
    service.config = config
    service.inventory = inventory
    service.ready = True
    service._scheduler = Scheduler(
        service._execute_scheduled,
        concurrency=1,
        max_queue=2,
        on_error=service._scheduler_error,
    )
    await service._scheduler.start()
    gate = asyncio.Event()
    entered = asyncio.Event()
    active = 0
    max_active = 0

    async def fake_execute(check):
        nonlocal active, max_active
        active += 1
        max_active = max(max_active, active)
        entered.set()
        try:
            await gate.wait()
        finally:
            active -= 1
        now = utc_now()
        definition = check.definition
        return RunResult(
            run_id="manual-success", check_id=definition.check_id,
            instance_id=config.instance_id, source_id=definition.source_id,
            entry_id=definition.entry_id, mode=definition.mode,
            target_set_id=definition.target_set_id, generation=definition.generation,
            state=ReachabilityState.SUCCESS, started_at=now, completed_at=now,
            success_count=1, quorum=1,
        )

    service.execute = fake_execute  # type: ignore[method-assign]
    first = asyncio.create_task(service.run_checks(check_id))
    try:
        await asyncio.wait_for(entered.wait(), timeout=1)
        rejected, exit_code = await service.run_checks(check_id)
        assert exit_code == 2
        assert rejected[0].reason is Reason.SCHEDULER
        assert max_active == 1
        gate.set()
        completed, exit_code = await first
        assert exit_code == 0
        assert completed[0].state is ReachabilityState.SUCCESS
    finally:
        gate.set()
        await service._scheduler.stop()


@pytest.mark.asyncio
async def test_disabled_check_remains_observable_but_cannot_run(tmp_path: Path) -> None:
    config = _config(tmp_path / "subscription.txt")
    config.assignments = [{
        "assignment_id": "disabled-entry", "entry_id": "entry-one",
        "enabled": False, "target_set_ids": ["default"],
    }]
    generation = SourceGeneration(
        source_id="source-one",
        generation="gen1",
        entries=[EntryRecord(
            entry_id="entry-one", source_id="source-one", name="one",
            mode="connection", generation="gen1", payload="vless://secret",
        )],
    )
    service = ProberService(tmp_path, schedule_enabled=False, control_enabled=False)
    service.config = config
    service.inventory = compile_inventory(config, {"source-one": generation})
    service.ready = True
    check_id = next(iter(service.inventory))
    snapshot = service.check_snapshot(check_id)
    assert snapshot is not None and snapshot["state"] == "disabled"
    assert [item["state"] for item in snapshot["targets"]] == ["disabled"]
    assert f'state="disabled"}} 1.0' in service.metrics.render().decode()
    assert await service.run_checks() == ([], 2)
    with pytest.raises(ServiceError, match="disabled"):
        await service.run_checks(check_id)
