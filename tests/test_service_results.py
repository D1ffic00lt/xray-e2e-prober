from pathlib import Path

import pytest

from xray_e2e_prober.inventory import compile_inventory
from xray_e2e_prober.models import (
    AppConfig,
    EntryRecord,
    ReachabilityState,
    RunResult,
    SourceGeneration,
    utc_now,
)
from xray_e2e_prober.service import ProberService, _config_revision


def _state(tmp_path: Path, *, url: str = "https://one.example.test"):
    config = AppConfig.model_validate({
        "instance_id": "result-test",
        "sources": [{
            "source_id": "src", "name": "source", "kind": "file",
            "location": str(tmp_path / "source.txt"), "target_set_ids": ["set"],
        }],
        "target_sets": [{
            "target_set_id": "set", "name": "set", "quorum": 1,
            "targets": [{"target_id": "one", "name": "one", "url": url}],
        }],
    })
    generation = SourceGeneration(
        source_id="src", generation="g1", entries=[EntryRecord(
            entry_id="entry", source_id="src", name="entry", mode="connection",
            generation="g1", payload="vless://secret",
        )],
    )
    inventory = compile_inventory(config, {"src": generation})
    return config, generation, inventory


def _result(config: AppConfig, check_id: str) -> RunResult:
    now = utc_now()
    return RunResult(
        run_id="run", check_id=check_id, instance_id=config.instance_id,
        source_id="src", entry_id="entry", mode="connection",
        target_set_id="set", generation="g1",
        config_revision=_config_revision(config), state=ReachabilityState.SUCCESS,
        started_at=now, completed_at=now, success_count=1, quorum=1,
    )


def test_loaded_recent_result_is_forced_stale(tmp_path: Path) -> None:
    config, generation, inventory = _state(tmp_path)
    service = ProberService(tmp_path, schedule_enabled=False, control_enabled=False)
    service.store.save_result(_result(config, next(iter(inventory))))
    service._load_results_as_stale()
    service.config = config
    service.generations = {"src": generation}
    service.inventory = inventory
    snapshot = service.check_snapshot(next(iter(inventory)))
    assert snapshot is not None and snapshot["state"] == "stale"


def test_config_revision_invalidates_same_generation_result(tmp_path: Path) -> None:
    old, generation, inventory = _state(tmp_path)
    service = ProberService(tmp_path, schedule_enabled=False, control_enabled=False)
    check_id = next(iter(inventory))
    service.config = old
    service.inventory = inventory
    service.results[check_id] = _result(old, check_id)
    new, _, new_inventory = _state(tmp_path, url="https://two.example.test")
    service.config = new
    service.inventory = new_inventory
    service._drop_obsolete_results()
    assert check_id not in service.results
