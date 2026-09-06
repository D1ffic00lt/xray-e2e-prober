from pathlib import Path

import pytest

from xray_e2e_prober.models import (
    AppConfig,
    CycleResult,
    EgressResult,
    EgressState,
    ReachabilityResult,
    ReachabilityState,
)


def _raw(tmp_path: Path) -> dict:
    return {
        "instance_id": "validation-test",
        "sources": [{
            "source_id": "src", "name": "source", "kind": "file",
            "location": str(tmp_path / "source.txt"),
            "target_set_ids": ["set"],
        }],
        "target_sets": [{
            "target_set_id": "set", "name": "set", "quorum": 1,
            "targets": [{"target_id": "one", "name": "one", "url": "https://example.test"}],
        }],
    }


def test_duplicate_default_target_references_are_rejected(tmp_path: Path) -> None:
    raw = _raw(tmp_path)
    raw["default_target_set_ids"] = ["set", "set"]
    with pytest.raises(ValueError, match="default_target_set_ids"):
        AppConfig.model_validate(raw)


def test_duplicate_assignment_egress_references_are_rejected(tmp_path: Path) -> None:
    raw = _raw(tmp_path)
    raw["egress_assertions"] = [{
        "assertion_id": "exit", "name": "exit", "url": "https://example.test/ip",
        "expected_cidrs": ["192.0.2.0/24"],
    }]
    raw["assignments"] = [{
        "assignment_id": "a1", "source_id": "src", "target_set_ids": ["set"],
        "egress_assertion_ids": ["exit", "exit"],
    }]
    with pytest.raises(ValueError, match="egress_assertion_ids"):
        AppConfig.model_validate(raw)


@pytest.mark.parametrize(
    ("reachability_state", "egress_state", "expected"),
    [
        (ReachabilityState.SUCCESS, None, ReachabilityState.SUCCESS),
        (ReachabilityState.SUCCESS, EgressState.MATCH, ReachabilityState.SUCCESS),
        (ReachabilityState.SUCCESS, EgressState.DISABLED, ReachabilityState.SUCCESS),
        (ReachabilityState.SUCCESS, EgressState.MISMATCH, ReachabilityState.FAILURE),
        (ReachabilityState.FAILURE, EgressState.ERROR, ReachabilityState.ERROR),
        (ReachabilityState.FAILURE, EgressState.STALE, ReachabilityState.STALE),
        (ReachabilityState.FAILURE, EgressState.UNKNOWN, ReachabilityState.UNKNOWN),
    ],
)
def test_cycle_overall_state_includes_egress_assertions(
    reachability_state: ReachabilityState,
    egress_state: EgressState | None,
    expected: ReachabilityState,
) -> None:
    egress = (
        []
        if egress_state is None
        else [EgressResult(assertion_id="exit", state=egress_state)]
    )
    cycle = CycleResult(
        check_id="check",
        generation="generation",
        reachability=ReachabilityResult(
            state=reachability_state,
            success_count=int(reachability_state is ReachabilityState.SUCCESS),
            quorum=1,
            targets=[],
        ),
        egress=egress,
    )

    assert cycle.overall_state is expected
