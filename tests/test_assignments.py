import re
import time

import pytest

from xray_e2e_prober.assignments import matches_filter, resolve_assignment
from xray_e2e_prober.inventory import compile_inventory
from xray_e2e_prober.models import AppConfig, AssignmentFilter, EntryRecord, SourceGeneration
from xray_e2e_prober.safe_regex import UnsafeNameRegexError


ENTRY = {
    "entry_id": "e1",
    "source_id": "s1",
    "name": "DE reality",
    "protocol": "vless",
    "transport": "tcp",
    "mode": "connection",
    "tags": ["paid"],
}


def test_individual_rule_wins_over_first_matching_saved_rule() -> None:
    rules = [
        {
            "rule_id": "group",
            "filter": {"protocol": "vless"},
            "target_set_ids": ["group-targets"],
        },
        {
            "rule_id": "individual",
            "entry_id": "e1",
            "enabled": False,
            "target_set_ids": [],
        },
    ]
    decision = resolve_assignment(
        ENTRY,
        rules=rules,
        source_target_set_ids=["source-targets"],
        global_target_set_ids=["global-targets"],
    )
    assert not decision.enabled
    assert decision.rule == "entry:individual"


def test_source_default_wins_over_global_default() -> None:
    decision = resolve_assignment(
        ENTRY,
        rules=[],
        source_target_set_ids=["source-targets"],
        global_target_set_ids=["global-targets"],
    )
    assert decision.target_set_ids == ("source-targets",)
    assert decision.rule == "source-default"


def test_source_default_propagates_egress_assertions() -> None:
    entry = ENTRY
    decision = resolve_assignment(
        entry,
        rules=[],
        source_target_set_ids=["source-set"],
        source_egress_assertion_ids=["office-egress"],
        global_target_set_ids=["global-set"],
    )
    assert decision.egress_assertion_ids == ("office-egress",)


def test_source_tags_participate_in_inventory_assignment() -> None:
    config = AppConfig.model_validate(
        {
            "instance_id": "tag-test",
            "sources": [{
                "source_id": "s1", "name": "source", "kind": "file",
                "location": "/tmp/source", "tags": ["region-eu"],
            }],
            "target_sets": [{
                "target_set_id": "t1", "name": "target", "quorum": 1,
                "targets": [{"target_id": "one", "name": "one", "url": "https://example.test"}],
            }],
            "assignments": [{
                "assignment_id": "tagged", "source_id": "s1",
                "filter": {"tags": ["region-eu"]}, "target_set_ids": ["t1"],
            }],
        }
    )
    generation = SourceGeneration(
        source_id="s1",
        generation="g1",
        entries=[EntryRecord(
            entry_id="e1", source_id="s1", name="one", mode="connection",
            generation="g1", payload="vless://secret",
        )],
    )
    inventory = compile_inventory(config, {"s1": generation})
    check = next(iter(inventory.values()))
    assert check.assignment_reason == "rule:tagged"
    assert check.entry.tags == {"region-eu"}


def test_rule_selects_runtime_lifecycle() -> None:
    decision = resolve_assignment(
        ENTRY,
        rules=[
            {
                "rule_id": "fresh-profile",
                "entry_id": "e1",
                "runtime_lifecycle": "fresh",
                "target_set_ids": ["targets"],
            }
        ],
    )
    assert decision.runtime_lifecycle == "fresh"


def test_safe_name_regex_preserves_documented_case_insensitive_alternation() -> None:
    selector = AssignmentFilter(name_regex="(?i)(retired|disabled)")
    assert matches_filter({"name": "DE RETIRED node"}, selector)
    assert matches_filter({"name": "disabled"}, selector)
    assert not matches_filter({"name": "healthy"}, selector)


def test_safe_name_regex_preserves_cli_generated_exact_names() -> None:
    name = r"DE (paid)+ [blue] #1\\"
    selector = AssignmentFilter(name_regex=f"^{re.escape(name)}$")
    assert matches_filter({"name": name}, selector)
    assert not matches_filter({"name": name + " duplicate"}, selector)


@pytest.mark.parametrize(
    "pattern",
    [
        "(a+)+$",
        "a*a*$",
        "a{1,3}",
        "(?=private)",
        r"^(a)\1$",
        "foo(bar|baz)",
    ],
)
def test_unsafe_assignment_name_regex_is_rejected(pattern: str) -> None:
    with pytest.raises(ValueError, match="assignment name_regex"):
        AssignmentFilter(name_regex=pattern)


def test_catastrophic_regex_is_rejected_promptly_even_for_long_name() -> None:
    started = time.perf_counter()
    with pytest.raises(UnsafeNameRegexError):
        matches_filter(
            {"name": "a" * 100_000 + "!"},
            {"name_regex": "(a+)+$"},
        )
    assert time.perf_counter() - started < 0.25


def test_name_glob_is_available_for_safe_wildcards() -> None:
    selector = AssignmentFilter(name_glob="*-disabled")
    assert matches_filter({"name": "EU-DISABLED"}, selector)
    assert not matches_filter({"name": "EU-active"}, selector)


def test_assignment_name_regex_length_is_bounded() -> None:
    with pytest.raises(ValueError, match="exceeds 256 characters"):
        AssignmentFilter(name_regex="a" * 257)
