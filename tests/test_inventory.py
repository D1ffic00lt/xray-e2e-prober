from xray_e2e_prober.inventory import compile_inventory, public_check_id
import pytest

from xray_e2e_prober.models import AppConfig, EntryRecord, SourceGeneration


def test_inventory_is_automatic_and_check_id_ignores_generation() -> None:
    config = AppConfig.model_validate(
        {
            "instance_id": "i1",
            "sources": [
                {
                    "source_id": "s1",
                    "name": "source",
                    "kind": "file",
                    "location": "/private/secret-subscription",
                    "target_set_ids": ["ts1"],
                }
            ],
            "target_sets": [
                {
                    "target_set_id": "ts1",
                    "name": "default",
                    "quorum": 1,
                    "targets": [
                        {"target_id": "t1", "name": "one", "url": "https://example.test"}
                    ],
                }
            ],
        }
    )
    entry = EntryRecord(
        entry_id="e1",
        source_id="s1",
        name="entry",
        mode="connection",
        generation="gen1",
        payload="vless://secret",
    )
    first = compile_inventory(
        config,
        {"s1": SourceGeneration(source_id="s1", generation="gen1", entries=[entry])},
    )
    entry.generation = "gen2"
    second = compile_inventory(
        config,
        {"s1": SourceGeneration(source_id="s1", generation="gen2", entries=[entry])},
    )
    assert list(first) == list(second)
    assert list(first) == [public_check_id("e1", "ts1", "connection")]


def test_check_id_uses_durable_assignment_id_not_private_profile_tags() -> None:
    raw = {
        "instance_id": "i1",
        "sources": [{
            "source_id": "s1", "name": "source", "kind": "file",
            "location": "/private/subscription", "target_set_ids": ["ts1"],
        }],
        "target_sets": [{
            "target_set_id": "ts1", "name": "targets", "quorum": 1,
            "targets": [{"target_id": "t1", "name": "one", "url": "https://example.test"}],
        }],
        "assignments": [{
            "assignment_id": "durable_route", "entry_id": "e1",
            "target_set_ids": ["ts1"], "mode": "profile",
            "outbound_tag": "PRIVATE-OUTBOUND-A", "inbound_tag": "PRIVATE-INBOUND-A",
        }],
    }
    generation = SourceGeneration(
        source_id="s1",
        generation="gen1",
        entries=[EntryRecord(
            entry_id="e1", source_id="s1", name="entry", mode="profile",
            generation="gen1", payload="vless://secret",
        )],
    )
    first = compile_inventory(AppConfig.model_validate(raw), {"s1": generation})
    raw["assignments"][0]["outbound_tag"] = "PRIVATE-OUTBOUND-B"
    raw["assignments"][0]["inbound_tag"] = "PRIVATE-INBOUND-B"
    second = compile_inventory(AppConfig.model_validate(raw), {"s1": generation})
    raw["assignments"][0]["assignment_id"] = "another_route"
    third = compile_inventory(AppConfig.model_validate(raw), {"s1": generation})

    assert list(first) == list(second)
    assert list(first) != list(third)


@pytest.mark.parametrize("disabled_component", ["source", "assignment", "target_set"])
def test_known_disabled_components_keep_disabled_check(disabled_component: str) -> None:
    raw = {
        "instance_id": "i1",
        "sources": [{
            "source_id": "s1", "name": "source", "kind": "file",
            "location": "/private/subscription", "target_set_ids": ["ts1"],
            "enabled": disabled_component != "source",
        }],
        "target_sets": [{
            "target_set_id": "ts1", "name": "targets", "quorum": 1,
            "enabled": disabled_component != "target_set",
            "targets": [{"target_id": "t1", "name": "one", "url": "https://example.test"}],
        }],
        "assignments": [{
            "assignment_id": "entry-rule", "entry_id": "e1",
            "enabled": disabled_component != "assignment", "target_set_ids": ["ts1"],
            "runtime_lifecycle": "fresh",
        }],
    }
    config = AppConfig.model_validate(raw)
    generation = SourceGeneration(
        source_id="s1",
        generation="gen1",
        entries=[EntryRecord(
            entry_id="e1", source_id="s1", name="entry", mode="connection",
            generation="gen1", payload="vless://secret",
        )],
    )
    inventory = compile_inventory(config, {"s1": generation})
    assert len(inventory) == 1
    check = next(iter(inventory.values())).definition
    assert check.enabled is False
    assert check.runtime_lifecycle.value == "fresh"


def test_persistent_profiles_must_leave_capacity_for_fresh_checks() -> None:
    from xray_e2e_prober.inventory import InventoryError

    config = AppConfig.model_validate(
        {
            "instance_id": "i1",
            "sources": [
                {
                    "source_id": "s1",
                    "name": "source",
                    "kind": "file",
                    "location": "/private/subscription",
                    "target_set_ids": ["ts1"],
                }
            ],
            "target_sets": [
                {
                    "target_set_id": "ts1",
                    "name": "targets",
                    "quorum": 1,
                    "targets": [
                        {
                            "target_id": "t1",
                            "name": "one",
                            "url": "https://example.test",
                        }
                    ],
                }
            ],
            "assignments": [
                {
                    "assignment_id": "persistent-entry",
                    "entry_id": "persistent",
                    "target_set_ids": ["ts1"],
                    "mode": "profile",
                    "runtime_lifecycle": "persistent",
                }
            ],
            "scheduler": {"max_active_runtimes": 1},
        }
    )
    generation = SourceGeneration(
        source_id="s1",
        generation="gen1",
        entries=[
            EntryRecord(
                entry_id="fresh",
                source_id="s1",
                name="fresh",
                mode="connection",
                generation="gen1",
                payload="vless://secret",
            ),
            EntryRecord(
                entry_id="persistent",
                source_id="s1",
                name="persistent",
                mode="profile",
                generation="gen1",
                payload={"outbounds": [{"protocol": "vless"}]},
            ),
        ],
    )
    with pytest.raises(InventoryError, match="no runtime slot"):
        compile_inventory(config, {"s1": generation})
