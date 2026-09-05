from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest
from pydantic import SecretStr

from xray_e2e_prober.config import (
    ConfigLoadError,
    ConfigValidationError,
    export_config_yaml,
    load_config,
    loads_config,
    resolve_source_headers,
    save_config,
)
from xray_e2e_prober.identity import IdentityRegistry, stable_check_id
from xray_e2e_prober.importers import import_content
from xray_e2e_prober.models import (
    AppConfig,
    CheckMode,
    EntryKind,
    EntryRecord,
    IdentityBindingModel,
    IdentityRegistryModel,
    SecretRef,
    SourceConfig,
    SourceGeneration,
    SourceKind,
    TargetConfig,
    TargetSetConfig,
)
from xray_e2e_prober.storage import (
    DataStore,
    FileLock,
    LockTimeoutError,
    StorageError,
    atomic_write_text,
)


UUID = "11111111-2222-4333-8444-555555555555"
URI = (
    f"vless://{UUID}@edge.example:443?type=tcp&security=reality&encryption=none"
    "&sni=www.example.com&fp=chrome&pbk=VERY_SECRET_PUBLIC_KEY&sid=0123#Primary"
)


def sample_config(tmp_path: Path) -> AppConfig:
    target = TargetConfig(
        target_id="target_health",
        name="Health",
        url="https://target.example/health",
        expected_statuses={200, 204},
    )
    target_set = TargetSetConfig(
        target_set_id="set_default", name="Default", targets=[target], quorum=1
    )
    source = SourceConfig(
        source_id="src_main",
        name="Main",
        kind=SourceKind.FILE,
        location=SecretStr(str(tmp_path / "subscription.secret")),
        headers={"Authorization": SecretStr("Bearer TOP_SECRET")},
        headers_ref={"X-API-Key": SecretRef(file="api-key")},
        target_set_ids=["set_default"],
    )
    return AppConfig(instance_id="instance_local", sources=[source], target_sets=[target_set])


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_config_round_trip_is_atomic_private_and_export_is_redacted(tmp_path: Path) -> None:
    config = sample_config(tmp_path)
    path = tmp_path / "config.yaml"
    save_config(config, path)
    assert mode(path) == 0o600
    loaded = load_config(path)
    assert loaded.instance_id == config.instance_id
    assert loaded.sources[0].location.get_secret_value() == str(tmp_path / "subscription.secret")

    exported = export_config_yaml(loaded)
    assert "TOP_SECRET" not in exported
    assert "subscription.secret" not in exported
    assert "VERY_SECRET" not in exported
    assert "<redacted>" in exported
    assert "api-key" in exported


def test_safe_yaml_rejects_duplicate_keys_custom_tags_and_wrong_version() -> None:
    with pytest.raises(ConfigLoadError):
        loads_config("schema_version: 1\ninstance_id: first\ninstance_id: second\n")
    with pytest.raises(ConfigLoadError):
        loads_config("schema_version: 1\ninstance_id: !!python/object:os.system ['id']\n")
    with pytest.raises(ConfigValidationError):
        loads_config("schema_version: 99\ninstance_id: instance_local\n")
    with pytest.raises(ConfigValidationError):
        loads_config("instance_id: instance_local\n")


def test_secret_reference_resolution(tmp_path: Path) -> None:
    key = tmp_path / "api-key"
    key.write_text("from-file\n")
    source = SourceConfig(
        source_id="src_ref",
        name="Reference",
        kind="file",
        location_ref=SecretRef(env="SUB_PATH"),
        headers_ref={"X-Key": SecretRef(file="api-key")},
    )
    headers = resolve_source_headers(source, base_dir=tmp_path)
    assert headers == {"X-Key": "from-file"}


def test_file_lock_has_bounded_contention(tmp_path: Path) -> None:
    path = tmp_path / "state.lock"
    first = FileLock(path, timeout=0.1)
    second = FileLock(path, timeout=0.01)
    with first:
        with pytest.raises(LockTimeoutError):
            second.acquire()
    with second:
        assert second.acquired
    assert mode(path) == 0o600


def test_data_store_secret_lkg_and_result_files_are_private(tmp_path: Path) -> None:
    store = DataStore(tmp_path / "data")
    secret_path = store.write_secret("sources/subscription", URI)
    assert mode(secret_path) == 0o600
    assert store.read_secret("sources/subscription").decode() == URI
    with pytest.raises(StorageError):
        store.write_secret("../escape", "bad")

    entry = EntryRecord(
        entry_id="entry_primary",
        source_id="src_main",
        name="Primary",
        kind=EntryKind.VLESS_URI,
        mode=CheckMode.CONNECTION,
        payload=URI,
        generation="gen_one",
        transport="raw",
        security="reality",
    )
    generation = SourceGeneration(
        source_id="src_main", generation="gen_one", entries=[entry]
    )
    generation_path = store.save_source_generation(generation)
    assert mode(generation_path) == 0o600
    restored = store.load_lkg("src_main")
    assert restored is not None
    assert restored.entries[0].payload == URI
    assert restored.generation == "gen_one"

    result_path = store.save_result(
        {"check_id": "check_primary", "generation": "gen_one", "state": "unknown"}
    )
    assert mode(result_path) == 0o600
    assert store.load_result("check_primary")["generation"] == "gen_one"


def test_atomic_write_replaces_complete_value(tmp_path: Path) -> None:
    path = tmp_path / "atomic.txt"
    atomic_write_text(path, "first")
    atomic_write_text(path, "second")
    assert path.read_text() == "second"
    assert not list(tmp_path.glob(".atomic.txt.*.tmp"))


def test_identity_rotation_is_stable_and_ambiguous_duplicates_are_not_applied() -> None:
    first_entries = import_content(URI, source_id="src_main")
    registry = IdentityRegistry()
    initial = registry.reconcile("src_main", first_entries)
    assert initial.ok
    initial_id = initial.entry_id_for("candidate_00001")

    rotated = URI.replace(UUID, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
    rotation = registry.reconcile("src_main", import_content(rotated, source_id="src_main"))
    assert rotation.ok
    assert rotation.entry_id_for("candidate_00001") == initial_id

    empty_registry = IdentityRegistry()
    duplicates = import_content(URI + "\n" + URI, source_id="src_duplicates")
    conflict = empty_registry.reconcile("src_duplicates", duplicates)
    assert conflict.requires_manual_reconciliation
    assert "src_duplicates" not in empty_registry.sources


def test_identity_registry_prunes_only_unmatchable_inactive_rows() -> None:
    registry = IdentityRegistry.from_model(
        IdentityRegistryModel(
            sources={
                "src": [
                    IdentityBindingModel(entry_id="entry_empty", active=False),
                    IdentityBindingModel(
                        entry_id="entry_historical", name_key="old", active=False
                    ),
                    IdentityBindingModel(entry_id="entry_active", active=True),
                ]
            }
        )
    )

    assert registry.prune_unmatchable_inactive() == 1
    assert [item.entry_id for item in registry.sources["src"]] == [
        "entry_historical",
        "entry_active",
    ]


def test_check_id_ignores_generation_and_is_mode_sensitive() -> None:
    first = stable_check_id("entry_primary", "connection", "set_default", "route_one")
    again = stable_check_id(
        "entry_primary", CheckMode.CONNECTION, "set_default", "route_one"
    )
    profile = stable_check_id("entry_primary", "profile", "set_default", "route_one")
    other_selection = stable_check_id(
        "entry_primary", "connection", "set_default", "route_two"
    )
    assert first == again
    assert first != profile
    assert first != other_selection
    assert len(first.removeprefix("check_")) == 64
