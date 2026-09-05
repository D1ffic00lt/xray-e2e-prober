from pathlib import Path

import pytest

import xray_e2e_prober.storage as storage_module
from xray_e2e_prober.config import load_config, save_config
from xray_e2e_prober.models import (
    AppConfig,
    EntryRecord,
    IdentityBindingModel,
    IdentityRegistryModel,
    SourceGeneration,
)
from xray_e2e_prober.storage import (
    SOURCE_GENERATION_RETENTION,
    SOURCE_STATE_RETENTION,
    DataStore,
    StorageError,
)


def _generation(generation_id: str, *, name: str) -> SourceGeneration:
    return SourceGeneration(
        source_id="src",
        generation=generation_id,
        entries=[
            EntryRecord(
                entry_id="entry",
                source_id="src",
                name=name,
                mode="connection",
                generation=generation_id,
                payload=f"vless://private-{name}",
            )
        ],
    )


def _registry(name: str) -> IdentityRegistryModel:
    return IdentityRegistryModel(
        sources={
            "src": [
                IdentityBindingModel(
                    entry_id="entry",
                    name_key=name,
                    connection_fingerprint=(name * 64)[:64],
                )
            ]
        }
    )


@pytest.mark.parametrize("crash_stage", ["generation", "state", "pointer"])
def test_source_state_crash_before_pointer_keeps_old_generation_and_registry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, crash_stage: str
) -> None:
    store = DataStore(tmp_path)
    store.publish_source_state(_generation("gen_old", name="a"), _registry("a"))
    original_write = storage_module.atomic_write_json

    def fail_commit(path, value, **kwargs):
        candidate = Path(path)
        stage = (
            "pointer"
            if candidate.name == "current.json"
            else "state"
            if candidate.parent.name == "states"
            else "generation"
            if candidate.name == "gen_new.json"
            else "other"
        )
        if stage == crash_stage:
            raise StorageError("injected crash before commit point")
        return original_write(path, value, **kwargs)

    monkeypatch.setattr(storage_module, "atomic_write_json", fail_commit)
    with pytest.raises(StorageError, match="injected"):
        store.publish_source_state(_generation("gen_new", name="b"), _registry("b"))

    restarted = DataStore(tmp_path)
    assert restarted.load_lkg("src").generation == "gen_old"  # type: ignore[union-attr]
    assert restarted.load_identity_registry().sources["src"][0].name_key == "a"


def test_source_state_pointer_is_authoritative_when_post_commit_maintenance_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = DataStore(tmp_path)
    store.publish_source_state(_generation("gen_old", name="a"), _registry("a"))

    def fail_maintenance(*_args, **_kwargs):
        raise StorageError("injected post-commit maintenance failure")

    monkeypatch.setattr(store, "save_identity_registry", fail_maintenance)
    monkeypatch.setattr(store, "_prune_source_history", fail_maintenance)
    store.publish_source_state(_generation("gen_new", name="b"), _registry("b"))

    restarted = DataStore(tmp_path)
    assert restarted.load_lkg("src").generation == "gen_new"  # type: ignore[union-attr]
    assert restarted.load_identity_registry().sources["src"][0].name_key == "b"


def test_source_history_retention_is_bounded_and_keeps_current(tmp_path: Path) -> None:
    store = DataStore(tmp_path)
    for index in range(10):
        name = chr(ord("a") + index)
        store.publish_source_state(
            _generation(f"gen_{index}", name=name), _registry(name)
        )

    source_dir = tmp_path / "lkg" / "src"
    assert len(list((source_dir / "states").glob("*.json"))) <= SOURCE_STATE_RETENTION
    assert (
        len(list((source_dir / "generations").glob("*.json")))
        <= SOURCE_GENERATION_RETENTION
    )
    assert store.load_lkg("src").generation == "gen_9"  # type: ignore[union-attr]


def test_prepared_config_replace_is_rolled_back_after_restart(tmp_path: Path) -> None:
    store = DataStore(tmp_path)
    old = AppConfig(instance_id="old")
    candidate = AppConfig(instance_id="candidate")
    save_config(old, store.config_path)
    secret_name = "src-cccccccccccccccccccccccccccccccc-location"

    store.begin_config_replace(store.config_path, secret_names=[secret_name])
    transaction_secret = store.write_new_secret(secret_name, "candidate-secret")
    save_config(candidate, store.config_path)
    assert DataStore(tmp_path).recover_config_replace(store.config_path) is True
    assert load_config(store.config_path).instance_id == "old"
    assert not store.config_transaction_path.exists()
    assert not transaction_secret.exists()


def test_committed_config_replace_survives_leftover_backup(tmp_path: Path) -> None:
    store = DataStore(tmp_path)
    save_config(AppConfig(instance_id="old"), store.config_path)
    store.begin_config_replace(store.config_path)
    save_config(AppConfig(instance_id="candidate"), store.config_path)
    store.commit_config_replace(store.config_path)

    assert DataStore(tmp_path).recover_config_replace(store.config_path) is False
    assert load_config(store.config_path).instance_id == "candidate"


def test_config_recovery_removes_uncommitted_first_config(tmp_path: Path) -> None:
    store = DataStore(tmp_path)
    store.begin_config_replace(store.config_path)
    save_config(AppConfig(instance_id="candidate"), store.config_path)

    assert store.recover_config_replace(store.config_path) is True
    assert not store.config_path.exists()


def test_prunes_obsolete_results_and_abandoned_transaction_secrets(
    tmp_path: Path,
) -> None:
    store = DataStore(tmp_path)
    store.save_result({"check_id": "current", "state": "unknown"})
    store.save_result({"check_id": "obsolete", "state": "unknown"})
    kept_secret = store.write_secret("src-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-location", "one")
    removed_secret = store.write_secret(
        "src-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-header-1", "two"
    )
    ordinary_secret = store.write_secret("operator-managed", "three")

    assert store.prune_results({"current"}) == 1
    assert store.load_result("current") is not None
    assert store.load_result("obsolete") is None
    assert store.prune_transaction_secrets({kept_secret}) == 1
    assert kept_secret.exists()
    assert not removed_secret.exists()
    assert ordinary_secret.exists()
