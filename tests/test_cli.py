import hashlib
import json
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from xray_e2e_prober.cli import app
from xray_e2e_prober.config import load_config, save_config
from xray_e2e_prober.identity import IdentityRegistry
from xray_e2e_prober.importers import import_content
from xray_e2e_prober.inventory import compile_inventory
from xray_e2e_prober.models import (
    AppConfig,
    IdentityBindingModel,
    IdentityRegistryModel,
    SourceGeneration,
)
from xray_e2e_prober.storage import DataStore


VALID_VLESS = (
    "vless://550e8400-e29b-41d4-a716-446655440000@example.test:443"
    "?encryption=none&security=tls&type=tcp&sni=example.test#safe-name\n"
)


def test_cli_exposes_the_required_command_tree() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in (
        "setup",
        "serve",
        "subscription",
        "entries",
        "targets",
        "assignments",
        "egress",
        "check",
        "status",
        "config",
    ):
        assert command in result.stdout


def test_setup_wizard_imports_without_manual_entry_configuration(tmp_path: Path) -> None:
    subscription = tmp_path / "subscription.txt"
    subscription.write_text(VALID_VLESS, encoding="utf-8")
    answers = iter(
        [
            "prober-test",  # instance ID
            "",  # use target preset
            "",  # confirm displayed preset URLs
            "",  # preset quorum
            "",  # no optional egress assertion
            "source-test",  # source ID
            "Local fixture",  # display name
            "file",  # source kind
            str(subscription),
            "",  # auto format
            "",  # refresh interval
            "",  # source timeout
            "",  # optional source tags
            "",  # reject empty source
            "",  # select all supported entries
            "",  # check interval
            "",  # request timeout
            "",  # Xray startup timeout
            "",  # runtime limit
            "",  # HTTP concurrency
            "",  # queue size
            "",  # max result age
            "",  # save confirmation
        ]
    )

    def answer(*_args, **kwargs):
        value = next(answers)
        return value or kwargs.get("default", "")

    runner = CliRunner()
    with patch("xray_e2e_prober.cli.terminal_prompt", side_effect=answer):
        result = runner.invoke(
            app,
            [
                "setup", "--data-dir", str(tmp_path),
                "--xray-binary", "/usr/bin/true",
            ],
        )

    assert result.exit_code == 0, result.output
    assert "550e8400" not in result.output
    config = load_config(tmp_path / "config.yaml")
    assert config.instance_id == "prober-test"
    assert config.sources[0].target_set_ids == ["internet-default"]
    generation = DataStore(tmp_path).load_lkg("source-test")
    assert generation is not None
    assert len(generation.entries) == 1
    assert generation.entries[0].mode.value == "connection"


def test_config_validate_json(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "schema_version: 1\ninstance_id: cli-test\nsources: []\ntarget_sets: []\n",
        encoding="utf-8",
    )
    result = CliRunner().invoke(
        app, ["config", "validate", str(config_path), "--json"]
    )
    assert result.exit_code == 0
    assert '"valid": true' in result.stdout
    assert '"instance_id": "cli-test"' in result.stdout


def test_config_export_omits_private_identity_keys(tmp_path: Path) -> None:
    save_config(
        AppConfig.model_validate({
            "instance_id": "export-test",
            "sources": [{
                "source_id": "src_main",
                "name": "source",
                "kind": "file",
                "location": "/private/source",
            }],
        }),
        tmp_path / "config.yaml",
    )
    DataStore(tmp_path).save_identity_registry(
        IdentityRegistryModel(
            sources={
                "src_main": [
                    IdentityBindingModel(
                        entry_id="entry_one",
                        external_id="EXTERNAL_SECRET",
                        name_key="NAME_SECRET",
                        connection_fingerprint="FINGERPRINT_SECRET",
                    )
                ]
            }
        )
    )

    result = CliRunner().invoke(
        app, ["config", "export", "--data-dir", str(tmp_path), "--json"]
    )
    assert result.exit_code == 0, result.output
    assert "EXTERNAL_SECRET" not in result.stdout
    assert "NAME_SECRET" not in result.stdout
    assert "FINGERPRINT_SECRET" not in result.stdout
    binding = json.loads(result.stdout)["identity_registry"]["sources"]["src_main"][0]
    assert binding == {"entry_id": "entry_one", "active": True}


def test_config_export_round_trips_ids_and_includes_lkg_inventory(tmp_path: Path) -> None:
    source_id = "src_main"
    candidate = import_content(VALID_VLESS, source_id=source_id)[0]
    registry = IdentityRegistry()
    reconciled = registry.reconcile(source_id, [candidate])
    entry_id = reconciled.entry_id_for(candidate.candidate_id)
    generation = SourceGeneration(
        source_id=source_id,
        generation="gen_one",
        entries=[candidate.to_entry_record(entry_id, "gen_one")],
    )
    config = AppConfig.model_validate({
        "instance_id": "edge_a",
        "sources": [{
            "source_id": source_id,
            "name": "source",
            "kind": "file",
            "location": "/private/subscription-with-credentials",
            "target_set_ids": ["web"],
        }],
        "target_sets": [{
            "target_set_id": "web",
            "name": "web",
            "quorum": 1,
            "targets": [{
                "target_id": "homepage",
                "name": "homepage",
                "url": "https://example.test/",
            }],
        }],
        "assignments": [{
            "assignment_id": "selected_route",
            "entry_id": entry_id,
            "mode": "connection",
            "target_set_ids": ["web"],
            "outbound_tag": "RAW-PRIVATE-PROFILE-TAG",
            "inbound_tag": "RAW-PRIVATE-INBOUND-TAG",
        }],
    })
    store = DataStore(tmp_path)
    save_config(config, tmp_path / "config.yaml")
    credential_hash = hashlib.sha256(
        "550e8400-e29b-41d4-a716-446655440000".encode()
    ).hexdigest()
    registry.sources[source_id][0].connection_fingerprint = credential_hash
    store.save_identity_registry(registry.to_model())
    store.save_source_generation(generation)

    result = CliRunner().invoke(
        app, ["config", "export", "--data-dir", str(tmp_path), "--json"]
    )
    assert result.exit_code == 0, result.output
    for private in (
        "550e8400-e29b-41d4-a716-446655440000",
        "RAW-PRIVATE-PROFILE-TAG",
        "RAW-PRIVATE-INBOUND-TAG",
        "/private/subscription-with-credentials",
    ):
        assert private not in result.stdout
    assert credential_hash not in result.stdout

    bundle = json.loads(result.stdout)
    assert bundle["export_version"] == 2
    expected = bundle["expected_inventory"]
    assert expected["instance_id"] == "edge_a"
    assert len(expected["checks"]) == 1
    expected_check_id = expected["checks"][0]["check_id"]
    binding = bundle["identity_registry"]["sources"][source_id][0]
    assert binding["entry_id"] == entry_id
    assert len(binding["connection_fingerprint"]) == 64
    assert bundle["config"]["assignments"][0]["outbound_tag"] is None
    assert bundle["config"]["assignments"][0]["inbound_tag"] is None
    assert bundle["config"]["assignments"][0]["selection_id"] == "selected_route"

    # A second observation point restores only the public mapping, supplies
    # its own credentials, and still obtains identical entry/check IDs.
    restored = IdentityRegistry.from_model(bundle["identity_registry"])
    rotated = VALID_VLESS.replace(
        "550e8400-e29b-41d4-a716-446655440000",
        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    )
    next_candidate = import_content(rotated, source_id=source_id)[0]
    next_reconciliation = restored.reconcile(source_id, [next_candidate])
    assert next_reconciliation.entry_id_for(next_candidate.candidate_id) == entry_id
    next_generation = SourceGeneration(
        source_id=source_id,
        generation="gen_two",
        entries=[next_candidate.to_entry_record(entry_id, "gen_two")],
    )
    next_config_value = dict(bundle["config"])
    next_config_value["instance_id"] = "edge_b"
    next_config = AppConfig.model_validate(next_config_value)
    next_inventory = compile_inventory(next_config, {source_id: next_generation})
    assert list(next_inventory) == [expected_check_id]
