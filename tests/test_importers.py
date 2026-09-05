from __future__ import annotations

import base64
import json

import pytest

from xray_e2e_prober.importers import (
    InvalidEntryError,
    UnknownSourceFormatError,
    UnsupportedEntryError,
    detect_format,
    effective_connection_outbound,
    import_content,
    parse_vless_uri,
    safe_entry_display,
    validate_xray_profile,
)
from xray_e2e_prober.models import CheckMode, EntryKind, SourceFormat


UUID = "11111111-2222-4333-8444-555555555555"


def reality_uri(name: str = "Moscow") -> str:
    return (
        f"vless://{UUID}@edge.example:443?type=tcp&security=reality"
        "&encryption=none&sni=www.example.com&fp=chrome&pbk=PUBLIC_KEY"
        f"&sid=0123456789abcdef&spx=%2F#{name}"
    )


def tls_profile(name: str = "Profile") -> dict:
    return {
        "name": name,
        "inbounds": [{"tag": "original-in", "protocol": "socks", "settings": {}}],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": "edge.example",
                            "port": 443,
                            "users": [{"id": UUID, "encryption": "none"}],
                        }
                    ],
                    "futureSetting": {"must": "survive"},
                },
                "streamSettings": {
                    "network": "xhttp",
                    "security": "tls",
                    "tlsSettings": {"serverName": "www.example.com"},
                    "xhttpSettings": {"path": "/probe", "mode": "auto"},
                },
                "futureOutboundField": [1, 2, 3],
            },
            {"tag": "direct", "protocol": "freedom", "settings": {}},
        ],
        "routing": {"rules": [{"type": "field", "outboundTag": "proxy"}]},
        "futureTopLevel": {"is": "preserved"},
    }


def test_parse_reality_raw_and_build_effective_outbound() -> None:
    uri = reality_uri()
    parsed = parse_vless_uri(uri)
    assert parsed.transport == "raw"
    assert parsed.security == "reality"
    assert parsed.name == "Moscow"

    outbound = effective_connection_outbound(uri)
    assert outbound["protocol"] == "vless"
    assert outbound["settings"]["vnext"][0]["users"][0]["id"] == UUID
    assert outbound["streamSettings"]["network"] == "raw"
    assert outbound["streamSettings"]["realitySettings"]["publicKey"] == "PUBLIC_KEY"

    display = safe_entry_display(uri)
    assert "Moscow" in display
    assert UUID not in display
    assert "edge.example" not in display
    assert "PUBLIC_KEY" not in display


def test_source_names_cannot_echo_candidate_secrets() -> None:
    imported = import_content(
        reality_uri(f"node {UUID} PUBLIC_KEY edge.example"), source_id="src_main"
    )[0]
    for public_value in (imported.name, imported.safe_display):
        assert UUID not in public_value
        assert "PUBLIC_KEY" not in public_value
        assert "edge.example" not in public_value

    profile = tls_profile(f"node {UUID} JSON_SECRET_KEY")
    profile["outbounds"][0]["streamSettings"]["tlsSettings"][
        "privateKey"
    ] = "JSON_SECRET_KEY"
    imported_profile = import_content(json.dumps(profile), source_id="src_json")[0]
    assert UUID not in imported_profile.name
    assert "JSON_SECRET_KEY" not in imported_profile.name


def test_short_reality_id_in_source_name_fails_closed() -> None:
    uri = reality_uri("node 01").replace("sid=0123456789abcdef", "sid=01")
    imported = import_content(uri, source_id="src_main")[0]

    assert imported.name == "unnamed"
    assert "01" not in imported.safe_display


def test_excessive_profile_secret_set_uses_opaque_display_name() -> None:
    profile = tls_profile("ordinary-looking name")
    profile["credentialExtensions"] = {
        f"field-{index}": f"private-value-{index}" for index in range(300)
    }

    imported = import_content(json.dumps(profile), source_id="src_json")[0]

    assert imported.name == "unnamed"


def test_json_profile_is_stored_once_and_raw_tags_are_not_public() -> None:
    imported = import_content(json.dumps(tls_profile()), source_id="src_json")[0]
    assert imported.payload is None
    record = imported.to_entry_record("entry_one", "generation_one")
    assert record.payload is None
    assert record.profile is not None
    public = record.public_dict()
    assert "outbound_tag" not in public
    assert "inbound_tag" not in public


def test_reconciliation_fingerprint_excludes_credentials_paths_and_profile_tags() -> None:
    original = tls_profile()
    first = import_content(json.dumps(original), source_id="src_json")[0]
    changed_private = tls_profile()
    changed_private["inbounds"][0]["tag"] = "private-inbound-two"
    changed_private["outbounds"][0]["tag"] = "private-outbound-two"
    changed_private["outbounds"][0]["settings"]["vnext"][0]["users"][0][
        "id"
    ] = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    changed_private["outbounds"][0]["streamSettings"]["xhttpSettings"][
        "path"
    ] = "/credential-like-private-path"
    second = import_content(json.dumps(changed_private), source_id="src_json")[0]

    assert first.connection_fingerprint == second.connection_fingerprint

    changed_endpoint = tls_profile()
    changed_endpoint["outbounds"][0]["settings"]["vnext"][0][
        "address"
    ] = "other-edge.example"
    third = import_content(json.dumps(changed_endpoint), source_id="src_json")[0]
    assert first.connection_fingerprint != third.connection_fingerprint


def test_xhttp_tls_and_base64_auto_detection() -> None:
    uri = (
        f"vless://{UUID}@edge.example:443?type=xhttp&security=tls"
        "&sni=www.example.com&fp=chrome&path=%2Fapi&host=cdn.example"
        "&mode=packet-up&extra=%7B%22scMaxEachPostBytes%22%3A1000%7D#XHTTP"
    )
    encoded = base64.urlsafe_b64encode((uri + "\n").encode()).decode().rstrip("=")
    assert detect_format(encoded) is SourceFormat.VLESS_BASE64
    entries = import_content(encoded, source_id="src_main")
    assert len(entries) == 1
    assert entries[0].mode is CheckMode.CONNECTION
    outbound = effective_connection_outbound(entries[0])
    xhttp = outbound["streamSettings"]["xhttpSettings"]
    assert xhttp["path"] == "/api"
    assert xhttp["mode"] == "packet-up"
    assert xhttp["extra"] == {"scMaxEachPostBytes": 1000}


def test_removed_tls_allow_insecure_is_never_emitted() -> None:
    base = f"vless://{UUID}@edge.example:443?type=raw&security=tls&sni=edge.example"
    outbound = effective_connection_outbound(base + "&allowInsecure=false")
    assert "allowInsecure" not in outbound["streamSettings"]["tlsSettings"]

    with pytest.raises(UnsupportedEntryError, match="certificate verification"):
        effective_connection_outbound(base + "&allowInsecure=true")
    with pytest.raises(InvalidEntryError, match="TLS verification setting"):
        effective_connection_outbound(base + "&allowInsecure=false&insecure=0")

    profile = tls_profile()
    profile["outbounds"][0]["streamSettings"]["tlsSettings"]["allowInsecure"] = False
    with pytest.raises(UnsupportedEntryError, match="removed TLS allowInsecure"):
        validate_xray_profile(profile)


def test_unknown_semantic_parameter_is_rejected_without_secret_echo() -> None:
    uri = reality_uri().replace(
        "#Moscow", "&unknownConnectionToken=DO_NOT_PRINT#Moscow"
    )
    with pytest.raises(UnsupportedEntryError) as raised:
        parse_vless_uri(uri)
    message = str(raised.value)
    assert "DO_NOT_PRINT" not in message
    assert "unknownConnectionToken" not in message
    assert UUID not in message


def test_duplicate_parameter_and_html_are_rejected() -> None:
    duplicate = reality_uri().replace(
        "#Moscow", "&SECRET_PARAMETER=x&SECRET_PARAMETER=y#Moscow"
    )
    with pytest.raises(InvalidEntryError) as raised:
        parse_vless_uri(duplicate)
    assert "SECRET_PARAMETER" not in str(raised.value)
    with pytest.raises(UnknownSourceFormatError):
        import_content("<!doctype html><title>login</title>")


def test_json_object_and_array_are_auto_detected_and_preserved() -> None:
    profile = tls_profile()
    original = json.loads(json.dumps(profile))
    single = import_content(json.dumps(profile), source_id="src_json")
    assert len(single) == 1
    assert single[0].kind is EntryKind.XRAY_JSON
    assert single[0].mode is CheckMode.PROFILE
    assert single[0].profile == original
    assert single[0].inbound_tag == "original-in"

    many = import_content(json.dumps([profile, tls_profile("Second")]))
    assert len(many) == 2
    assert detect_format(json.dumps([profile])) is SourceFormat.XRAY_JSON_ARRAY

    copied = validate_xray_profile(profile)
    copied["futureTopLevel"]["is"] = "changed"
    assert profile["futureTopLevel"]["is"] == "preserved"


def test_profile_rejects_unsupported_proxy_protocol() -> None:
    profile = tls_profile()
    profile["outbounds"].append({"tag": "trojan", "protocol": "trojan", "settings": {}})
    with pytest.raises(UnsupportedEntryError):
        import_content(json.dumps(profile))


def test_effective_profile_outbound_is_unambiguous_and_deep_copied() -> None:
    profile = tls_profile()
    selected = effective_connection_outbound(profile, outbound_tag="proxy", effective_tag="selected")
    assert selected["tag"] == "selected"
    selected["settings"]["futureSetting"]["must"] = "changed"
    assert profile["outbounds"][0]["settings"]["futureSetting"]["must"] == "survive"


def test_json_duplicate_keys_are_rejected() -> None:
    duplicate = '{"outbounds": [], "outbounds": []}'
    with pytest.raises(InvalidEntryError):
        import_content(duplicate, SourceFormat.XRAY_JSON)
