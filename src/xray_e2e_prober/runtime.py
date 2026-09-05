"""Safe construction and lifecycle management for Xray client runtimes.

The module deliberately treats Xray configurations as dictionaries.  Xray's
configuration surface is much larger than the application's own schema and a
round trip through a partial model could silently discard meaningful fields.
"""

from __future__ import annotations

import asyncio
import copy
import ipaddress
import json
import os
import re
import socket
import tempfile
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlsplit


PROBER_INBOUND_TAG: Final = "xray-e2e-prober-socks"
_SUPPORTED_OUTBOUNDS: Final = frozenset({"vless", "freedom", "blackhole", "dns"})
_ADAPTABLE_INBOUNDS: Final = frozenset({"socks", "http"})
_UNSAFE_TOP_LEVEL: Final = frozenset(
    {"api", "reverse", "metrics", "env", "browserForwarder"}
)
_UNREPRODUCIBLE_RULE_FIELDS: Final = frozenset(
    {"source", "sourcePort", "user", "attrs", "process", "processPath"}
)
_EXTERNAL_FILE_KEYS: Final = frozenset(
    {
        "certificatefile",
        "keyfile",
        "masterkeylog",
        "masterkeylogfile",
    }
)
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_UUID = re.compile(
    r"(?i)(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f])"
)
_URL_CREDENTIALS = re.compile(r"(?i)(://[^\s/:]+:)[^\s/@]+(@)")
_QUERY_SECRET = re.compile(
    r"(?i)([?&](?:token|key|secret|auth|password|uuid)=)[^&#\s]+"
)
_JSON_SECRET = re.compile(
    r"(?i)([\"'](?:id|uuid|password|token|auth|authorization|apikey|privatekey|"
    r"publickey|pbk|shortid|sid|spiderx|email)[\"']\s*[:=]\s*[\"'])"
    r"[^\"']*([\"'])"
)
_SHORT_SECRET_KEYS: Final = frozenset(
    {
        "id",
        "uuid",
        "password",
        "token",
        "auth",
        "authorization",
        "apikey",
        "privatekey",
        "publickey",
        "pbk",
        "shortid",
        "sid",
        "spiderx",
        "email",
    }
)
_MAX_REDACTION_LITERALS: Final = 256
_MAX_REDACTION_NODES: Final = 4096
_OPAQUE_DIAGNOSTIC_SENTINEL: Final = "\x00xray-e2e-prober-redact-all\x00"


class EffectiveConfigError(ValueError):
    """The requested effective configuration cannot be reproduced safely."""

    def __init__(self, message: str, *, reason: str = "unsupported") -> None:
        super().__init__(message)
        self.reason = reason


class XrayRuntimeError(RuntimeError):
    """Base error with a stable public reason and already-sanitized detail."""

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


class XrayConfigError(XrayRuntimeError):
    def __init__(self, message: str) -> None:
        super().__init__(message, reason="config_invalid")


class XrayStartError(XrayRuntimeError):
    def __init__(self, message: str) -> None:
        super().__init__(message, reason="runtime_start")


class XrayExitedError(XrayRuntimeError):
    def __init__(self, message: str) -> None:
        super().__init__(message, reason="runtime_exit")


def _as_mapping(value: Any, *, what: str) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return copy.deepcopy(dict(value))
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        dumped = dump(mode="python", round_trip=True)
        if isinstance(dumped, Mapping):
            return copy.deepcopy(dict(dumped))
    raise EffectiveConfigError(f"{what} must be a mapping", reason="config_invalid")


def _field(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def _profile_from(value: Any, *, vless_tag: str | None = None) -> dict[str, Any]:
    """Extract a lossless Xray JSON object from a dict or an EntryRecord-like value."""

    candidate = _field(value, "profile")
    if candidate is None:
        candidate = _field(value, "payload")
    if candidate is None and isinstance(value, Mapping):
        candidate = value
    if isinstance(candidate, str):
        if candidate.casefold().startswith("vless://"):
            # Local import avoids a module cycle: importers depend on models but
            # the runtime otherwise remains independent of the import pipeline.
            from .importers import SourceImportError, vless_uri_to_outbound

            try:
                outbound = vless_uri_to_outbound(
                    candidate,
                    tag=vless_tag or _field(value, "outbound_tag") or "probe-selected",
                )
            except SourceImportError as exc:
                raise EffectiveConfigError(
                    str(exc), reason=getattr(exc, "reason", "config_invalid")
                ) from exc
            candidate = {"outbounds": [outbound]}
        else:
            try:
                candidate = json.loads(candidate)
            except (TypeError, json.JSONDecodeError) as exc:
                raise EffectiveConfigError(
                    "entry does not contain an Xray JSON profile", reason="config_invalid"
                ) from exc
    profile = _as_mapping(candidate, what="Xray profile")
    # An importer may provide one already-normalized outbound instead of a full
    # profile.  Wrapping it is lossless and useful for connection mode.
    if "outbounds" not in profile and isinstance(profile.get("protocol"), str):
        profile = {"outbounds": [profile]}
    return profile


def _valid_port(port: int) -> int:
    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
        raise EffectiveConfigError(
            "SOCKS port must be between 0 and 65535", reason="config_invalid"
        )
    return port


def _safe_socks_inbound(port: int, tag: str, sniffing: Any = None) -> dict[str, Any]:
    inbound: dict[str, Any] = {
        "tag": tag,
        "listen": "127.0.0.1",
        "port": _valid_port(port),
        "protocol": "socks",
        "settings": {"auth": "noauth", "udp": False},
    }
    if isinstance(sniffing, Mapping):
        inbound["sniffing"] = copy.deepcopy(dict(sniffing))
    return inbound


def _outbounds(
    profile: Mapping[str, Any], *, synthesize_missing_tags: bool = False
) -> list[dict[str, Any]]:
    raw = profile.get("outbounds")
    if not isinstance(raw, list) or not raw:
        raise EffectiveConfigError("profile has no outbounds", reason="config_invalid")
    result: list[dict[str, Any]] = []
    tags: set[str] = set()
    # Reserve every explicit tag before generating any connection-mode tags.
    # Otherwise an untagged outbound could take a name used by a later outbound.
    for index, item in enumerate(raw):
        outbound = _as_mapping(item, what=f"outbound {index}")
        if "tag" not in outbound:
            continue
        tag = outbound.get("tag")
        if not isinstance(tag, str) or not tag or tag in tags:
            raise EffectiveConfigError(
                "outbound tags must be non-empty and unique", reason="config_invalid"
            )
        tags.add(tag)
    for index, item in enumerate(raw):
        outbound = _as_mapping(item, what=f"outbound {index}")
        protocol = outbound.get("protocol")
        if protocol not in _SUPPORTED_OUTBOUNDS:
            raise EffectiveConfigError(f"unsupported outbound protocol at index {index}")
        if "tag" not in outbound and synthesize_missing_tags:
            base = f"xray-e2e-prober-outbound-{index}"
            tag = base
            suffix = 1
            while tag in tags:
                tag = f"{base}-{suffix}"
                suffix += 1
            outbound["tag"] = tag
            tags.add(tag)
        result.append(outbound)
    return result


def _select_outbound(
    outbounds: list[dict[str, Any]], requested_tag: str | None
) -> dict[str, Any]:
    if requested_tag:
        matches = [item for item in outbounds if item.get("tag") == requested_tag]
        if len(matches) != 1:
            raise EffectiveConfigError("selected outbound tag is missing", reason="config_invalid")
        selected = matches[0]
    else:
        candidates = [item for item in outbounds if item.get("protocol") == "vless"]
        if len(candidates) != 1:
            raise EffectiveConfigError("connection mode requires one selected VLESS outbound")
        selected = candidates[0]
    if selected.get("protocol") != "vless":
        raise EffectiveConfigError("connection mode supports a selected VLESS outbound only")
    return selected


def _dependency_tags(outbound: Mapping[str, Any]) -> set[str]:
    tags: set[str] = set()
    proxy_settings = outbound.get("proxySettings")
    if isinstance(proxy_settings, Mapping) and isinstance(proxy_settings.get("tag"), str):
        tags.add(proxy_settings["tag"])
    stream = outbound.get("streamSettings")
    if isinstance(stream, Mapping):
        sockopt = stream.get("sockopt")
        if isinstance(sockopt, Mapping) and isinstance(sockopt.get("dialerProxy"), str):
            tags.add(sockopt["dialerProxy"])
    return tags


def _connection_outbounds(
    outbounds: list[dict[str, Any]], selected_tag: str
) -> list[dict[str, Any]]:
    by_tag = {item["tag"]: item for item in outbounds}
    needed = {selected_tag}
    pending = [selected_tag]
    while pending:
        current = by_tag[pending.pop()]
        for dependency in _dependency_tags(current):
            if dependency not in by_tag:
                raise EffectiveConfigError(
                    "selected outbound has a missing chained dependency", reason="config_invalid"
                )
            if dependency not in needed:
                needed.add(dependency)
                pending.append(dependency)
    # Preserve original order: Xray configurations may rely on it elsewhere and
    # keeping the order also makes generated files predictable for inspection.
    return [item for item in outbounds if item["tag"] in needed]


def _managed_log() -> dict[str, Any]:
    # Never inherit access/error file paths or verbose output from an imported
    # profile. Runtime output is still drained, bounded, and sanitized.
    return {"loglevel": "none", "dnsLog": False}


def _is_host_local_endpoint(value: Any) -> bool:
    """Identify endpoints that depend on the Xray process host or local network."""

    if not isinstance(value, str):
        return False
    candidate = value.strip()
    if not candidate:
        return False
    lowered = candidate.casefold()
    if lowered in {"local", "localhost", "localhost.localdomain"}:
        return True
    if lowered.endswith((".localhost", ".local", ".localdomain")):
        return True
    if lowered.startswith(("/", "./", "../", "file:", "unix:")):
        return True
    try:
        direct_address = ipaddress.ip_address(candidate.split("%", 1)[0])
    except ValueError:
        pass
    else:
        return direct_address.is_multicast or not direct_address.is_global
    try:
        parsed = urlsplit(candidate if "://" in candidate else f"//{candidate}")
        if parsed.scheme.casefold().endswith("+local"):
            return True
        host = parsed.hostname
    except ValueError:
        return False
    if host is None:
        return False
    host = host.split("%", 1)[0]
    if host.casefold() in {"local", "localhost", "localhost.localdomain"}:
        return True
    if host.casefold().endswith((".localhost", ".local", ".localdomain")):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    # Private, loopback, link-local, unspecified, multicast, and reserved
    # addresses are all tied to the runtime's network environment.
    return address.is_multicast or not address.is_global


def _reject_host_local_dependencies(config: Mapping[str, Any]) -> None:
    dns = config.get("dns")
    if isinstance(dns, Mapping):
        servers = dns.get("servers", [])
        if isinstance(servers, list):
            for server in servers:
                address = server.get("address") if isinstance(server, Mapping) else server
                if _is_host_local_endpoint(address):
                    raise EffectiveConfigError("profile requires a host-local DNS server")
        hosts = dns.get("hosts")
        if isinstance(hosts, Mapping):
            for answer in hosts.values():
                answers = answer if isinstance(answer, list) else [answer]
                if any(_is_host_local_endpoint(item) for item in answers):
                    raise EffectiveConfigError("profile DNS maps a name to a local address")

    outbounds = config.get("outbounds", [])
    if not isinstance(outbounds, list):
        return
    for outbound in outbounds:
        if not isinstance(outbound, Mapping):
            continue
        if "sendThrough" in outbound:
            raise EffectiveConfigError("profile outbound requires sendThrough")
        settings = outbound.get("settings")
        if not isinstance(settings, Mapping):
            continue
        vnext = settings.get("vnext", [])
        if isinstance(vnext, list):
            for server in vnext:
                address = server.get("address") if isinstance(server, Mapping) else None
                if _is_host_local_endpoint(address):
                    raise EffectiveConfigError("profile outbound requires a host-local server")
        if _is_host_local_endpoint(settings.get("redirect")):
            raise EffectiveConfigError("profile outbound redirects to a host-local endpoint")


def _reject_unsafe_features(config: Mapping[str, Any]) -> None:
    forbidden = sorted(key for key in _UNSAFE_TOP_LEVEL if key in config)
    if forbidden:
        raise EffectiveConfigError(
            f"unsupported externally-listening feature: {forbidden[0]}"
        )
    for outbound in config.get("outbounds", []):
        stream = outbound.get("streamSettings") if isinstance(outbound, Mapping) else None
        sockopt = stream.get("sockopt") if isinstance(stream, Mapping) else None
        if isinstance(sockopt, Mapping) and any(
            key in sockopt for key in ("interface", "mark", "tproxy")
        ):
            raise EffectiveConfigError(
                "profile requires interface, packet mark, or transparent-proxy state"
            )

    def reject_external_files(item: Any) -> None:
        if isinstance(item, Mapping):
            for key, value in item.items():
                if str(key).casefold() in _EXTERNAL_FILE_KEYS and value:
                    raise EffectiveConfigError(
                        "profile requires an external key or certificate file"
                    )
                reject_external_files(value)
        elif isinstance(item, list):
            for value in item:
                reject_external_files(value)
        elif isinstance(item, str) and item.casefold().startswith("ext:"):
            raise EffectiveConfigError("profile requires an external routing resource")

    reject_external_files(config)
    _reject_host_local_dependencies(config)


def _validate_profile_routing(profile: Mapping[str, Any]) -> None:
    routing = profile.get("routing")
    if routing is None:
        return
    if not isinstance(routing, Mapping):
        raise EffectiveConfigError("routing must be an object", reason="config_invalid")
    rules = routing.get("rules", [])
    if not isinstance(rules, list):
        raise EffectiveConfigError("routing.rules must be a list", reason="config_invalid")
    for rule in rules:
        if not isinstance(rule, Mapping):
            raise EffectiveConfigError("routing rule must be an object", reason="config_invalid")
        unsupported = sorted(_UNREPRODUCIBLE_RULE_FIELDS.intersection(rule))
        if unsupported:
            raise EffectiveConfigError(
                f"routing rule depends on unavailable field: {unsupported[0]}"
            )


def validate_imported_profile(entry_or_profile: Any) -> None:
    """Reject unsafe or unreproducible profile semantics before LKG publish."""

    profile = _profile_from(entry_or_profile)
    _reject_unsafe_features(profile)
    _validate_profile_routing(profile)
    _outbounds(profile)


def build_connection_config(
    entry_or_profile: Any,
    socks_port: int = 0,
    *,
    outbound_tag: str | None = None,
    inbound_tag: str = PROBER_INBOUND_TAG,
) -> dict[str, Any]:
    """Build an isolated config whose application traffic cannot use a fallback.

    The original routing is replaced with a catch-all rule for the managed SOCKS
    inbound.  Only the selected VLESS outbound and its explicit chaining
    dependencies remain, so a failed connection cannot become a direct success.
    """

    requested = outbound_tag or _field(entry_or_profile, "outbound_tag")
    profile = _profile_from(entry_or_profile, vless_tag=requested)
    _reject_unsafe_features(profile)
    all_outbounds = _outbounds(profile, synthesize_missing_tags=True)
    selected = _select_outbound(all_outbounds, requested)
    selected_tag = selected["tag"]

    effective = copy.deepcopy(profile)
    effective["log"] = _managed_log()
    effective["inbounds"] = [_safe_socks_inbound(socks_port, inbound_tag)]
    effective["outbounds"] = _connection_outbounds(all_outbounds, selected_tag)
    effective["routing"] = {
        "domainStrategy": "AsIs",
        "rules": [
            {
                "type": "field",
                "inboundTag": [inbound_tag],
                "outboundTag": selected_tag,
            }
        ],
    }
    # These profile-mode background systems can make unrelated network requests
    # and are not dependencies of a concrete outbound check.
    effective.pop("observatory", None)
    effective.pop("burstObservatory", None)
    validate_effective_config(effective, expected_port=socks_port, inbound_tag=inbound_tag)
    return effective


def _select_inbound(profile: Mapping[str, Any], requested_tag: str | None) -> dict[str, Any]:
    raw = profile.get("inbounds")
    if not isinstance(raw, list) or not raw:
        raise EffectiveConfigError(
            "profile mode requires a client inbound", reason="config_invalid"
        )
    inbounds = [
        inbound
        for item in raw
        if (inbound := _as_mapping(item, what="inbound")).get("protocol")
        in _ADAPTABLE_INBOUNDS
    ]
    if not inbounds:
        raise EffectiveConfigError("profile has no compatible SOCKS or HTTP client inbound")
    if requested_tag:
        matches = [item for item in inbounds if item.get("tag") == requested_tag]
        if len(matches) != 1:
            raise EffectiveConfigError("selected inbound tag is missing or ambiguous")
        return matches[0]
    if len(inbounds) != 1:
        raise EffectiveConfigError("profile mode requires an explicit inbound selection")
    return inbounds[0]


def _collision_free_inbound_tag(profile: Mapping[str, Any]) -> str:
    used: set[str] = set()
    raw_inbounds = profile.get("inbounds", [])
    if isinstance(raw_inbounds, list):
        for inbound in raw_inbounds:
            if isinstance(inbound, Mapping) and isinstance(inbound.get("tag"), str):
                used.add(inbound["tag"])
    routing = profile.get("routing")
    rules = routing.get("rules", []) if isinstance(routing, Mapping) else []
    if isinstance(rules, list):
        for rule in rules:
            if not isinstance(rule, Mapping):
                continue
            references = rule.get("inboundTag", [])
            if isinstance(references, str):
                used.add(references)
            elif isinstance(references, list):
                used.update(item for item in references if isinstance(item, str))

    candidate = PROBER_INBOUND_TAG
    suffix = 1
    while candidate in used:
        candidate = f"{PROBER_INBOUND_TAG}-{suffix}"
        suffix += 1
    return candidate


def build_profile_config(
    entry_or_profile: Any,
    socks_port: int = 0,
    *,
    inbound_tag: str | None = None,
) -> dict[str, Any]:
    """Adapt one profile inbound to a private SOCKS listener.

    Routing, DNS, outbound ordering, balancers, and observatory settings are
    preserved.  The selected inbound's tag and sniffing are preserved because
    both are inputs to routing decisions. An originally untagged inbound gets a
    managed tag that cannot collide with an existing routing selector.
    """

    profile = _profile_from(entry_or_profile)
    _reject_unsafe_features(profile)
    _validate_profile_routing(profile)
    normalized_outbounds = _outbounds(profile)
    requested = inbound_tag or _field(entry_or_profile, "inbound_tag")
    selected = _select_inbound(profile, requested)
    if "tag" in selected:
        selected_tag = selected.get("tag")
    else:
        selected_tag = _collision_free_inbound_tag(profile)
    if not isinstance(selected_tag, str) or not selected_tag:
        raise EffectiveConfigError("selected inbound tag is invalid", reason="config_invalid")

    effective = copy.deepcopy(profile)
    effective["log"] = _managed_log()
    effective["inbounds"] = [
        _safe_socks_inbound(socks_port, selected_tag, selected.get("sniffing"))
    ]
    effective["outbounds"] = normalized_outbounds
    validate_effective_config(effective, expected_port=socks_port, inbound_tag=selected_tag)
    return effective


def build_effective_config(
    entry_or_profile: Any,
    mode: str | Any,
    socks_port: int = 0,
    *,
    outbound_tag: str | None = None,
    inbound_tag: str | None = None,
) -> dict[str, Any]:
    """Dispatch to the connection/profile builder, accepting enum-like modes."""

    mode_value = getattr(mode, "value", mode)
    if mode_value == "connection":
        return build_connection_config(
            entry_or_profile,
            socks_port,
            outbound_tag=outbound_tag,
            inbound_tag=inbound_tag or PROBER_INBOUND_TAG,
        )
    if mode_value == "profile":
        return build_profile_config(entry_or_profile, socks_port, inbound_tag=inbound_tag)
    raise EffectiveConfigError("mode must be connection or profile", reason="config_invalid")


def _managed_inbound(config: Mapping[str, Any], inbound_tag: str | None = None) -> dict[str, Any]:
    raw = config.get("inbounds")
    if not isinstance(raw, list) or len(raw) != 1 or not isinstance(raw[0], Mapping):
        raise EffectiveConfigError("effective config must have exactly one inbound")
    inbound = dict(raw[0])
    if inbound_tag is not None and inbound.get("tag") != inbound_tag:
        raise EffectiveConfigError("managed inbound tag changed", reason="config_invalid")
    return inbound


def validate_effective_config(
    config: Mapping[str, Any],
    *,
    expected_port: int | None = None,
    inbound_tag: str | None = None,
) -> None:
    """Validate the safety boundary common to both effective modes."""

    if not isinstance(config, Mapping):
        raise EffectiveConfigError("effective config must be an object", reason="config_invalid")
    _reject_unsafe_features(config)
    inbound = _managed_inbound(config, inbound_tag)
    if inbound.get("listen") not in {"127.0.0.1", "::1"}:
        raise EffectiveConfigError("managed SOCKS inbound must listen on loopback")
    if inbound.get("protocol") != "socks":
        raise EffectiveConfigError("managed inbound must use SOCKS")
    port = inbound.get("port")
    _valid_port(port)
    if expected_port is not None and port != expected_port:
        raise EffectiveConfigError("managed SOCKS port changed", reason="config_invalid")
    settings = inbound.get("settings")
    if not isinstance(settings, Mapping):
        raise EffectiveConfigError("managed SOCKS settings are missing", reason="config_invalid")
    if settings.get("auth", "noauth") != "noauth" or settings.get("udp", False):
        raise EffectiveConfigError("managed SOCKS must be TCP-only without authentication")
    _outbounds(config)
    log = config.get("log")
    if not isinstance(log, Mapping) or log.get("loglevel") != "none":
        raise EffectiveConfigError("effective config must use managed logging")
    try:
        json.dumps(config, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise EffectiveConfigError(
            "effective config is not valid JSON", reason="config_invalid"
        ) from exc


def _replace_managed_port(config: Mapping[str, Any], port: int) -> dict[str, Any]:
    result = copy.deepcopy(dict(config))
    inbound = _managed_inbound(result)
    inbound["port"] = _valid_port(port)
    result["inbounds"] = [inbound]
    validate_effective_config(result, expected_port=port)
    return result


def sanitize_diagnostic(text: str, secret_literals: Sequence[str] = ()) -> str:
    """Return a single safe diagnostic suitable for API/CLI exposure."""

    # An unusually complex source-controlled profile can otherwise turn every
    # output line into thousands of regex substitutions. The collector emits a
    # private sentinel when its bounded budget is exceeded; fail closed instead
    # of attempting a partial redaction.
    if _OPAQUE_DIAGNOSTIC_SENTINEL in secret_literals:
        return "[diagnostic redacted]"

    result = _CONTROL_CHARACTERS.sub("?", text)
    # Xray may normalize the casing of values before echoing them. Treat
    # configured literals as case-insensitive exact byte-string equivalents.
    unique_literals: dict[str, str] = {}
    for secret in secret_literals:
        if secret:
            unique_literals.setdefault(secret.casefold(), secret)
    for secret in sorted(unique_literals.values(), key=len, reverse=True):
        result = re.sub(re.escape(secret), "[redacted]", result, flags=re.IGNORECASE)
    result = _UUID.sub("[redacted]", result)
    result = _URL_CREDENTIALS.sub(r"\1[redacted]\2", result)
    result = _QUERY_SECRET.sub(r"\1[redacted]", result)
    result = _JSON_SECRET.sub(r"\1[redacted]\2", result)
    return result


def _redaction_literals(config: Any) -> tuple[str, ...]:
    values: set[str] = set()
    stack: list[tuple[Any, str | None]] = [(config, None)]
    visited_containers: set[int] = set()
    visited_nodes = 0

    def remember(value: str) -> bool:
        if value:
            values.add(value)
        return len(values) <= _MAX_REDACTION_LITERALS

    while stack:
        item, key = stack.pop()
        visited_nodes += 1
        if visited_nodes > _MAX_REDACTION_NODES:
            return (_OPAQUE_DIAGNOSTIC_SENTINEL,)
        if isinstance(item, Mapping):
            identity = id(item)
            if identity in visited_containers:
                continue
            visited_containers.add(identity)
            for child_key, value in item.items():
                key_text = str(child_key)
                # Lossless profiles can contain source-controlled extension
                # keys. Xray's parser may echo an unknown key verbatim, so keys
                # need the same fail-closed treatment as their values.
                if not remember(key_text):
                    return (_OPAQUE_DIAGNOSTIC_SENTINEL,)
                for part in key_text.splitlines():
                    if not remember(part):
                        return (_OPAQUE_DIAGNOSTIC_SENTINEL,)
                stack.append((value, key_text))
        elif isinstance(item, list):
            identity = id(item)
            if identity in visited_containers:
                continue
            visited_containers.add(identity)
            stack.extend((value, key) for value in item)
        elif isinstance(item, str):
            normalized_key = re.sub(r"[^a-z0-9]", "", (key or "").casefold())
            minimum_length = 1 if normalized_key in _SHORT_SECRET_KEYS else 4
            if len(item) < minimum_length:
                continue
            # Xray errors may echo remote addresses, SNI, paths, or credentials;
            # all imported string values are safer to treat as sensitive. Very
            # short values are retained only for explicitly sensitive keys.
            if not remember(item):
                return (_OPAQUE_DIAGNOSTIC_SENTINEL,)
            for part in item.splitlines():
                if len(part) >= minimum_length and not remember(part):
                    return (_OPAQUE_DIAGNOSTIC_SENTINEL,)

    return tuple(values)


class _SanitizedBuffer:
    """Continuously drained output with bounded raw-line and retained buffers."""

    def __init__(
        self,
        limit_bytes: int,
        secret_literals: Sequence[str],
        *,
        pending_limit: int = 64 * 1024,
    ) -> None:
        self._limit = max(0, limit_bytes)
        self._pending_limit = max(1024, pending_limit)
        self._secrets = secret_literals
        self._chunks: deque[bytes] = deque()
        self._size = 0
        self._pending = bytearray()
        self._discarding_oversized_line = False

    def _append_safe(self, raw: bytes) -> None:
        if not self._limit:
            return
        decoded = raw.decode("utf-8", "replace")
        safe = sanitize_diagnostic(decoded, self._secrets).encode("utf-8", "replace")
        self._chunks.append(safe)
        self._size += len(safe)
        while self._size > self._limit and self._chunks:
            excess = self._size - self._limit
            first = self._chunks[0]
            if len(first) <= excess:
                self._chunks.popleft()
                self._size -= len(first)
            else:
                self._chunks[0] = first[excess:]
                self._size -= excess

    def feed(self, data: bytes) -> None:
        if self._discarding_oversized_line:
            newline = data.find(b"\n")
            if newline < 0:
                return
            data = data[newline + 1 :]
            self._discarding_oversized_line = False
        self._pending.extend(data)
        while True:
            newline = self._pending.find(b"\n")
            if newline < 0:
                break
            self._append_safe(bytes(self._pending[: newline + 1]))
            del self._pending[: newline + 1]
        if len(self._pending) > self._pending_limit:
            # Do not split an untrusted line: a credential could straddle the
            # split and evade literal redaction. Discard it as one safe marker.
            self._append_safe(b"[oversized diagnostic line discarded]\n")
            self._pending.clear()
            self._discarding_oversized_line = True

    def finish(self) -> None:
        if self._pending:
            self._append_safe(bytes(self._pending))
            self._pending.clear()

    def text(self) -> str:
        return b"".join(self._chunks).decode("utf-8", "replace")


async def _drain_stream(stream: Any, buffer: _SanitizedBuffer) -> None:
    if stream is None:
        return
    try:
        while True:
            chunk = await stream.read(4096)
            if not chunk:
                break
            buffer.feed(chunk)
    finally:
        buffer.finish()


def _public_process_detail(stdout: _SanitizedBuffer, stderr: _SanitizedBuffer) -> str:
    detail = stderr.text().strip() or stdout.text().strip()
    if len(detail) > 180:
        detail = "..." + detail[-177:]
    return detail


async def _terminate_process(process: Any, timeout: float) -> None:
    """Always reap a process: terminate, bounded wait, kill, final wait."""

    if process.returncode is not None:
        await process.wait()
        return
    try:
        process.terminate()
    except ProcessLookupError:
        pass
    try:
        await asyncio.wait_for(process.wait(), timeout=max(0.01, timeout))
        return
    except asyncio.TimeoutError:
        pass
    try:
        process.kill()
    except ProcessLookupError:
        pass
    await process.wait()


async def _wait_owned_task(
    task: asyncio.Future[Any],
) -> tuple[Any, asyncio.CancelledError | None]:
    """Wait for owned work to finish while remembering caller cancellation.

    A child task that cancels itself is deliberately re-raised via result(); it
    must not be mistaken for repeated cancellation of this awaiting caller.
    """

    cancellation: asyncio.CancelledError | None = None
    while True:
        try:
            return await asyncio.shield(task), cancellation
        except asyncio.CancelledError as exc:
            if task.done():
                task.result()
            cancellation = exc


async def _terminate_process_complete(process: Any, timeout: float) -> None:
    cleanup = asyncio.create_task(_terminate_process(process, timeout))
    _, cancellation = await _wait_owned_task(cleanup)
    if cancellation is not None:
        raise cancellation


def _reserve_port(port: int = 0) -> tuple[socket.socket, int]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        sock.bind(("127.0.0.1", port))
        sock.listen(1)
        return sock, int(sock.getsockname()[1])
    except BaseException:
        sock.close()
        raise


def allocate_local_socks_port() -> int:
    """Allocate a currently free loopback port.

    Prefer :meth:`XrayRuntimeManager.start` for actual runtime startup; it holds
    the reservation through the Xray config-test phase, narrowing the race.
    """

    sock, port = _reserve_port()
    sock.close()
    return port


def _write_private_json(path: Path, config: Mapping[str, Any]) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(config, output, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        try:
            path.unlink(missing_ok=True)
        finally:
            raise


async def _write_private_json_complete(
    path: Path, config: Mapping[str, Any]
) -> None:
    """Do not let cancellation race a background writer with path cleanup."""

    writer = asyncio.create_task(asyncio.to_thread(_write_private_json, path, config))
    _, cancellation = await _wait_owned_task(writer)
    if cancellation is not None:
        raise cancellation


@dataclass(frozen=True, slots=True)
class RuntimeDiagnostics:
    stdout: str
    stderr: str


@dataclass(eq=False)
class XrayRuntime:
    """One running Xray process and its private managed SOCKS listener."""

    process: Any
    socks_host: str
    socks_port: int
    config_path: Path
    _stdout: _SanitizedBuffer
    _stderr: _SanitizedBuffer
    _drainers: tuple[asyncio.Task[None], ...]
    _stop_timeout: float
    _on_stopped: Any = None

    def __post_init__(self) -> None:
        self._stop_lock = asyncio.Lock()
        self._stopped = False
        self._stop_task: asyncio.Task[None] | None = None

    @property
    def returncode(self) -> int | None:
        return self.process.returncode

    @property
    def alive(self) -> bool:
        return not self._stopped and self.process.returncode is None

    @property
    def proxy_url(self) -> str:
        return f"socks5://{self.socks_host}:{self.socks_port}"

    @property
    def diagnostics(self) -> RuntimeDiagnostics:
        return RuntimeDiagnostics(self._stdout.text(), self._stderr.text())

    def ensure_running(self) -> None:
        if not self.alive:
            raise XrayExitedError("Xray runtime exited")

    async def wait(self) -> int:
        code = await self.process.wait()
        await asyncio.gather(*self._drainers, return_exceptions=True)
        return code

    async def _stop_complete(self) -> None:
        try:
            await _terminate_process(self.process, self._stop_timeout)
        finally:
            await asyncio.gather(*self._drainers, return_exceptions=True)
            self.config_path.unlink(missing_ok=True)
            if self._on_stopped is not None:
                self._on_stopped(self)

    async def stop(self) -> None:
        async with self._stop_lock:
            cleanup = self._stop_task
            if cleanup is None:
                self._stopped = True
                cleanup = asyncio.create_task(
                    self._stop_complete(), name="xray-runtime-shutdown"
                )
                self._stop_task = cleanup

        _, cancellation = await _wait_owned_task(cleanup)
        if cancellation is not None:
            raise cancellation

    async def __aenter__(self) -> "XrayRuntime":
        self.ensure_running()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.stop()


class XrayRuntimeManager:
    """Validate, start, readiness-check, track, and stop official Xray children."""

    def __init__(
        self,
        binary: str | os.PathLike[str] = "xray",
        *,
        runtime_dir: str | os.PathLike[str] | None = None,
        startup_timeout: float = 10.0,
        config_test_timeout: float = 10.0,
        stop_timeout: float = 3.0,
        readiness_interval: float = 0.05,
        output_limit_bytes: int = 16 * 1024,
        run_args: Sequence[str] = ("run",),
        test_args: Sequence[str] = ("run", "-test"),
        config_flag: str = "-config",
    ) -> None:
        self.binary = os.fspath(binary)
        self.startup_timeout = startup_timeout
        self.config_test_timeout = config_test_timeout
        self.stop_timeout = stop_timeout
        self.readiness_interval = readiness_interval
        self.output_limit_bytes = output_limit_bytes
        self.run_args = tuple(run_args)
        self.test_args = tuple(test_args)
        self.config_flag = config_flag
        if runtime_dir is None:
            self.runtime_dir = Path(tempfile.mkdtemp(prefix="xray-e2e-prober-"))
            self._owns_runtime_dir = True
        else:
            self.runtime_dir = Path(runtime_dir)
            self.runtime_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            self._owns_runtime_dir = False
        try:
            self.runtime_dir.chmod(0o700)
        except OSError:
            # Validation at file creation still enforces mode 0600. Some mounted
            # filesystems do not implement chmod and are handled by deployment.
            pass
        self._runtimes: set[XrayRuntime] = set()
        self._start_lock = asyncio.Lock()
        self._closed = False
        self._close_task: asyncio.Task[None] | None = None

    @property
    def active(self) -> tuple[XrayRuntime, ...]:
        return tuple(runtime for runtime in self._runtimes if runtime.alive)

    async def _spawn(self, arguments: Sequence[str]) -> Any:
        return await asyncio.create_subprocess_exec(
            *arguments,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )

    async def _spawn_reap_on_cancel(self, arguments: Sequence[str]) -> Any:
        """Return a spawned process or reap it before propagating cancellation."""

        starter = asyncio.create_task(self._spawn(arguments))
        process, cancellation = await _wait_owned_task(starter)
        if cancellation is not None:
            try:
                await _terminate_process_complete(process, self.stop_timeout)
            except asyncio.CancelledError as exc:
                # Cleanup has completed; preserve the most recent cancellation.
                raise exc from cancellation
            raise cancellation
        return process

    def _buffers(
        self, secrets: Sequence[str]
    ) -> tuple[_SanitizedBuffer, _SanitizedBuffer]:
        return (
            _SanitizedBuffer(self.output_limit_bytes, secrets),
            _SanitizedBuffer(self.output_limit_bytes, secrets),
        )

    async def _run_config_test(self, path: Path, secrets: Sequence[str]) -> None:
        arguments = (self.binary, *self.test_args, self.config_flag, os.fspath(path))
        try:
            process = await self._spawn_reap_on_cancel(arguments)
        except (OSError, ValueError) as exc:
            raise XrayStartError("unable to start Xray config test") from exc
        stdout, stderr = self._buffers(secrets)
        drainers = (
            asyncio.create_task(_drain_stream(process.stdout, stdout)),
            asyncio.create_task(_drain_stream(process.stderr, stderr)),
        )
        try:
            code = await asyncio.wait_for(process.wait(), timeout=self.config_test_timeout)
        except asyncio.TimeoutError as exc:
            await _terminate_process_complete(process, self.stop_timeout)
            raise XrayStartError("Xray config test timed out") from exc
        except asyncio.CancelledError:
            await _terminate_process_complete(process, self.stop_timeout)
            raise
        finally:
            await asyncio.gather(*drainers, return_exceptions=True)
        if code != 0:
            detail = _public_process_detail(stdout, stderr)
            suffix = f": {detail}" if detail else ""
            raise XrayConfigError(f"Xray rejected effective config{suffix}")

    async def _wait_ready(
        self, runtime: XrayRuntime, *, timeout: float | None = None
    ) -> None:
        loop = asyncio.get_running_loop()
        readiness_timeout = self.startup_timeout if timeout is None else timeout
        if readiness_timeout <= 0:
            raise XrayStartError("Xray SOCKS readiness timed out")
        deadline = loop.time() + readiness_timeout
        while True:
            if runtime.process.returncode is not None:
                await asyncio.gather(*runtime._drainers, return_exceptions=True)
                detail = _public_process_detail(runtime._stdout, runtime._stderr)
                suffix = f": {detail}" if detail else ""
                raise XrayExitedError(f"Xray exited before SOCKS readiness{suffix}")
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise XrayStartError("Xray SOCKS readiness timed out")
            writer: asyncio.StreamWriter | None = None
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(runtime.socks_host, runtime.socks_port),
                    timeout=min(remaining, max(0.05, self.readiness_interval)),
                )
                writer.write(b"\x05\x01\x00")  # SOCKS5, one method, no authentication
                await writer.drain()
                reply = await asyncio.wait_for(
                    reader.readexactly(2),
                    timeout=min(remaining, max(0.05, self.readiness_interval)),
                )
                if reply == b"\x05\x00":
                    return
            except (OSError, asyncio.IncompleteReadError, asyncio.TimeoutError):
                pass
            finally:
                if writer is not None:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except OSError:
                        pass
            if runtime.process.returncode is None:
                await asyncio.sleep(min(self.readiness_interval, max(0.0, remaining)))

    async def ensure_ready(self, runtime: XrayRuntime, *, timeout: float = 1.0) -> None:
        """Boundedly verify that a retained runtime still answers SOCKS5."""

        runtime.ensure_running()
        await self._wait_ready(runtime, timeout=min(timeout, self.startup_timeout))

    async def start(
        self,
        effective_config: Mapping[str, Any],
        *,
        socks_port: int | None = None,
    ) -> XrayRuntime:
        """Start one validated runtime and return only after SOCKS is reachable."""

        if self._closed:
            raise XrayStartError("runtime manager is closed")
        async with self._start_lock:
            # close() marks the manager closed before waiting for this lock so
            # a start already queued behind another operation cannot slip past
            # shutdown and register a child afterwards.
            if self._closed:
                raise XrayStartError("runtime manager is closed")
            inbound = _managed_inbound(effective_config)
            configured_port = inbound.get("port", 0)
            requested_port = configured_port if socks_port is None else socks_port
            if not isinstance(requested_port, int) or isinstance(requested_port, bool):
                raise XrayConfigError("managed SOCKS port is invalid")
            try:
                reservation, allocated_port = _reserve_port(requested_port)
            except OSError as exc:
                raise XrayStartError("unable to reserve local SOCKS port") from exc
            config = _replace_managed_port(effective_config, allocated_port)
            secrets = _redaction_literals(config)
            path = self.runtime_dir / f"runtime-{os.urandom(12).hex()}.json"
            runtime: XrayRuntime | None = None
            try:
                await _write_private_json_complete(path, config)
                await self._run_config_test(path, secrets)
                if self._closed:
                    raise XrayStartError("runtime manager is closed")
                reservation.close()
                arguments = (self.binary, *self.run_args, self.config_flag, os.fspath(path))
                try:
                    process = await self._spawn_reap_on_cancel(arguments)
                except (OSError, ValueError) as exc:
                    raise XrayStartError("unable to start Xray runtime") from exc
                stdout, stderr = self._buffers(secrets)
                drainers = (
                    asyncio.create_task(_drain_stream(process.stdout, stdout)),
                    asyncio.create_task(_drain_stream(process.stderr, stderr)),
                )
                runtime = XrayRuntime(
                    process=process,
                    socks_host="127.0.0.1",
                    socks_port=allocated_port,
                    config_path=path,
                    _stdout=stdout,
                    _stderr=stderr,
                    _drainers=drainers,
                    _stop_timeout=self.stop_timeout,
                    _on_stopped=self._runtimes.discard,
                )
                try:
                    if self._closed:
                        raise XrayStartError("runtime manager is closed")
                    await self._wait_ready(runtime)
                    if self._closed:
                        raise XrayStartError("runtime manager is closed")
                except BaseException:
                    await runtime.stop()
                    raise
                self._runtimes.add(runtime)
                return runtime
            except BaseException:
                reservation.close()
                if runtime is None:
                    path.unlink(missing_ok=True)
                raise

    async def start_for(
        self,
        entry_or_profile: Any,
        mode: str | Any,
        *,
        outbound_tag: str | None = None,
        inbound_tag: str | None = None,
    ) -> XrayRuntime:
        config = build_effective_config(
            entry_or_profile,
            mode,
            0,
            outbound_tag=outbound_tag,
            inbound_tag=inbound_tag,
        )
        return await self.start(config)

    async def validate_for(
        self,
        entry_or_profile: Any,
        mode: str | Any,
        *,
        outbound_tag: str | None = None,
        inbound_tag: str | None = None,
    ) -> None:
        """Build and config-test an entry without reserving a port or starting Xray."""

        config = build_effective_config(
            entry_or_profile,
            mode,
            0,
            outbound_tag=outbound_tag,
            inbound_tag=inbound_tag,
        )
        if self._closed:
            raise XrayStartError("runtime manager is closed")
        async with self._start_lock:
            if self._closed:
                raise XrayStartError("runtime manager is closed")
            validate_effective_config(config, expected_port=0)
            secrets = _redaction_literals(config)
            path = self.runtime_dir / f"runtime-{os.urandom(12).hex()}.json"
            try:
                await _write_private_json_complete(path, config)
                await self._run_config_test(path, secrets)
            finally:
                path.unlink(missing_ok=True)

    async def stop_all(self) -> None:
        runtimes = tuple(self._runtimes)
        if runtimes:
            outcomes = await asyncio.gather(
                *(runtime.stop() for runtime in runtimes), return_exceptions=True
            )
            for outcome in outcomes:
                if isinstance(outcome, BaseException):
                    raise outcome

    async def _close_complete(self) -> None:
        # start() owns this lock through config creation, child startup, and
        # registration. Waiting for it makes the runtime snapshot definitive:
        # no child can be registered after stop_all() has taken its snapshot.
        async with self._start_lock:
            await self.stop_all()
        if self._owns_runtime_dir:
            try:
                self.runtime_dir.rmdir()
            except OSError:
                # Never recursively remove a directory: it may have been reused
                # by an operator between creation and shutdown.
                pass

    async def close(self) -> None:
        cleanup = self._close_task
        if cleanup is None:
            # Publish closure before waiting for the start lock. Queued starts
            # re-check this state after acquiring it and abort without writing
            # a config or spawning a child.
            self._closed = True
            cleanup = asyncio.create_task(
                self._close_complete(), name="xray-runtime-manager-shutdown"
            )
            self._close_task = cleanup

        _, cancellation = await _wait_owned_task(cleanup)
        if cancellation is not None:
            raise cancellation

    async def __aenter__(self) -> "XrayRuntimeManager":
        if self._closed:
            raise XrayStartError("runtime manager is closed")
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()


# Shorter aliases make the module pleasant to use while retaining explicit
# names for callers that expose errors through API and metrics.
RuntimeManager = XrayRuntimeManager
Runtime = XrayRuntime
RuntimeError = XrayRuntimeError
