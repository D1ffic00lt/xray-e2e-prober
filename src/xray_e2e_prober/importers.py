"""Strict, secret-conscious importers for the MVP source formats."""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Mapping
from urllib.parse import parse_qsl, unquote, urlsplit

from .models import (
    CheckMode,
    Compatibility,
    EntryKind,
    EntryRecord,
    ImportedEntry,
    SourceFormat,
    clean_display_name,
)
from .security import redact_text


MAX_IMPORT_BYTES = 16 * 1024 * 1024
MAX_ENTRIES = 10_000
_BAD_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")
_PARAMETER_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
_BASE64_TEXT = re.compile(r"^[A-Za-z0-9_+/=\s-]+$")

_COMMON_PARAMETERS = {
    "encryption",
    "security",
    "type",
    "flow",
    "sni",
    "fp",
    "alpn",
    "packetEncoding",
    "allowInsecure",
    "insecure",
}
_REALITY_PARAMETERS = {"pbk", "sid", "spx"}
_RAW_PARAMETERS = {"headerType"}
_XHTTP_PARAMETERS = {"host", "path", "mode", "extra"}
_XHTTP_MODES = {"auto", "packet-up", "stream-up", "stream-one"}
_ALLOWED_OUTBOUND_PROTOCOLS = {"vless", "freedom", "blackhole", "dns"}
_ADAPTABLE_INBOUND_PROTOCOLS = {"socks", "http"}
_SENSITIVE_PROFILE_KEYS = {
    "address",
    "email",
    "host",
    "id",
    "password",
    "path",
    "publickey",
    "server",
    "servername",
    "shortid",
    "spiderx",
    "tag",
    "token",
    "uuid",
}
_MAX_PROFILE_SECRET_LITERALS = 256
_MAX_PROFILE_SECRET_NODES = 4096
_PROFILE_SECRET_OVERFLOW = "\x00xray-e2e-prober-redact-profile-name\x00"


class SourceImportError(ValueError):
    """Base error whose text is safe to show without echoing source data."""

    reason = "source_parse"


class UnknownSourceFormatError(SourceImportError):
    pass


class UnsupportedEntryError(SourceImportError):
    reason = "unsupported"


class InvalidEntryError(SourceImportError):
    pass


@dataclass(frozen=True, repr=False)
class ParsedVlessURI:
    uri: str = field(repr=False)
    user_id: str = field(repr=False)
    host: str = field(repr=False)
    port: int
    name: str
    transport: str
    security: str
    parameters: Mapping[str, str] = field(repr=False)

    def __repr__(self) -> str:
        return (
            "ParsedVlessURI("
            f"name={self.name!r}, transport={self.transport!r}, "
            f"security={self.security!r}, port=<redacted>)"
        )

    @property
    def safe_display(self) -> str:
        return f"{self.name} (VLESS/{self.transport.upper()}/{self.security.upper()})"


def _sanitize_source_name(value: str, secret_literals: set[str]) -> str:
    """Remove candidate-local credentials from an otherwise untrusted label."""

    if _PROFILE_SECRET_OVERFLOW in secret_literals or len(value) > 512:
        return "unnamed"
    sanitized = value
    for literal in sorted(secret_literals, key=len, reverse=True):
        literal = literal.strip()
        if not literal or literal.casefold() not in sanitized.casefold():
            continue
        # Replacing one- to three-character secrets throughout a display name
        # can leave recognizable fragments. Prefer an opaque name whenever such
        # a value (for example a short REALITY ID) is actually present.
        if len(literal) < 4:
            return "unnamed"
        sanitized = re.sub(re.escape(literal), "<redacted>", sanitized, flags=re.IGNORECASE)
    return clean_display_name(redact_text(sanitized, max_length=512))


def _profile_secret_literals(profile: Mapping[str, Any]) -> set[str]:
    literals: set[str] = set()
    stack: list[tuple[Any, str | None, bool]] = [(profile, None, False)]
    visited_containers: set[int] = set()
    visited_nodes = 0
    while stack:
        value, key, inherited = stack.pop()
        visited_nodes += 1
        if visited_nodes > _MAX_PROFILE_SECRET_NODES:
            return {_PROFILE_SECRET_OVERFLOW}
        normalized = re.sub(r"[^a-z0-9]", "", key.casefold()) if key else ""
        sensitive = (
            inherited
            or normalized in _SENSITIVE_PROFILE_KEYS
            or any(
                marker in normalized
                for marker in ("credential", "password", "secret", "token", "uuid")
            )
            or normalized.endswith("key")
        )
        if isinstance(value, Mapping):
            identity = id(value)
            if identity in visited_containers:
                continue
            visited_containers.add(identity)
            stack.extend(
                (child_value, str(child_key), sensitive)
                for child_key, child_value in value.items()
            )
        elif isinstance(value, list):
            identity = id(value)
            if identity in visited_containers:
                continue
            visited_containers.add(identity)
            stack.extend((child, key, sensitive) for child in value)
        elif sensitive and isinstance(value, str) and value.strip():
            literals.add(value)
            if len(literals) > _MAX_PROFILE_SECRET_LITERALS:
                return {_PROFILE_SECRET_OVERFLOW}

    return literals


def _decode_text(content: str | bytes) -> str:
    if isinstance(content, str):
        encoded_size = len(content.encode("utf-8"))
        if encoded_size > MAX_IMPORT_BYTES:
            raise SourceImportError("source exceeds the import size limit")
        return content.lstrip("\ufeff")
    if not isinstance(content, (bytes, bytearray)):
        raise TypeError("source content must be str or bytes")
    if len(content) > MAX_IMPORT_BYTES:
        raise SourceImportError("source exceeds the import size limit")
    try:
        return bytes(content).decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise SourceImportError("source is not valid UTF-8") from exc


def _reject_html(text: str) -> None:
    beginning = text.lstrip()[:1024].casefold()
    if beginning.startswith("<!doctype html") or beginning.startswith("<html"):
        raise UnknownSourceFormatError("source returned an HTML document, not a subscription")


def _json_no_duplicates(text: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise InvalidEntryError("JSON contains a duplicate object key")
            result[key] = value
        return result

    try:
        return json.loads(text, object_pairs_hook=pairs)
    except SourceImportError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise InvalidEntryError("source contains invalid JSON") from exc


def _decode_base64_subscription(text: str) -> str:
    compact = "".join(text.split())
    if not compact or not _BASE64_TEXT.fullmatch(compact):
        raise InvalidEntryError("source is not a valid Base64 subscription")
    if len(compact) > MAX_IMPORT_BYTES * 2:
        raise SourceImportError("encoded source exceeds the import size limit")
    compact += "=" * (-len(compact) % 4)
    try:
        decoded = base64.b64decode(compact, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InvalidEntryError("source is not a valid Base64 subscription") from exc
    if len(decoded) > MAX_IMPORT_BYTES:
        raise SourceImportError("decoded source exceeds the import size limit")
    try:
        return decoded.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise InvalidEntryError("Base64 subscription is not valid UTF-8") from exc


def detect_format(content: str | bytes) -> SourceFormat:
    text = _decode_text(content)
    _reject_html(text)
    stripped = text.strip()
    if not stripped:
        # An empty VLESS list is syntactically valid; allow_empty is source policy.
        return SourceFormat.VLESS
    if stripped.startswith("{"):
        value = _json_no_duplicates(stripped)
        if isinstance(value, dict):
            return SourceFormat.XRAY_JSON
        raise UnknownSourceFormatError("JSON source is not a client configuration object")
    if stripped.startswith("["):
        value = _json_no_duplicates(stripped)
        if isinstance(value, list):
            return SourceFormat.XRAY_JSON_ARRAY
        raise UnknownSourceFormatError("JSON source is not an array")
    lines = [line.strip() for line in stripped.splitlines() if line.strip()]
    if lines and all(line.casefold().startswith("vless://") for line in lines):
        return SourceFormat.VLESS
    try:
        decoded = _decode_base64_subscription(stripped)
    except SourceImportError as exc:
        raise UnknownSourceFormatError("source format is not supported") from exc
    decoded_lines = [line.strip() for line in decoded.strip().splitlines() if line.strip()]
    if decoded_lines and all(line.casefold().startswith("vless://") for line in decoded_lines):
        return SourceFormat.VLESS_BASE64
    raise UnknownSourceFormatError("decoded source is not a VLESS URI list")


def parse_vless_uri(uri: str) -> ParsedVlessURI:
    """Parse a supported URI, rejecting every unconsumed semantic parameter."""

    if not isinstance(uri, str) or not uri:
        raise InvalidEntryError("VLESS entry is empty")
    if len(uri) > 32_768:
        raise InvalidEntryError("VLESS entry is too long")
    if _BAD_PERCENT.search(uri):
        raise InvalidEntryError("VLESS entry contains malformed percent encoding")
    try:
        parsed = urlsplit(uri)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise InvalidEntryError("VLESS entry has an invalid address or port") from exc
    if parsed.scheme.casefold() != "vless":
        raise InvalidEntryError("entry is not a VLESS URI")
    if parsed.password is not None:
        raise InvalidEntryError("VLESS URI userinfo must not contain a password")
    if parsed.username is None or host is None or port is None:
        raise InvalidEntryError("VLESS URI requires UUID, host, and port")
    try:
        user_id = str(uuid.UUID(unquote(parsed.username)))
    except (ValueError, AttributeError) as exc:
        raise InvalidEntryError("VLESS URI contains an invalid UUID") from exc
    if not 1 <= port <= 65535:
        raise InvalidEntryError("VLESS URI port is out of range")

    try:
        pairs = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=64)
    except ValueError as exc:
        raise InvalidEntryError("VLESS URI query is invalid or too large") from exc
    parameters: dict[str, str] = {}
    for key, value in pairs:
        if not _PARAMETER_NAME.fullmatch(key):
            raise UnsupportedEntryError("VLESS URI contains an unsupported query parameter")
        if key in parameters:
            # Parameter names are source-controlled and can themselves contain
            # private material; public diagnostics stay deliberately opaque.
            raise InvalidEntryError("VLESS URI repeats a query parameter")
        parameters[key] = value

    transport_value = parameters.get("type", "tcp").casefold()
    if transport_value not in {"tcp", "raw", "xhttp"}:
        raise UnsupportedEntryError("VLESS transport is not supported")
    transport = "raw" if transport_value == "tcp" else transport_value
    security = parameters.get("security", "").casefold()
    if security not in {"tls", "reality"}:
        raise UnsupportedEntryError("VLESS security must be TLS or REALITY")
    if parameters.get("encryption", "none").casefold() != "none":
        raise UnsupportedEntryError("VLESS encryption setting is not supported")

    allowed = set(_COMMON_PARAMETERS)
    allowed |= _RAW_PARAMETERS if transport == "raw" else _XHTTP_PARAMETERS
    if security == "reality":
        allowed |= _REALITY_PARAMETERS
    unknown = set(parameters) - allowed
    if unknown:
        raise UnsupportedEntryError("VLESS URI contains unsupported semantic parameters")

    if security == "reality":
        if not parameters.get("pbk") or not parameters.get("sni"):
            raise InvalidEntryError("REALITY VLESS requires pbk and sni")
        if parameters.get("allowInsecure") or parameters.get("insecure"):
            raise UnsupportedEntryError("allowInsecure is not meaningful for REALITY")
    elif set(parameters) & _REALITY_PARAMETERS:
        raise UnsupportedEntryError("REALITY parameters cannot be used with TLS")

    if transport == "raw":
        if parameters.get("headerType", "none").casefold() != "none":
            raise UnsupportedEntryError("only a none RAW header is supported")
    else:
        mode = parameters.get("mode", "auto")
        if mode not in _XHTTP_MODES:
            raise UnsupportedEntryError("XHTTP mode is not supported")
        if "extra" in parameters:
            try:
                extra = _json_no_duplicates(parameters["extra"])
            except SourceImportError as exc:
                raise InvalidEntryError("XHTTP extra parameter is not valid JSON") from exc
            if not isinstance(extra, dict):
                raise InvalidEntryError("XHTTP extra parameter must be a JSON object")

    for boolean_parameter in ("allowInsecure", "insecure"):
        if boolean_parameter in parameters and parameters[boolean_parameter].casefold() not in {
            "0",
            "1",
            "false",
            "true",
        }:
            raise InvalidEntryError("VLESS boolean parameter is invalid")
    if "allowInsecure" in parameters and "insecure" in parameters:
        raise InvalidEntryError("VLESS URI repeats the TLS verification setting")
    insecure = parameters.get("allowInsecure", parameters.get("insecure"))
    if insecure is not None and insecure.casefold() in {"1", "true"}:
        # Xray 26.3.27 removed tlsSettings.allowInsecure.  Silently ignoring a
        # request to disable certificate validation would also change the
        # connection's meaning, so fail the candidate explicitly.
        raise UnsupportedEntryError("disabling TLS certificate verification is unsupported")
    if "packetEncoding" in parameters and parameters["packetEncoding"] not in {
        "",
        "none",
        "packetaddr",
        "xudp",
    }:
        raise UnsupportedEntryError("VLESS packetEncoding is not supported")

    if parsed.fragment:
        secret_literals = {user_id, host}
        secret_literals.update(
            value
            for key, value in parameters.items()
            if key in {"extra", "host", "path", "pbk", "sid", "sni", "spx"} and value
        )
        name = _sanitize_source_name(unquote(parsed.fragment), secret_literals)
    else:
        name = "VLESS connection"
    return ParsedVlessURI(
        uri=uri,
        user_id=user_id,
        host=host.casefold(),
        port=port,
        name=name,
        transport=transport,
        security=security,
        parameters=parameters,
    )


def _comma_values(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def vless_uri_to_outbound(
    value: str | ParsedVlessURI,
    *,
    tag: str = "probe-selected",
) -> dict[str, Any]:
    parsed = parse_vless_uri(value) if isinstance(value, str) else value
    parameters = parsed.parameters
    user: dict[str, Any] = {
        "id": parsed.user_id,
        "encryption": parameters.get("encryption", "none"),
    }
    if parameters.get("flow"):
        user["flow"] = parameters["flow"]
    settings: dict[str, Any] = {
        "vnext": [
            {
                "address": parsed.host,
                "port": parsed.port,
                "users": [user],
            }
        ]
    }
    if parameters.get("packetEncoding") not in {None, "", "none"}:
        settings["packetEncoding"] = parameters["packetEncoding"]
    stream: dict[str, Any] = {"network": parsed.transport, "security": parsed.security}
    security_settings: dict[str, Any] = {}
    if parameters.get("sni"):
        security_settings["serverName"] = parameters["sni"]
    if parameters.get("fp"):
        security_settings["fingerprint"] = parameters["fp"]
    if parameters.get("alpn"):
        security_settings["alpn"] = _comma_values(parameters["alpn"])
    if parsed.security == "reality":
        security_settings["publicKey"] = parameters["pbk"]
        if parameters.get("sid"):
            security_settings["shortId"] = parameters["sid"]
        if parameters.get("spx"):
            security_settings["spiderX"] = parameters["spx"]
        stream["realitySettings"] = security_settings
    else:
        # Explicit false is equivalent to Xray's strict default.  Do not emit
        # the removed allowInsecure field even when older URI producers include
        # it as boilerplate.
        stream["tlsSettings"] = security_settings

    if parsed.transport == "raw":
        stream["rawSettings"] = {"header": {"type": "none"}}
    else:
        xhttp: dict[str, Any] = {
            "path": parameters.get("path", "/"),
            "mode": parameters.get("mode", "auto"),
        }
        if parameters.get("host"):
            xhttp["host"] = parameters["host"]
        if "extra" in parameters:
            xhttp["extra"] = _json_no_duplicates(parameters["extra"])
        stream["xhttpSettings"] = xhttp
    return {"tag": tag, "protocol": "vless", "settings": settings, "streamSettings": stream}


def _validate_vless_outbound(outbound: Mapping[str, Any]) -> tuple[str, str]:
    stream = outbound.get("streamSettings")
    if not isinstance(stream, Mapping):
        raise UnsupportedEntryError("VLESS outbound requires streamSettings")
    transport_value = str(stream.get("network", "raw")).casefold()
    if transport_value not in {"tcp", "raw", "xhttp"}:
        raise UnsupportedEntryError("profile contains an unsupported VLESS transport")
    transport = "raw" if transport_value == "tcp" else transport_value
    security = str(stream.get("security", "")).casefold()
    if security not in {"tls", "reality"}:
        raise UnsupportedEntryError("profile VLESS security must be TLS or REALITY")
    if security == "tls":
        tls_settings = stream.get("tlsSettings")
        if isinstance(tls_settings, Mapping) and "allowInsecure" in tls_settings:
            raise UnsupportedEntryError(
                "profile uses the removed TLS allowInsecure setting"
            )
    settings = outbound.get("settings")
    if not isinstance(settings, Mapping):
        raise InvalidEntryError("VLESS outbound settings are missing")
    vnext = settings.get("vnext")
    if not isinstance(vnext, list) or not vnext:
        raise InvalidEntryError("VLESS outbound has no server")
    return transport, security


def validate_xray_profile(profile: Any) -> dict[str, Any]:
    """Validate the MVP outbound matrix while retaining the exact JSON tree."""

    if not isinstance(profile, dict):
        raise InvalidEntryError("Xray profile must be a JSON object")
    outbounds = profile.get("outbounds")
    if not isinstance(outbounds, list) or not outbounds:
        raise InvalidEntryError("Xray profile requires a non-empty outbounds array")
    vless_count = 0
    tags: set[str] = set()
    for outbound in outbounds:
        if not isinstance(outbound, dict):
            raise InvalidEntryError("Xray outbound must be a JSON object")
        protocol = outbound.get("protocol")
        if protocol not in _ALLOWED_OUTBOUND_PROTOCOLS:
            raise UnsupportedEntryError("profile contains an unsupported outbound protocol")
        tag = outbound.get("tag")
        if tag is not None:
            if not isinstance(tag, str) or not tag:
                raise InvalidEntryError("Xray outbound tag must be a non-empty string")
            if tag in tags:
                raise InvalidEntryError("Xray profile contains duplicate outbound tags")
            tags.add(tag)
        if protocol == "vless":
            _validate_vless_outbound(outbound)
            vless_count += 1
    if vless_count == 0:
        raise UnsupportedEntryError("Xray profile has no supported VLESS outbound")
    _compatible_inbound_tag(profile)
    # copy.deepcopy is intentional: callers may adapt runtime copies without
    # modifying the accepted last-known-good profile.
    return copy.deepcopy(profile)


def _compatible_inbound_tag(profile: Mapping[str, Any]) -> str | None:
    """Validate client inbounds and return the sole automatically selectable tag."""

    inbounds = profile.get("inbounds")
    if not isinstance(inbounds, list) or not inbounds:
        raise InvalidEntryError("Xray client profile requires a non-empty inbounds array")
    compatible: list[Mapping[str, Any]] = []
    tags: set[str] = set()
    for inbound in inbounds:
        if not isinstance(inbound, Mapping):
            raise InvalidEntryError("Xray inbound must be a JSON object")
        tag = inbound.get("tag")
        if tag is not None:
            if not isinstance(tag, str) or not tag:
                raise InvalidEntryError("Xray inbound tag must be a non-empty string")
            if tag in tags:
                raise InvalidEntryError("Xray profile contains duplicate inbound tags")
            tags.add(tag)
        if inbound.get("protocol") in _ADAPTABLE_INBOUND_PROTOCOLS:
            sniffing = inbound.get("sniffing")
            if sniffing is not None and not isinstance(sniffing, Mapping):
                raise InvalidEntryError("Xray inbound sniffing must be a JSON object")
            compatible.append(inbound)
    if not compatible:
        raise UnsupportedEntryError("profile has no compatible SOCKS or HTTP client inbound")
    if len(compatible) > 1 and any(not item.get("tag") for item in compatible):
        raise UnsupportedEntryError("ambiguous compatible inbounds require non-empty tags")
    if len(compatible) == 1:
        tag = compatible[0].get("tag")
        return tag if isinstance(tag, str) else None
    return None


def _nonsecret_vless_identity(parsed: ParsedVlessURI) -> str:
    """Fingerprint a deliberately small allow-list of non-credential fields."""

    parameters = parsed.parameters
    semantic = {
        "host": parsed.host,
        "port": parsed.port,
        "transport": parsed.transport,
        "security": parsed.security,
        "sni": parameters.get("sni"),
        "xhttp_host": parameters.get("host"),
        "xhttp_mode": parameters.get("mode"),
    }
    # UUIDs, public/private keys, short IDs, paths, extra, tags, user metadata,
    # and every other free-form field are intentionally outside this digest.
    encoded = (
        "safe-reconciliation-v2\0"
        + json.dumps(semantic, sort_keys=True, separators=(",", ":"))
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _profile_identity(profile: Mapping[str, Any]) -> str:
    """Fingerprint only whitelisted endpoint semantics from a client profile."""

    semantic: list[dict[str, Any]] = []
    for outbound in profile.get("outbounds", []):
        if outbound.get("protocol") != "vless":
            continue
        stream = outbound.get("streamSettings") or {}
        vnext = (outbound.get("settings") or {}).get("vnext") or []
        server = vnext[0] if vnext else {}
        security = stream.get("security")
        secure = stream.get(f"{security}Settings") or {}
        xhttp = stream.get("xhttpSettings") or {}
        semantic.append(
            {
                "address": server.get("address"),
                "port": server.get("port"),
                "network": stream.get("network", "raw"),
                "security": security,
                "serverName": secure.get("serverName"),
                "xhttpHost": xhttp.get("host"),
                "xhttpMode": xhttp.get("mode"),
            }
        )
    semantic.sort(
        key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":"))
    )
    # Do not add tags, credentials, keys, user IDs, XHTTP paths/extra, routing,
    # or display metadata. The exported digest must never be a credential hash.
    encoded = (
        "safe-reconciliation-v2\0"
        + json.dumps(semantic, sort_keys=True, separators=(",", ":"))
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def safe_reconciliation_fingerprint(entry: ImportedEntry | EntryRecord) -> str | None:
    """Recompute an export-safe identity digest without trusting stored hashes.

    The result is derived exclusively from the allow-lists above. Returning
    ``None`` fails closed for a malformed historical LKG entry.
    """

    try:
        if isinstance(entry.profile, Mapping):
            return _profile_identity(entry.profile)
        if isinstance(entry.payload, Mapping):
            return _profile_identity(entry.payload)
        if isinstance(entry.payload, str):
            return _nonsecret_vless_identity(parse_vless_uri(entry.payload))
    except (SourceImportError, TypeError, ValueError):
        return None
    return None


def _profile_name(profile: Mapping[str, Any], index: int) -> str:
    secret_literals = _profile_secret_literals(profile)
    for key in ("name", "remarks", "remark"):
        value = profile.get(key)
        if isinstance(value, str) and value.strip():
            return _sanitize_source_name(value, secret_literals)
    metadata = profile.get("metadata")
    if isinstance(metadata, Mapping):
        for key in ("name", "remarks"):
            value = metadata.get(key)
            if isinstance(value, str) and value.strip():
                return _sanitize_source_name(value, secret_literals)
    return f"Xray profile {index}"


def _profile_external_id(profile: Mapping[str, Any]) -> str | None:
    for container in (profile, profile.get("metadata")):
        if isinstance(container, Mapping):
            value = container.get("id")
            if isinstance(value, str) and value.strip() and len(value) <= 512:
                return value
    return None


def _import_vless_lines(text: str, source_id: str | None) -> list[ImportedEntry]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) > MAX_ENTRIES:
        raise SourceImportError("source contains too many entries")
    entries: list[ImportedEntry] = []
    for index, line in enumerate(lines, 1):
        try:
            parsed = parse_vless_uri(line)
        except SourceImportError as exc:
            raise type(exc)(f"entry {index}: {exc}") from exc
        entries.append(
            ImportedEntry(
                candidate_id=f"candidate_{index:05d}",
                source_id=source_id,
                name=parsed.name,
                kind=EntryKind.VLESS_URI,
                mode=CheckMode.CONNECTION,
                payload=line,
                protocol="vless",
                transport=parsed.transport,
                security=parsed.security,
                compatibility=Compatibility.SUPPORTED,
                identity_name=parsed.name.casefold(),
                connection_fingerprint=_nonsecret_vless_identity(parsed),
                safe_display=parsed.safe_display,
            )
        )
    return entries


def _import_profiles(values: list[Any], source_id: str | None) -> list[ImportedEntry]:
    if len(values) > MAX_ENTRIES:
        raise SourceImportError("source contains too many entries")
    entries: list[ImportedEntry] = []
    for index, raw in enumerate(values, 1):
        try:
            profile = validate_xray_profile(raw)
        except SourceImportError as exc:
            raise type(exc)(f"entry {index}: {exc}") from exc
        transports: set[str] = set()
        securities: set[str] = set()
        for outbound in profile["outbounds"]:
            if outbound.get("protocol") == "vless":
                transport, security = _validate_vless_outbound(outbound)
                transports.add(transport)
                securities.add(security)
        name = _profile_name(profile, index)
        inbound_tag = _compatible_inbound_tag(profile)
        transport_label = next(iter(transports)) if len(transports) == 1 else "mixed"
        security_label = next(iter(securities)) if len(securities) == 1 else "mixed"
        entries.append(
            ImportedEntry(
                candidate_id=f"candidate_{index:05d}",
                source_id=source_id,
                name=name,
                kind=EntryKind.XRAY_JSON,
                mode=CheckMode.PROFILE,
                profile=profile,
                inbound_tag=inbound_tag,
                external_id=_profile_external_id(profile),
                protocol="vless",
                transport=transport_label,
                security=security_label,
                identity_name=name.casefold(),
                connection_fingerprint=_profile_identity(profile),
                safe_display=f"{name} (Xray profile, VLESS/{transport_label}/{security_label})",
            )
        )
    return entries


def import_content(
    content: str | bytes,
    source_format: SourceFormat | str = SourceFormat.AUTO,
    *,
    source_id: str | None = None,
    format: SourceFormat | str | None = None,
) -> list[ImportedEntry]:
    """Import one source atomically; any bad entry fails the whole source."""

    if format is not None:
        if source_format not in {SourceFormat.AUTO, SourceFormat.AUTO.value}:
            raise TypeError("pass source_format or format, not both")
        source_format = format
    try:
        selected_format = SourceFormat(source_format)
    except ValueError as exc:
        raise UnknownSourceFormatError("source format is not supported") from exc
    text = _decode_text(content)
    _reject_html(text)
    if selected_format is SourceFormat.AUTO:
        selected_format = detect_format(text)
    if selected_format is SourceFormat.VLESS_BASE64:
        text = _decode_base64_subscription(text)
        return _import_vless_lines(text, source_id)
    if selected_format is SourceFormat.VLESS:
        return _import_vless_lines(text, source_id)
    value = _json_no_duplicates(text)
    if selected_format is SourceFormat.XRAY_JSON:
        if not isinstance(value, dict):
            raise InvalidEntryError("expected one Xray JSON object")
        return _import_profiles([value], source_id)
    if selected_format is SourceFormat.XRAY_JSON_ARRAY:
        if not isinstance(value, list):
            raise InvalidEntryError("expected an array of Xray JSON objects")
        return _import_profiles(value, source_id)
    raise UnknownSourceFormatError("source format is not supported")


parse_subscription = import_content
import_entries = import_content


def effective_connection_outbound(
    value: str | ParsedVlessURI | ImportedEntry | EntryRecord | Mapping[str, Any],
    *,
    outbound_tag: str | None = None,
    effective_tag: str | None = None,
) -> dict[str, Any]:
    """Return a deep-copied VLESS outbound for a connection-mode runtime."""

    if isinstance(value, (str, ParsedVlessURI)):
        return vless_uri_to_outbound(value, tag=effective_tag or "probe-selected")
    if isinstance(value, (ImportedEntry, EntryRecord)):
        outbound_tag = outbound_tag or value.outbound_tag
        if isinstance(value.payload, str):
            return vless_uri_to_outbound(value.payload, tag=effective_tag or "probe-selected")
        profile = value.profile or (value.payload if isinstance(value.payload, dict) else None)
        if profile is None:
            raise InvalidEntryError("entry has no effective profile")
    elif isinstance(value, Mapping):
        if value.get("protocol"):
            profile = {"outbounds": [dict(value)]}
        else:
            profile = dict(value)
    else:
        raise TypeError("unsupported effective outbound input")
    validated = validate_xray_profile(profile)
    candidates = [item for item in validated["outbounds"] if item.get("protocol") == "vless"]
    if outbound_tag is not None:
        candidates = [item for item in candidates if item.get("tag") == outbound_tag]
        if not candidates:
            raise InvalidEntryError("selected VLESS outbound tag was not found")
    if len(candidates) != 1:
        raise UnsupportedEntryError("connection mode requires one unambiguous VLESS outbound")
    result = copy.deepcopy(candidates[0])
    if effective_tag is not None:
        result["tag"] = effective_tag
    return result


def safe_entry_display(value: str | ParsedVlessURI | ImportedEntry | EntryRecord) -> str:
    if isinstance(value, str):
        return parse_vless_uri(value).safe_display
    if isinstance(value, ParsedVlessURI):
        return value.safe_display
    return clean_display_name(value.safe_display or value.name)


def redact_vless_uri(value: str) -> str:
    """Return only non-addressing display metadata, never a reconstructed URI."""

    try:
        return parse_vless_uri(value).safe_display
    except SourceImportError:
        return "invalid VLESS entry (redacted)"


__all__ = [
    "InvalidEntryError",
    "ParsedVlessURI",
    "SourceImportError",
    "UnknownSourceFormatError",
    "UnsupportedEntryError",
    "detect_format",
    "effective_connection_outbound",
    "import_content",
    "import_entries",
    "parse_subscription",
    "parse_vless_uri",
    "redact_vless_uri",
    "safe_reconciliation_fingerprint",
    "safe_entry_display",
    "validate_xray_profile",
    "vless_uri_to_outbound",
]
