"""Small, deliberately conservative helpers for public output and logs."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import SplitResult, urlsplit, urlunsplit

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_UUID_RE = re.compile(
    r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"
)
_VLESS_RE = re.compile(r"(?i)vless://[^\s\]\[<>]+")
_AUTH_RE = re.compile(
    r"(?im)\b(authorization|proxy-authorization|x-api-key|api[-_]?key|token|password)"
    r"(?:['\"])?\s*[:=]\s*[^\r\n]*"
)
_AUTH_SCHEME_RE = re.compile(r"(?i)\b(bearer|basic)\s+[^\s,;\]}]+")
_URL_RE = re.compile(r"https?://[^\s\]\[<>]+", re.IGNORECASE)
_SECRET_QUERY_RE = re.compile(
    r"(?i)([?&](?:token|key|secret|auth|signature|sig|password|uuid)=)[^&#\s]+"
)
_SENSITIVE_FIELD_RE = re.compile(
    r"(?ix)"
    r"(?P<prefix>(?<![a-z0-9_])[\"']?"
    r"(?:private[_-]?key|public[_-]?key|certificate[_-]?key|key|"
    r"short[_-]?ids?|pbk|sid|spiderx|password|token|secret|"
    r"auth(?:orization)?|api[-_]?key|uuid)"
    r"[\"']?\s*[:=]\s*)"
    r"(?:"
    r"\[[^\]\r\n]*\]|"
    r"\{[^}\r\n]*\}|"
    r"\"(?:\\.|[^\"\\\r\n])*\"|"
    r"'(?:\\.|[^'\\\r\n])*'|"
    r"[^\s,;}\]\r\n]+"
    r")"
)
_MAX_REDACTION_INPUT = 16 * 1024


def safe_display_name(value: str, *, max_length: int = 96) -> str:
    """Make untrusted subscription text safe to print on one terminal line."""

    cleaned = _CONTROL_RE.sub(" ", value).strip()
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned[:max_length] or "unnamed"


def redact_url(value: str) -> str:
    """Return only an HTTP URL origin, never userinfo or resource identifiers."""

    try:
        parsed = urlsplit(value)
    except ValueError:
        return "<redacted-url>"
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return "<redacted-url>"
    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    try:
        port = f":{parsed.port}" if parsed.port is not None else ""
    except ValueError:
        return "<redacted-url>"
    return urlunsplit(SplitResult(parsed.scheme, host + port, "", "", ""))


def redact_text(value: object, *, max_length: int = 512) -> str:
    """Redact values commonly present in transport and parser exceptions."""

    text = str(value)
    if len(text) > _MAX_REDACTION_INPUT:
        return "[diagnostic redacted]"
    text = _VLESS_RE.sub("<redacted-vless-uri>", text)
    text = _UUID_RE.sub("<redacted-uuid>", text)
    text = _AUTH_RE.sub(lambda m: f"{m.group(1)}=<redacted>", text)
    text = _AUTH_SCHEME_RE.sub(lambda m: f"{m.group(1)} <redacted>", text)
    text = _SECRET_QUERY_RE.sub(r"\1<redacted>", text)
    text = _SENSITIVE_FIELD_RE.sub(r"\g<prefix><redacted>", text)
    text = _URL_RE.sub(lambda m: redact_url(m.group(0)), text)
    text = _CONTROL_RE.sub(" ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:max_length]


def secret_from_file(path: str | Path, *, max_bytes: int = 64 * 1024) -> str:
    """Read a secret reference with a hard size limit."""

    secret_path = Path(path)
    size = secret_path.stat().st_size
    if size > max_bytes:
        raise ValueError("secret file is too large")
    return secret_path.read_text(encoding="utf-8").rstrip("\r\n")


def public_error(reason: str, detail: object | None = None) -> dict[str, str]:
    payload = {"reason": reason}
    if detail is not None:
        payload["detail"] = redact_text(detail)
    return payload
