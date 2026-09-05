"""Bounded source acquisition, kept separate from probing HTTP clients."""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from .security import secret_from_file

REDIRECT_STATUSES = {301, 302, 303, 307, 308}
SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie", "x-api-key"}


class SourceFetchError(RuntimeError):
    reason = "source_fetch"


@dataclass(frozen=True, slots=True)
class SourcePayload:
    content: bytes
    content_type: str | None
    origin: str
    documents: tuple[bytes, ...] = ()


def _value(source: Any, name: str, default: Any = None) -> Any:
    if isinstance(source, dict):
        return source.get(name, default)
    return getattr(source, name, default)


def _resolved_headers(source: Any, *, base_dir: Path | None = None) -> dict[str, str]:
    headers: dict[str, str] = {}
    raw = _value(source, "headers", {}) or {}
    for key, value in raw.items():
        # Config accepts either a literal (primarily for tests/non-secret headers)
        # or {value_file: /run/secrets/...}. Export retains only the reference.
        if isinstance(value, dict) and value.get("value_file"):
            value = secret_from_file(value["value_file"])
        elif hasattr(value, "value_file") and value.value_file:
            value = secret_from_file(value.value_file)
        elif hasattr(value, "get_secret_value"):
            value = value.get_secret_value()
        elif hasattr(value, "value"):
            value = value.value
        if value is not None:
            headers[str(key)] = str(value)
    for key, reference in (_value(source, "headers_ref", {}) or {}).items():
        headers[str(key)] = _secret_reference(reference, base_dir=base_dir)
    return headers


def _secret_reference(value: Any, *, base_dir: Path | None = None) -> str:
    file = _value(value, "file")
    env = _value(value, "env")
    if file:
        path = Path(str(file))
        if not path.is_absolute() and base_dir is not None:
            path = base_dir / path
        return secret_from_file(path)
    if env:
        try:
            return os.environ[str(env)]
        except KeyError as exc:
            raise SourceFetchError("required source secret is unavailable") from exc
    raise SourceFetchError("invalid source secret reference")


def _location(source: Any, *, base_dir: Path | None = None) -> str:
    value = _value(source, "location")
    if value is not None:
        if hasattr(value, "get_secret_value"):
            value = value.get_secret_value()
        return str(value)
    reference = _value(source, "location_ref")
    if reference is not None:
        return _secret_reference(reference, base_dir=base_dir)
    # Loose mappings are accepted for tests and programmatic callers.
    return str(_value(source, "url", "") or _value(source, "path", ""))


class SourceLoader:
    def __init__(
        self,
        *,
        user_agent: str = "xray-e2e-prober/0.1",
        base_dir: str | os.PathLike[str] | None = None,
    ) -> None:
        self.user_agent = user_agent
        self.base_dir = Path(base_dir) if base_dir is not None else None

    async def fetch(self, source: Any) -> SourcePayload:
        # Secret references are small and bounded, but they are still backed by
        # operator-controlled files that may live on a slow mounted filesystem.
        location = await asyncio.to_thread(_location, source, base_dir=self.base_dir)
        raw_kind = _value(source, "kind", "auto")
        kind = str(getattr(raw_kind, "value", raw_kind)).casefold()
        if kind in {"http", "https", "url"}:
            return await self._fetch_http(source, location)
        if kind in {"file", "directory"}:
            return await self._fetch_local(source, Path(location))
        if kind == "auto":
            if location.startswith(("http://", "https://")):
                return await self._fetch_http(source, location)
            return await self._fetch_local(source, Path(location))
        raise SourceFetchError("unsupported source kind")

    async def _fetch_http(self, source: Any, location: str) -> SourcePayload:
        try:
            parsed = urlsplit(location)
            # Accessing ``port`` validates malformed bracket and port syntax.
            parsed.port
        except ValueError as exc:
            raise SourceFetchError("source URL is invalid") from exc
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise SourceFetchError("source URL must be HTTP or HTTPS")
        if parsed.scheme == "http" and not bool(_value(source, "allow_insecure_http", False)):
            raise SourceFetchError("plain HTTP source requires allow_insecure_http")

        timeout = float(_value(source, "timeout_seconds", _value(source, "timeout", 20)))
        max_bytes = int(_value(source, "max_bytes", 4 * 1024 * 1024))
        max_redirects = int(_value(source, "max_redirects", 3))
        base_headers = {"User-Agent": self.user_agent}
        resolved_headers = await asyncio.to_thread(
            _resolved_headers, source, base_dir=self.base_dir
        )
        headers = {**base_headers, **resolved_headers}
        url = location
        original_origin = _origin(url)
        try:
            # Per-phase HTTPX timeouts reset as data arrives. The outer timeout
            # bounds the complete redirect chain and a trickling response body.
            async with asyncio.timeout(timeout):
                async with httpx.AsyncClient(
                    trust_env=False,
                    follow_redirects=False,
                    timeout=httpx.Timeout(timeout),
                ) as client:
                    for redirect_count in range(max_redirects + 1):
                        request_headers = dict(headers)
                        if _origin(url) != original_origin:
                            # A configured header may carry credentials under any
                            # user-selected name. Cross-origin redirects therefore
                            # receive only headers owned by the application.
                            request_headers = dict(base_headers)
                        async with client.stream("GET", url, headers=request_headers) as response:
                            if response.status_code in REDIRECT_STATUSES:
                                if redirect_count >= max_redirects:
                                    raise SourceFetchError("source redirect limit exceeded")
                                target = response.headers.get("location")
                                if not target:
                                    raise SourceFetchError("source redirect has no location")
                                url = urljoin(str(response.url), target)
                                target_scheme = urlsplit(url).scheme
                                if target_scheme not in {"http", "https"}:
                                    raise SourceFetchError(
                                        "source redirected to an unsupported scheme"
                                    )
                                if target_scheme == "http" and not bool(
                                    _value(source, "allow_insecure_http", False)
                                ):
                                    raise SourceFetchError("source redirected to plain HTTP")
                                continue
                            if response.status_code < 200 or response.status_code >= 300:
                                raise SourceFetchError(
                                    f"source returned HTTP status {response.status_code}"
                                )
                            content = await _read_limited(response, max_bytes)
                            return SourcePayload(
                                content=content,
                                content_type=response.headers.get("content-type"),
                                origin=_origin(str(response.url)),
                            )
        except SourceFetchError:
            raise
        except (
            TimeoutError,
            httpx.TimeoutException,
            httpx.NetworkError,
            httpx.ProtocolError,
        ) as exc:
            raise SourceFetchError("source request failed") from exc
        raise SourceFetchError("source request failed")

    async def _fetch_local(self, source: Any, path: Path) -> SourcePayload:
        max_bytes = int(_value(source, "max_bytes", 4 * 1024 * 1024))
        try:
            documents = await asyncio.to_thread(_read_local, path, max_bytes)
        except (OSError, ValueError) as exc:
            raise SourceFetchError("local source could not be read") from exc
        return SourcePayload(
            content=documents[0] if len(documents) == 1 else b"",
            content_type=None,
            origin="local",
            documents=documents,
        )


async def _read_limited(response: httpx.Response, limit: int) -> bytes:
    expected = response.headers.get("content-length")
    if expected and expected.isdecimal() and int(expected) > limit:
        raise SourceFetchError("source response exceeds size limit")
    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if total > limit:
            raise SourceFetchError("source response exceeds size limit")
        chunks.append(chunk)
    return b"".join(chunks)


def _read_local(path: Path, limit: int) -> tuple[bytes, ...]:
    if path.is_file():
        if path.stat().st_size > limit:
            raise ValueError("source file exceeds size limit")
        return (path.read_bytes(),)
    if not path.is_dir():
        raise OSError("source path does not exist")
    chunks: list[bytes] = []
    total = 0
    for child in sorted(path.iterdir()):
        if not child.is_file() or child.suffix.lower() not in {".json", ".txt", ".conf"}:
            continue
        size = child.stat().st_size
        total += size + 1
        if total > limit:
            raise ValueError("source directory exceeds size limit")
        chunks.append(child.read_bytes())
    return tuple(chunks)

    
def _origin(url: str) -> str:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise SourceFetchError("source URL is invalid") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SourceFetchError("source URL is invalid")
    default_port = 443 if parsed.scheme == "https" else 80
    suffix = f":{port}" if port and port != default_port else ""
    return f"{parsed.scheme}://{parsed.hostname}{suffix}"
