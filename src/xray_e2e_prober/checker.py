"""HTTP end-to-end checks executed exclusively through a managed Xray SOCKS port."""

from __future__ import annotations

import asyncio
import contextvars
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpcore
import httpx

from .models import (
    CycleResult,
    EgressResult,
    EgressState,
    ReachabilityResult,
    ReachabilityState,
    Reason,
    TargetResult,
)


class CheckerConfigurationError(ValueError):
    reason = Reason.CONFIG_INVALID


@dataclass(frozen=True, slots=True)
class _ResponseData:
    status_code: int
    body: bytes
    bytes_read: int
    duration_seconds: float
    ttfb_seconds: float | None
    encoding: str | None
    redirect_count: int


class _BodyTooLarge(Exception):
    def __init__(self, bytes_read: int) -> None:
        self.bytes_read = bytes_read


class _InvalidResponse(Exception):
    pass


_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


@dataclass(slots=True)
class _TTFBObservation:
    started: float
    clock: Callable[[], float]
    armed: bool = False
    first_byte_at: float | None = None

    def observe(self, data: bytes) -> None:
        if self.armed and data and self.first_byte_at is None:
            self.first_byte_at = self.clock()

    @property
    def elapsed(self) -> float | None:
        if self.first_byte_at is None:
            return None
        return max(0.0, self.first_byte_at - self.started)


_ACTIVE_TTFB: contextvars.ContextVar[_TTFBObservation | None] = contextvars.ContextVar(
    "xray_e2e_prober_ttfb", default=None
)


class _TTFBStream(httpcore.AsyncNetworkStream):
    """Pinned-httpcore stream wrapper observing the first response socket read."""

    def __init__(self, stream: httpcore.AsyncNetworkStream) -> None:
        self._stream = stream

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        data = await self._stream.read(max_bytes, timeout)
        observation = _ACTIVE_TTFB.get()
        if observation is not None:
            observation.observe(data)
        return data

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        await self._stream.write(buffer, timeout)

    async def aclose(self) -> None:
        await self._stream.aclose()

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.AsyncNetworkStream:
        stream = await self._stream.start_tls(ssl_context, server_hostname, timeout)
        return _TTFBStream(stream)

    def get_extra_info(self, info: str) -> Any:
        return self._stream.get_extra_info(info)


class _TTFBBackend(httpcore.AsyncNetworkBackend):
    """Wrap streams created by HTTP Core while preserving its pinned backend."""

    def __init__(self, backend: httpcore.AsyncNetworkBackend) -> None:
        self._backend = backend

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        stream = await self._backend.connect_tcp(
            host,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )
        return _TTFBStream(stream)

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        stream = await self._backend.connect_unix_socket(
            path, timeout=timeout, socket_options=socket_options
        )
        return _TTFBStream(stream)

    async def sleep(self, seconds: float) -> None:
        await self._backend.sleep(seconds)


def _ttfb_transport(proxy_url: str, limits: httpx.Limits) -> httpx.AsyncHTTPTransport:
    """Create the version-pinned HTTPX/httpcore SOCKS transport instrumentation.

    HTTPX 0.27.2 with the locked httpcore 1.0.9 does not expose the network
    backend constructor argument. The lockfile pins this private pool seam and
    integration tests fail closed if it changes instead of publishing false
    header-completion timing as TTFB.
    """

    transport = httpx.AsyncHTTPTransport(
        proxy=proxy_url,
        trust_env=False,
        limits=limits,
        http1=True,
        http2=False,
    )
    pool = getattr(transport, "_pool", None)
    backend = getattr(pool, "_network_backend", None)
    if not isinstance(backend, httpcore.AsyncNetworkBackend):
        raise RuntimeError("installed HTTP transport cannot provide exact TTFB")
    pool._network_backend = _TTFBBackend(backend)
    return transport


def _field(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def _enum_value(value: Any) -> Any:
    return getattr(value, "value", value)


def _target_id(target: Any) -> str:
    value = _field(target, "target_id")
    if not isinstance(value, str) or not value:
        raise CheckerConfigurationError("target_id is required")
    return value


def _absolute_http_url(value: Any, *, kind: str) -> str:
    if not isinstance(value, str):
        raise CheckerConfigurationError(f"{kind} URL must be a string")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise CheckerConfigurationError(f"{kind} URL must be absolute HTTP or HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise CheckerConfigurationError(f"{kind} URL must not contain userinfo")
    return value


def _redirect_url(base_url: str, location: str) -> str:
    """Resolve one server-provided redirect without accepting other schemes."""

    try:
        candidate = urljoin(base_url, location)
        parsed = urlsplit(candidate)
        # Accessing ``port`` also validates malformed bracket/port syntax.
        parsed.port
        httpx.URL(candidate)
    except (TypeError, ValueError, httpx.InvalidURL) as exc:
        raise _InvalidResponse("invalid redirect URL") from exc
    if (
        parsed.scheme.casefold() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise _InvalidResponse("unsupported redirect URL")
    return candidate


def _positive_timeout(value: Any, default: float) -> float:
    if value is None:
        value = default
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise CheckerConfigurationError("request timeout must be positive")
    return float(value)


def _body_limit(value: Any, default: int) -> int:
    if value is None:
        value = default
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise CheckerConfigurationError("response body limit must be positive")
    return value


def _statuses(target: Any) -> frozenset[int]:
    values = _field(target, "expected_statuses")
    if values is None:
        values = _field(target, "expected_status_codes", {200})
    try:
        result = frozenset(values)
    except TypeError as exc:
        raise CheckerConfigurationError("expected statuses must be a collection") from exc
    if not result or any(
        isinstance(value, bool) or not isinstance(value, int) or not 100 <= value <= 599
        for value in result
    ):
        raise CheckerConfigurationError("expected HTTP statuses are invalid")
    return result


def _matcher(target: Any) -> tuple[str, str] | None:
    body = _field(target, "body")
    if body is None:
        exact = _field(target, "body_exact")
        regex = _field(target, "body_regex")
        if exact is not None and regex is not None:
            raise CheckerConfigurationError("only one body matcher may be configured")
        if exact is not None:
            return "exact", str(exact)
        if regex is not None:
            try:
                re.compile(str(regex))
            except re.error as exc:
                raise CheckerConfigurationError("invalid body regular expression") from exc
            return "regex", str(regex)
        return None
    kind = _enum_value(_field(body, "kind"))
    expected = _field(body, "value")
    if kind not in {"exact", "regex"} or not isinstance(expected, str):
        raise CheckerConfigurationError("invalid body matcher")
    if kind == "regex":
        try:
            re.compile(expected)
        except re.error as exc:
            raise CheckerConfigurationError("invalid body regular expression") from exc
    return str(kind), expected


def _decode_body(body: bytes, encoding: str | None) -> str:
    try:
        return body.decode(encoding or "utf-8", "replace")
    except LookupError:
        return body.decode("utf-8", "replace")


_REGEX_HELPER = (
    "import json,re,sys;"
    "v=json.load(sys.stdin);"
    "sys.stdout.write('1' if re.search(v['pattern'],v['text']) is not None else '0')"
)


async def _wait_killed(process: asyncio.subprocess.Process) -> None:
    if process.returncode is None:
        try:
            process.kill()
        except ProcessLookupError:
            pass
    waiter = asyncio.create_task(process.wait())
    while True:
        try:
            await asyncio.shield(waiter)
            return
        except asyncio.CancelledError:
            # Cleanup is intentionally non-interruptible: leaving a catastrophic
            # matcher behind would turn a request timeout into continuing CPU use.
            if waiter.done():
                # Propagate an unexpected cancellation originating in wait()
                # instead of spinning forever on an already-finished task.
                waiter.result()
                return
            continue


async def _start_regex_process() -> asyncio.subprocess.Process:
    starter = asyncio.create_task(
        asyncio.create_subprocess_exec(
            sys.executable,
            "-I",
            "-S",
            "-c",
            _REGEX_HELPER,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env={"PATH": os.defpath},
        )
    )
    try:
        return await asyncio.shield(starter)
    except asyncio.CancelledError:
        if starter.done():
            process = starter.result()
        else:
            while True:
                try:
                    process = await asyncio.shield(starter)
                    break
                except asyncio.CancelledError:
                    if starter.done():
                        process = starter.result()
                        break
                    continue
        await _wait_killed(process)
        raise


async def _regex_search(pattern: str, text: str) -> bool:
    payload = json.dumps(
        {"pattern": pattern, "text": text}, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    process = await _start_regex_process()
    try:
        stdout, _ = await process.communicate(payload)
    except BaseException:
        await _wait_killed(process)
        raise
    if process.returncode != 0 or stdout not in {b"0", b"1"}:
        raise CheckerConfigurationError("body regular expression could not be evaluated")
    return stdout == b"1"


async def _decode_and_match(
    body: bytes, encoding: str | None, matcher: tuple[str, str]
) -> bool:
    """Decode bounded input and evaluate regex in a killable isolated process."""

    actual = await asyncio.to_thread(_decode_body, body, encoding)
    kind, expected = matcher
    if kind == "exact":
        return actual == expected
    return await _regex_search(expected, actual)


def _redirect_limit(target: Any) -> int:
    follow = bool(_field(target, "follow_redirects", False))
    redirects = _field(target, "max_redirects", 0)
    if isinstance(redirects, bool) or not isinstance(redirects, int) or redirects < 0:
        raise CheckerConfigurationError("max_redirects is invalid")
    # Match TargetConfig's documented default for flexible mapping callers.
    return 5 if follow and redirects == 0 else redirects


def _validate_target(target: Any, default_timeout: float, default_body_limit: int) -> None:
    _target_id(target)
    _absolute_http_url(_field(target, "url"), kind="target")
    if _field(target, "method", "GET") != "GET":
        raise CheckerConfigurationError("only GET targets are supported")
    _statuses(target)
    _positive_timeout(
        _field(target, "timeout", _field(target, "timeout_seconds")), default_timeout
    )
    _body_limit(_field(target, "max_body_bytes"), default_body_limit)
    follow = bool(_field(target, "follow_redirects", False))
    redirects = _redirect_limit(target)
    if redirects and not follow:
        raise CheckerConfigurationError("max_redirects requires redirects to be enabled")
    _matcher(target)


def _exception_chain(exc: BaseException) -> list[BaseException]:
    result: list[BaseException] = []
    current: BaseException | None = exc
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        result.append(current)
        current = current.__cause__ or current.__context__
    return result


def _classify_exception(exc: BaseException) -> tuple[Reason, str]:
    chain = _exception_chain(exc)
    if isinstance(exc, (asyncio.TimeoutError, httpx.TimeoutException)):
        return Reason.TIMEOUT, "request deadline exceeded"
    if any(isinstance(item, ssl.SSLError) for item in chain):
        return Reason.TLS, "target TLS verification failed"
    if any(isinstance(item, socket.gaierror) for item in chain):
        # With SOCKS this signal is uncommon because destination DNS is normally
        # delegated to Xray, but retain it when the transport reports it reliably.
        return Reason.DNS, "target name resolution failed"
    if isinstance(exc, httpx.TooManyRedirects):
        return Reason.RESPONSE_INVALID, "redirect limit exceeded"
    if isinstance(exc, (httpx.InvalidURL, httpx.UnsupportedProtocol)):
        return Reason.CONFIG_INVALID, "target URL is invalid"
    if isinstance(exc, httpx.ConnectError):
        # A SOCKS failure cannot reliably distinguish credentials, proxy DNS,
        # remote transport, or the selected outbound. Do not invent precision.
        return Reason.PROXY, "request failed through SOCKS proxy"
    if isinstance(exc, (httpx.NetworkError, httpx.ProxyError)):
        return Reason.PROXY, "request failed through SOCKS proxy"
    if isinstance(exc, (httpx.DecodingError, httpx.RemoteProtocolError, _InvalidResponse)):
        return Reason.RESPONSE_INVALID, "target returned an invalid response"
    if isinstance(exc, _BodyTooLarge):
        return Reason.RESPONSE_INVALID, "response body limit exceeded"
    if isinstance(exc, CheckerConfigurationError):
        return Reason.CONFIG_INVALID, str(exc)
    if isinstance(exc, httpx.HTTPError):
        return Reason.CONNECT, "HTTP request failed"
    return Reason.INTERNAL, "internal checker error"


def _network_failure(reason: Reason) -> bool:
    return reason in {
        Reason.CONNECT,
        Reason.PROXY,
        Reason.DNS,
        Reason.TIMEOUT,
        Reason.TLS,
        Reason.HTTP_STATUS,
        Reason.BODY_MISMATCH,
        Reason.RESPONSE_INVALID,
    }


def _target_error_result(
    target_id: str,
    exc: BaseException,
    *,
    duration: float | None = None,
    bytes_read: int | None = None,
    ttfb_seconds: float | None = None,
) -> TargetResult:
    reason, safe_error = _classify_exception(exc)
    state = ReachabilityState.FAILURE if _network_failure(reason) else ReachabilityState.ERROR
    if isinstance(exc, _BodyTooLarge):
        bytes_read = exc.bytes_read
    return TargetResult(
        target_id=target_id,
        state=state,
        reason=reason,
        duration_seconds=duration,
        ttfb_seconds=ttfb_seconds,
        bytes_read=bytes_read,
        error=safe_error,
    )


class Checker:
    """Perform one-cycle HTTP and egress probes through a local SOCKS proxy.

    A new HTTPX client (and therefore a new pool and cookie jar) is created for
    every target-set call. Reuse occurs only among requests in that one cycle.
    """

    def __init__(
        self,
        *,
        request_timeout: float = 15.0,
        max_parallel_requests: int = 8,
        default_body_limit: int = 64 * 1024,
        egress_body_limit: int = 4096,
        client_factory: Callable[..., Any] | None = None,
    ) -> None:
        self.request_timeout = _positive_timeout(request_timeout, 15.0)
        if (
            isinstance(max_parallel_requests, bool)
            or not isinstance(max_parallel_requests, int)
            or max_parallel_requests < 1
        ):
            raise CheckerConfigurationError("max_parallel_requests must be positive")
        self.default_body_limit = _body_limit(default_body_limit, 64 * 1024)
        self.egress_body_limit = _body_limit(egress_body_limit, 4096)
        self._semaphore = asyncio.Semaphore(max_parallel_requests)
        self._client_factory = client_factory

    @staticmethod
    def _proxy_url(host: str, port: int) -> str:
        try:
            address = ipaddress.ip_address(host)
        except ValueError as exc:
            raise CheckerConfigurationError("SOCKS host must be a loopback IP") from exc
        if not address.is_loopback:
            raise CheckerConfigurationError("SOCKS host must be a loopback IP")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise CheckerConfigurationError("SOCKS port is invalid")
        bracketed = f"[{host}]" if address.version == 6 else host
        return f"socks5://{bracketed}:{port}"

    def _make_client(self, proxy_url: str) -> Any:
        limits = httpx.Limits(max_connections=None, max_keepalive_connections=20)
        options = {
            "trust_env": False,
            "timeout": None,
            "follow_redirects": False,
            # Redirects are followed manually so every target has an independent
            # limit and one deadline covers its complete chain.
            "max_redirects": 1,
            "headers": {
                "Accept-Encoding": "identity",
                "User-Agent": "xray-e2e-prober/2",
            },
            "limits": limits,
        }
        if self._client_factory is not None:
            return self._client_factory(proxy=proxy_url, **options)
        transport = _ttfb_transport(proxy_url, limits)
        return httpx.AsyncClient(transport=transport, **options)

    async def _request(
        self,
        client: httpx.AsyncClient,
        *,
        url: str,
        body_limit: int,
        follow_redirects: bool,
        max_redirects: int,
        accepted_statuses: frozenset[int],
        read_body: bool,
        observation: _TTFBObservation | None = None,
    ) -> _ResponseData:
        loop = asyncio.get_running_loop()
        started = loop.time() if observation is None else observation.started
        observation = observation or _TTFBObservation(started=started, clock=loop.time)
        body = bytearray()
        bytes_read = 0
        current_url = url
        redirect_count = 0

        async def trace(event_name: str, _: Mapping[str, Any]) -> None:
            if event_name == "http11.receive_response_headers.started":
                observation.armed = True

        token = _ACTIVE_TTFB.set(observation)
        try:
            while True:
                async with client.stream(
                    "GET",
                    current_url,
                    # This must remain false: per-target redirect policy is
                    # enforced by the loop below, not shared client state.
                    follow_redirects=False,
                    extensions={"trace": trace},
                ) as response:
                    status = response.status_code
                    location = response.headers.get("location")
                    if (
                        follow_redirects
                        and status in _REDIRECT_STATUSES
                        and location is not None
                    ):
                        if redirect_count >= max_redirects:
                            raise httpx.TooManyRedirects(
                                "redirect limit exceeded", request=response.request
                            )
                        current_url = _redirect_url(str(response.url), location)
                        redirect_count += 1
                        continue
                    if redirect_count > max_redirects:
                        raise httpx.TooManyRedirects(
                            "redirect limit exceeded", request=response.request
                        )
                    encoding = response.encoding
                    if status in accepted_statuses and read_body:
                        declared_length = response.headers.get("content-length")
                        if declared_length and declared_length.isdecimal():
                            if int(declared_length) > body_limit:
                                raise _BodyTooLarge(int(declared_length))
                        content_encoding = response.headers.get(
                            "content-encoding", "identity"
                        )
                        if content_encoding.casefold().strip() not in {"", "identity"}:
                            # We explicitly request identity. Reject an unsolicited
                            # compressed body instead of letting a decompression bomb
                            # bypass the decoded-byte limit inside HTTPX.
                            raise _InvalidResponse("unexpected content encoding")
                        async for chunk in response.aiter_bytes(chunk_size=8192):
                            bytes_read += len(chunk)
                            if bytes_read > body_limit:
                                raise _BodyTooLarge(bytes_read)
                            body.extend(chunk)
                    break
        finally:
            _ACTIVE_TTFB.reset(token)
        return _ResponseData(
            status_code=status,
            body=bytes(body),
            bytes_read=bytes_read,
            duration_seconds=loop.time() - started,
            ttfb_seconds=observation.elapsed,
            encoding=encoding,
            redirect_count=redirect_count,
        )

    async def check_target(self, client: httpx.AsyncClient, target: Any) -> TargetResult:
        """Check one target. Caller owns the per-cycle HTTPX client."""

        loop = asyncio.get_running_loop()
        started = loop.time()
        request_started: float | None = None
        observation: _TTFBObservation | None = None
        try:
            _validate_target(target, self.request_timeout, self.default_body_limit)
            target_id = _target_id(target)
            url = _absolute_http_url(_field(target, "url"), kind="target")
            statuses = _statuses(target)
            matcher = _matcher(target)
            timeout = _positive_timeout(
                _field(target, "timeout", _field(target, "timeout_seconds")),
                self.request_timeout,
            )
            max_body = _body_limit(
                _field(target, "max_body_bytes"), self.default_body_limit
            )
            follow = bool(_field(target, "follow_redirects", False))
            max_redirects = _redirect_limit(target)
            async with self._semaphore:
                request_started = loop.time()
                observation = _TTFBObservation(started=request_started, clock=loop.time)
                matched: bool | None = None
                # One deadline covers connect, every redirect, the bounded body
                # stream, decoding, and exact/regex evaluation.
                async with asyncio.timeout(timeout):
                    response = await self._request(
                        client,
                        url=url,
                        body_limit=max_body,
                        follow_redirects=follow,
                        max_redirects=max_redirects,
                        accepted_statuses=statuses,
                        read_body=matcher is not None,
                        observation=observation,
                    )
                    if response.status_code in statuses and matcher is not None:
                        matched = await _decode_and_match(
                            response.body,
                            response.encoding,
                            matcher,
                        )
                duration = loop.time() - request_started
            if response.status_code not in statuses:
                return TargetResult(
                    target_id=target_id,
                    state=ReachabilityState.FAILURE,
                    reason=Reason.HTTP_STATUS,
                    http_status=response.status_code,
                    duration_seconds=duration,
                    ttfb_seconds=response.ttfb_seconds,
                    bytes_read=response.bytes_read,
                    error="unexpected HTTP status",
                )
            if matcher is not None:
                assert matched is not None
                if not matched:
                    return TargetResult(
                        target_id=target_id,
                        state=ReachabilityState.FAILURE,
                        reason=Reason.BODY_MISMATCH,
                        http_status=response.status_code,
                        duration_seconds=duration,
                        ttfb_seconds=response.ttfb_seconds,
                        bytes_read=response.bytes_read,
                        error="response body did not match",
                    )
            return TargetResult(
                target_id=target_id,
                state=ReachabilityState.SUCCESS,
                http_status=response.status_code,
                duration_seconds=duration,
                ttfb_seconds=response.ttfb_seconds,
                bytes_read=response.bytes_read,
            )
        except asyncio.CancelledError:
            raise
        except BaseException as exc:
            try:
                target_id = _target_id(target)
            except CheckerConfigurationError:
                target_id = "invalid-target"
            return _target_error_result(
                target_id,
                exc,
                duration=max(
                    0.0,
                    loop.time()
                    - (request_started if request_started is not None else started),
                ),
                ttfb_seconds=observation.elapsed if observation is not None else None,
            )

    async def check_egress(
        self, client: httpx.AsyncClient, assertion: Any
    ) -> EgressResult:
        assertion_id = _field(assertion, "assertion_id")
        if not isinstance(assertion_id, str) or not assertion_id:
            assertion_id = "invalid-assertion"
        if not bool(_field(assertion, "enabled", True)):
            return EgressResult(assertion_id=assertion_id, state=EgressState.DISABLED)
        loop = asyncio.get_running_loop()
        started = loop.time()
        request_started: float | None = None
        try:
            url = _absolute_http_url(_field(assertion, "url"), kind="egress")
            timeout = _positive_timeout(
                _field(assertion, "timeout", _field(assertion, "timeout_seconds")),
                self.request_timeout,
            )
            cidr_values = _field(assertion, "expected_cidrs")
            if not isinstance(cidr_values, Sequence) or isinstance(
                cidr_values, (str, bytes)
            ):
                raise CheckerConfigurationError("expected CIDRs must be a list")
            try:
                networks = tuple(ipaddress.ip_network(item, strict=False) for item in cidr_values)
            except (TypeError, ValueError) as exc:
                raise CheckerConfigurationError("expected CIDR is invalid") from exc
            if not networks:
                raise CheckerConfigurationError("at least one expected CIDR is required")
            async with self._semaphore:
                request_started = loop.time()
                async with asyncio.timeout(timeout):
                    response = await self._request(
                        client,
                        url=url,
                        body_limit=self.egress_body_limit,
                        follow_redirects=False,
                        max_redirects=0,
                        accepted_statuses=frozenset({200}),
                        read_body=True,
                    )
            if response.status_code != 200:
                raise ValueError("unexpected egress response status")
            format_value = _enum_value(_field(assertion, "response_format", "plain"))
            try:
                text = response.body.decode(response.encoding or "utf-8", "strict")
            except (LookupError, UnicodeDecodeError) as exc:
                raise ValueError("invalid egress response encoding") from exc
            if format_value == "plain":
                candidate: Any = text.strip()
            elif format_value == "json":
                field_name = _field(assertion, "json_field")
                if not isinstance(field_name, str) or not field_name:
                    raise CheckerConfigurationError("JSON egress field is required")
                try:
                    candidate = json.loads(text)
                    for part in field_name.split("."):
                        if not isinstance(candidate, Mapping) or part not in candidate:
                            raise KeyError(part)
                        candidate = candidate[part]
                except (json.JSONDecodeError, KeyError) as exc:
                    raise ValueError("invalid egress JSON response") from exc
            else:
                raise CheckerConfigurationError("unsupported egress response format")
            if not isinstance(candidate, str):
                raise ValueError("egress IP field is not a string")
            try:
                observed = ipaddress.ip_address(candidate.strip())
            except ValueError as exc:
                raise ValueError("egress response does not contain one IP") from exc
            matches = any(
                observed.version == network.version and observed in network for network in networks
            )
            return EgressResult(
                assertion_id=assertion_id,
                state=EgressState.MATCH if matches else EgressState.MISMATCH,
                reason=None if matches else Reason.EGRESS_MISMATCH,
                observed_ip=str(observed),
                duration_seconds=response.duration_seconds,
                error=None if matches else "egress IP is outside expected networks",
            )
        except asyncio.CancelledError:
            raise
        except BaseException as exc:
            reason, safe_error = _classify_exception(exc)
            if isinstance(exc, ValueError) and not isinstance(exc, CheckerConfigurationError):
                reason, safe_error = Reason.RESPONSE_INVALID, "egress response is invalid"
            return EgressResult(
                assertion_id=assertion_id,
                state=EgressState.ERROR,
                reason=reason,
                duration_seconds=max(
                    0.0,
                    loop.time()
                    - (request_started if request_started is not None else started),
                ),
                error=safe_error,
            )

    async def check_target_set(
        self,
        target_set: Any,
        socks_port: int,
        *,
        socks_host: str = "127.0.0.1",
        egress_assertions: Sequence[Any] = (),
    ) -> tuple[ReachabilityResult, list[EgressResult]]:
        """Run every enabled target and egress assertion in one isolated cycle."""

        targets_raw = _field(target_set, "targets")
        if not isinstance(targets_raw, Sequence) or isinstance(targets_raw, (str, bytes)):
            raise CheckerConfigurationError("target set targets must be a list")
        targets = [item for item in targets_raw if bool(_field(item, "enabled", True))]
        quorum = _field(target_set, "quorum")
        if (
            isinstance(quorum, bool)
            or not isinstance(quorum, int)
            or quorum < 1
            or quorum > len(targets)
        ):
            raise CheckerConfigurationError("target set quorum is invalid")
        if not bool(_field(target_set, "enabled", True)):
            return (
                ReachabilityResult(
                    state=ReachabilityState.DISABLED,
                    success_count=0,
                    quorum=quorum,
                    targets=[],
                ),
                [
                    EgressResult(
                        assertion_id=str(_field(item, "assertion_id", "invalid-assertion")),
                        state=EgressState.DISABLED,
                    )
                    for item in egress_assertions
                ],
            )
        proxy_url = self._proxy_url(socks_host, socks_port)
        try:
            client_context = self._make_client(proxy_url)
            async with client_context as client:
                target_results = await asyncio.gather(
                    *(self.check_target(client, target) for target in targets)
                )
                # Egress stays independent from quorum but uses the exact same
                # runtime and routing mode as the reachability requests.
                egress_results = await asyncio.gather(
                    *(self.check_egress(client, assertion) for assertion in egress_assertions)
                )
        except asyncio.CancelledError:
            raise
        except BaseException as exc:
            target_results = [
                _target_error_result(_target_id(target), exc) for target in targets
            ]
            reason, safe_error = _classify_exception(exc)
            egress_results = [
                EgressResult(
                    assertion_id=str(_field(item, "assertion_id", "invalid-assertion")),
                    state=EgressState.ERROR,
                    reason=reason,
                    error=safe_error,
                )
                for item in egress_assertions
            ]
        success_count = sum(item.state is ReachabilityState.SUCCESS for item in target_results)
        if success_count >= quorum:
            state = ReachabilityState.SUCCESS
        elif any(item.state is ReachabilityState.ERROR for item in target_results):
            state = ReachabilityState.ERROR
        else:
            state = ReachabilityState.FAILURE
        return (
            ReachabilityResult(
                state=state,
                success_count=success_count,
                quorum=quorum,
                targets=list(target_results),
            ),
            list(egress_results),
        )

    async def run_cycle(
        self,
        check: Any,
        target_set: Any,
        socks_port: int,
        *,
        socks_host: str = "127.0.0.1",
        egress_assertions: Sequence[Any] = (),
    ) -> CycleResult:
        started = datetime.now(timezone.utc)
        reachability, egress = await self.check_target_set(
            target_set,
            socks_port,
            socks_host=socks_host,
            egress_assertions=egress_assertions,
        )
        return CycleResult(
            check_id=str(_field(check, "check_id")),
            generation=str(_field(check, "generation")),
            reachability=reachability,
            egress=egress,
            started_at=started,
            completed_at=datetime.now(timezone.utc),
        )


async def check_target_set(
    target_set: Any,
    socks_port: int,
    *,
    socks_host: str = "127.0.0.1",
    egress_assertions: Sequence[Any] = (),
    request_timeout: float = 15.0,
    max_parallel_requests: int = 8,
) -> tuple[ReachabilityResult, list[EgressResult]]:
    """Convenience wrapper for callers that do not retain a Checker instance."""

    checker = Checker(
        request_timeout=request_timeout,
        max_parallel_requests=max_parallel_requests,
    )
    return await checker.check_target_set(
        target_set,
        socks_port,
        socks_host=socks_host,
        egress_assertions=egress_assertions,
    )


TargetChecker = Checker
E2EChecker = Checker


__all__ = [
    "Checker",
    "CheckerConfigurationError",
    "E2EChecker",
    "TargetChecker",
    "check_target_set",
]
