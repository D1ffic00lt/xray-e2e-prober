from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator

import httpx
import pytest

from xray_e2e_prober import checker as checker_module
from xray_e2e_prober.checker import Checker
from xray_e2e_prober.models import (
    BodyMatchKind,
    BodyMatcher,
    EgressAssertionConfig,
    EgressResponseFormat,
    EgressState,
    ReachabilityState,
    Reason,
    TargetConfig,
    TargetSetConfig,
)


def _factory(handler, captured: list[dict] | None = None):
    transport = httpx.MockTransport(handler)

    def create(**kwargs):
        if captured is not None:
            captured.append(kwargs)
        # A MockTransport intentionally replaces SOCKS only at the test boundary.
        return httpx.AsyncClient(
            transport=transport,
            trust_env=kwargs["trust_env"],
            timeout=kwargs["timeout"],
            follow_redirects=kwargs["follow_redirects"],
            max_redirects=kwargs["max_redirects"],
            headers=kwargs["headers"],
        )

    return create


@pytest.mark.asyncio
async def test_quorum_runs_every_target_and_never_uses_environment_proxy() -> None:
    visited: list[str] = []
    client_options: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        visited.append(request.url.host)
        if request.url.host == "one.test":
            return httpx.Response(200, text="healthy", request=request)
        if request.url.host == "two.test":
            return httpx.Response(204, request=request)
        return httpx.Response(503, text="down", request=request)

    targets = TargetSetConfig(
        target_set_id="set",
        name="set",
        quorum=2,
        targets=[
            TargetConfig(
                target_id="one",
                name="one",
                url="https://one.test/status",
                body=BodyMatcher(kind=BodyMatchKind.EXACT, value="healthy"),
            ),
            TargetConfig(
                target_id="two",
                name="two",
                url="https://two.test/status",
                expected_statuses={204},
            ),
            TargetConfig(target_id="three", name="three", url="https://three.test/status"),
        ],
    )
    checker = Checker(client_factory=_factory(handler, client_options))

    reachability, egress = await checker.check_target_set(targets, 18080)

    assert reachability.state is ReachabilityState.SUCCESS
    assert reachability.success_count == 2
    assert len(reachability.targets) == 3
    assert set(visited) == {"one.test", "two.test", "three.test"}
    assert egress == []
    assert client_options[0]["proxy"] == "socks5://127.0.0.1:18080"
    assert client_options[0]["trust_env"] is False


@pytest.mark.asyncio
async def test_status_and_body_failures_remain_target_diagnostics() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "status.test":
            return httpx.Response(500, text="secret body is never needed", request=request)
        return httpx.Response(200, text="wrong", request=request)

    targets = {
        "quorum": 2,
        "targets": [
            {
                "target_id": "status",
                "url": "https://status.test/",
                "expected_status_codes": [200],
            },
            {
                "target_id": "body",
                "url": "https://body.test/",
                "body_regex": "^right$",
            },
        ],
    }
    checker = Checker(client_factory=_factory(handler))

    reachability, _ = await checker.check_target_set(targets, 18081)

    assert reachability.state is ReachabilityState.FAILURE
    assert [result.reason for result in reachability.targets] == [
        Reason.HTTP_STATUS,
        Reason.BODY_MISMATCH,
    ]
    assert reachability.targets[0].bytes_read == 0


@pytest.mark.asyncio
async def test_catastrophic_regex_timeout_kills_matcher_process(monkeypatch) -> None:
    processes = []
    real_spawn = asyncio.create_subprocess_exec

    async def recording_spawn(*args, **kwargs):
        process = await real_spawn(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(
        "xray_e2e_prober.checker.asyncio.create_subprocess_exec", recording_spawn
    )
    body = "a" * 100_000 + "!"
    checker = Checker(
        request_timeout=0.2,
        client_factory=_factory(
            lambda request: httpx.Response(200, text=body, request=request)
        ),
    )
    reachability, _ = await checker.check_target_set(
        {
            "quorum": 1,
            "targets": [
                {
                    "target_id": "regex-timeout",
                    "url": "https://regex.test/",
                    "body_regex": "^(a+)+$",
                    "timeout": 0.2,
                    "max_body_bytes": 200_000,
                }
            ],
        },
        18081,
    )

    assert reachability.state is ReachabilityState.FAILURE
    assert reachability.targets[0].reason is Reason.TIMEOUT
    assert len(processes) == 1
    assert processes[0].returncode is not None


@pytest.mark.asyncio
async def test_regex_spawn_internal_cancellation_does_not_spin(monkeypatch) -> None:
    async def cancelled_spawn(*args, **kwargs):
        raise asyncio.CancelledError

    monkeypatch.setattr(
        "xray_e2e_prober.checker.asyncio.create_subprocess_exec", cancelled_spawn
    )

    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(checker_module._start_regex_process(), timeout=0.2)


@pytest.mark.asyncio
async def test_regex_wait_internal_cancellation_does_not_spin() -> None:
    class CancelledWaitProcess:
        returncode = 1

        async def wait(self):
            raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(
            checker_module._wait_killed(CancelledWaitProcess()), timeout=0.2
        )


class _DelayedStream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[tuple[float, bytes]]) -> None:
        self.chunks = chunks

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for delay, chunk in self.chunks:
            await asyncio.sleep(delay)
            yield chunk


@pytest.mark.asyncio
async def test_streaming_limit_and_whole_request_deadline() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "large.test":
            stream = _DelayedStream([(0, b"1234"), (0, b"5678")])
        else:
            stream = _DelayedStream([(0, b"ok"), (0.08, b" eventually")])
        return httpx.Response(200, stream=stream, request=request)

    targets = TargetSetConfig(
        target_set_id="bounded",
        name="bounded",
        quorum=2,
        targets=[
            TargetConfig(
                target_id="large",
                name="large",
                url="https://large.test/",
                body=BodyMatcher(kind="exact", value="12345678"),
                max_body_bytes=6,
            ),
            TargetConfig(
                target_id="slow",
                name="slow",
                url="https://slow.test/",
                body=BodyMatcher(kind="exact", value="ok eventually"),
                timeout=0.02,
            ),
        ],
    )
    checker = Checker(client_factory=_factory(handler))

    reachability, _ = await checker.check_target_set(targets, 18082)

    assert reachability.state is ReachabilityState.FAILURE
    by_id = {item.target_id: item for item in reachability.targets}
    assert by_id["large"].reason is Reason.RESPONSE_INVALID
    assert by_id["large"].bytes_read > 6
    assert by_id["slow"].reason is Reason.TIMEOUT
    assert by_id["slow"].duration_seconds < 0.08
    assert by_id["slow"].ttfb_seconds is None


@pytest.mark.asyncio
async def test_redirect_limit_is_per_target() -> None:
    visited: dict[str, list[int]] = {"short.test": [], "long.test": []}

    def handler(request: httpx.Request) -> httpx.Response:
        step = int(request.url.path.strip("/") or "0")
        visited[request.url.host].append(step)
        if step < 3:
            return httpx.Response(
                302,
                headers={"location": f"/{step + 1}"},
                request=request,
            )
        return httpx.Response(200, request=request)

    targets = {
        "quorum": 2,
        "targets": [
            {
                "target_id": "short",
                "url": "https://short.test/0",
                "follow_redirects": True,
                "max_redirects": 2,
                "expected_statuses": [200],
            },
            {
                "target_id": "long",
                "url": "https://long.test/0",
                "follow_redirects": True,
                "max_redirects": 3,
                "expected_statuses": [200],
            },
        ],
    }
    client_options: list[dict] = []
    checker = Checker(client_factory=_factory(handler, client_options))

    reachability, _ = await checker.check_target_set(targets, 18083)

    assert reachability.state is ReachabilityState.FAILURE
    by_id = {item.target_id: item for item in reachability.targets}
    assert by_id["short"].reason is Reason.RESPONSE_INVALID
    assert by_id["long"].state is ReachabilityState.SUCCESS
    assert visited["short.test"] == [0, 1, 2]
    assert visited["long.test"] == [0, 1, 2, 3]
    assert client_options[0]["follow_redirects"] is False
    assert client_options[0]["max_redirects"] == 1


@pytest.mark.asyncio
async def test_unsupported_redirect_url_is_invalid_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            302,
            headers={"location": "file:///etc/passwd"},
            request=request,
        )

    checker = Checker(client_factory=_factory(handler))
    reachability, _ = await checker.check_target_set(
        {
            "quorum": 1,
            "targets": [
                {
                    "target_id": "redirect",
                    "url": "https://redirect.test/",
                    "follow_redirects": True,
                    "max_redirects": 1,
                }
            ],
        },
        18083,
    )

    assert reachability.state is ReachabilityState.FAILURE
    assert reachability.targets[0].reason is Reason.RESPONSE_INVALID


@pytest.mark.asyncio
async def test_total_deadline_includes_body_matching(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_match = checker_module._decode_and_match

    async def slow_match(
        body: bytes, encoding: str | None, matcher: tuple[str, str]
    ) -> bool:
        await asyncio.sleep(0.08)
        return await original_match(body, encoding, matcher)

    monkeypatch.setattr(checker_module, "_decode_and_match", slow_match)
    checker = Checker(
        client_factory=_factory(lambda request: httpx.Response(200, text="ok", request=request))
    )

    reachability, _ = await checker.check_target_set(
        {
            "quorum": 1,
            "targets": [
                {
                    "target_id": "slow-match",
                    "url": "https://matcher.test/",
                    "timeout": 0.02,
                    "body_regex": "^ok$",
                }
            ],
        },
        18083,
    )

    result = reachability.targets[0]
    assert result.reason is Reason.TIMEOUT
    assert result.duration_seconds is not None
    assert 0.015 <= result.duration_seconds < 0.07


@pytest.mark.asyncio
async def test_egress_plain_and_json_ipv4_ipv6_are_independent_from_quorum() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "target.test":
            return httpx.Response(200, request=request)
        if request.url.host == "plain.test":
            return httpx.Response(200, text="203.0.113.19\n", request=request)
        return httpx.Response(200, json={"client": {"ip": "2001:db8::7"}}, request=request)

    targets = TargetSetConfig(
        target_set_id="egress",
        name="egress",
        quorum=1,
        targets=[TargetConfig(target_id="target", name="target", url="https://target.test/")],
    )
    assertions = [
        EgressAssertionConfig(
            assertion_id="plain",
            name="plain",
            url="https://plain.test/",
            expected_cidrs=["203.0.113.0/24"],
        ),
        EgressAssertionConfig(
            assertion_id="json",
            name="json",
            url="https://json.test/",
            response_format=EgressResponseFormat.JSON,
            json_field="client.ip",
            expected_cidrs=["2001:db9::/32"],
        ),
    ]
    checker = Checker(client_factory=_factory(handler))

    reachability, egress = await checker.check_target_set(
        targets, 18084, egress_assertions=assertions
    )

    assert reachability.state is ReachabilityState.SUCCESS
    assert [item.state for item in egress] == [EgressState.MATCH, EgressState.MISMATCH]
    assert egress[1].reason is Reason.EGRESS_MISMATCH
    assert egress[1].observed_ip == "2001:db8::7"


@pytest.mark.asyncio
async def test_invalid_egress_response_is_error_not_mismatch() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "target.test":
            return httpx.Response(200, request=request)
        return httpx.Response(200, text="not an ip", request=request)

    checker = Checker(client_factory=_factory(handler))
    reachability, egress = await checker.check_target_set(
        {
            "quorum": 1,
            "targets": [{"target_id": "target", "url": "https://target.test/"}],
        },
        18085,
        egress_assertions=[
            {
                "assertion_id": "bad",
                "url": "https://echo.test/",
                "expected_cidrs": ["10.0.0.0/8"],
                "response_format": "plain",
            }
        ],
    )

    assert reachability.state is ReachabilityState.SUCCESS
    assert egress[0].state is EgressState.ERROR
    assert egress[0].reason is Reason.RESPONSE_INVALID


@pytest.mark.asyncio
async def test_non_loopback_socks_endpoint_is_rejected() -> None:
    checker = Checker(client_factory=_factory(lambda request: httpx.Response(200, request=request)))
    with pytest.raises(ValueError, match="loopback"):
        await checker.check_target_set(
            {"quorum": 1, "targets": [{"target_id": "a", "url": "https://a.test/"}]},
            1080,
            socks_host="192.0.2.1",
        )


@pytest.mark.asyncio
async def test_real_socks_transport_sends_destination_as_domain() -> None:
    seen_domains: list[str] = []

    async def http_target(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await reader.readuntil(b"\r\n\r\n")
            await asyncio.sleep(0.06)
            writer.write(b"HTTP/1.")
            await writer.drain()
            await asyncio.sleep(0.18)
            writer.write(b"1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n")
            await writer.drain()
            await asyncio.sleep(0.12)
            writer.write(b"ok")
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    target_server = await asyncio.start_server(http_target, "127.0.0.1", 0)
    target_port = target_server.sockets[0].getsockname()[1]

    async def socks_proxy(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        upstream_writer: asyncio.StreamWriter | None = None
        try:
            version, method_count = await reader.readexactly(2)
            assert version == 5
            await reader.readexactly(method_count)
            writer.write(b"\x05\x00")
            await writer.drain()
            version, command, reserved, address_type = await reader.readexactly(4)
            assert (version, command, reserved, address_type) == (5, 1, 0, 3)
            domain_length = (await reader.readexactly(1))[0]
            domain = (await reader.readexactly(domain_length)).decode("ascii")
            await reader.readexactly(2)  # requested port
            seen_domains.append(domain)
            upstream_reader, upstream_writer = await asyncio.open_connection(
                "127.0.0.1", target_port
            )
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()

            async def copy(source: asyncio.StreamReader, destination: asyncio.StreamWriter) -> None:
                while chunk := await source.read(8192):
                    destination.write(chunk)
                    await destination.drain()

            await asyncio.gather(copy(reader, upstream_writer), copy(upstream_reader, writer))
        finally:
            writer.close()
            if upstream_writer is not None:
                upstream_writer.close()
            await asyncio.gather(
                writer.wait_closed(),
                *(
                    [upstream_writer.wait_closed()]
                    if upstream_writer is not None
                    else []
                ),
                return_exceptions=True,
            )

    socks_server = await asyncio.start_server(socks_proxy, "127.0.0.1", 0)
    socks_port = socks_server.sockets[0].getsockname()[1]
    try:
        reachability, _ = await Checker().check_target_set(
            {
                "quorum": 1,
                "targets": [
                    {
                        "target_id": "domain",
                        "url": f"http://only-xray-resolves.invalid:{target_port}/",
                        "body_exact": "ok",
                    }
                ],
            },
            socks_port,
        )
    finally:
        socks_server.close()
        target_server.close()
        await asyncio.gather(socks_server.wait_closed(), target_server.wait_closed())

    assert reachability.state is ReachabilityState.SUCCESS
    assert seen_domains == ["only-xray-resolves.invalid"]
    result = reachability.targets[0]
    assert result.ttfb_seconds is not None
    assert result.ttfb_seconds >= 0.04
    assert result.duration_seconds - result.ttfb_seconds >= 0.25
