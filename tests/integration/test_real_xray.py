"""Opt-in end-to-end checks against the Xray binary shipped in the image.

The test topology never needs the public network.  A tiny HTTP origin, the
VLESS server, the REALITY camouflage endpoint, and the prober's SOCKS client
all run in this process/container.  Credentials, certificates, and X25519
keys are generated for each test and disappear with pytest's temporary
directory.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import uuid
from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

import pytest

from xray_e2e_prober.checker import Checker
from xray_e2e_prober.importers import import_content, vless_uri_to_outbound
from xray_e2e_prober.inventory import CompiledCheck
from xray_e2e_prober.models import (
    BodyMatchKind,
    BodyMatcher,
    CheckDefinition,
    CheckMode,
    EgressAssertionConfig,
    EgressState,
    ReachabilityState,
    SourceFormat,
    TargetConfig,
    TargetSetConfig,
)
from xray_e2e_prober.runtime import XrayRuntimeManager
from xray_e2e_prober.runtime_pool import RuntimePool


_RUN_INTEGRATION = os.environ.get("XRAY_INTEGRATION") == "1"
_XRAY_BINARY = os.environ.get("XRAY_BINARY")
_EXPECTED_XRAY_VERSION = os.environ.get("XRAY_EXPECTED_VERSION", "26.3.27")
_RESPONSE_BODY = b"xray-e2e-integration-ok\n"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not _RUN_INTEGRATION,
        reason="set XRAY_INTEGRATION=1 to run real-Xray integration tests",
    ),
    pytest.mark.skipif(
        not _XRAY_BINARY or shutil.which(_XRAY_BINARY) is None,
        reason="XRAY_BINARY must name an installed Xray executable",
    ),
]


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("0.0.0.0", 0))
        return int(listener.getsockname()[1])


async def _run_command(*arguments: str) -> tuple[str, str]:
    process = await asyncio.create_subprocess_exec(
        *arguments,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_bytes, stderr_bytes = await asyncio.wait_for(process.communicate(), timeout=10)
    stdout = stdout_bytes.decode("utf-8", "replace")
    stderr = stderr_bytes.decode("utf-8", "replace")
    if process.returncode != 0:
        pytest.fail(
            f"command {Path(arguments[0]).name!r} exited {process.returncode}: "
            f"{(stderr or stdout)[-1000:]}"
        )
    return stdout, stderr


async def _ephemeral_certificate(binary: str, directory: Path) -> dict[str, list[str]]:
    stdout, _ = await _run_command(
        binary,
        "tls",
        "cert",
        "--domain=localhost",
        "--expire=1h",
    )
    beginning = stdout.find("{")
    if beginning < 0:
        pytest.fail("Xray tls cert did not return JSON")
    generated = json.loads(stdout[beginning:])
    certificate = generated.get("certificate")
    key = generated.get("key")
    if not (
        isinstance(certificate, list)
        and certificate
        and all(isinstance(line, str) for line in certificate)
        and isinstance(key, list)
        and key
        and all(isinstance(line, str) for line in key)
    ):
        pytest.fail("Xray tls cert returned an unexpected document")

    # Python's local TLS camouflage endpoint needs filesystem-backed PEMs.
    # They live only below pytest's private temporary directory.
    certificate_path = directory / "ephemeral-certificate.pem"
    key_path = directory / "ephemeral-key.pem"
    certificate_path.write_text("\n".join(certificate) + "\n", encoding="ascii")
    # Xray 26.3.27 emits an EC key with legacy ``RSA PRIVATE KEY`` labels.
    # Xray accepts that output directly, while OpenSSL correctly expects the
    # matching EC label when the same ephemeral key is loaded by Python.
    openssl_key = [line.replace("RSA PRIVATE KEY", "EC PRIVATE KEY") for line in key]
    key_path.write_text("\n".join(openssl_key) + "\n", encoding="ascii")
    certificate_path.chmod(0o600)
    key_path.chmod(0o600)
    return {
        "certificate": certificate,
        "key": key,
        "certificate_path": [os.fspath(certificate_path)],
        "key_path": [os.fspath(key_path)],
    }


async def _ephemeral_x25519(binary: str) -> tuple[str, str]:
    stdout, _ = await _run_command(binary, "x25519")
    private_match = re.search(r"^PrivateKey:\s*(\S+)\s*$", stdout, re.MULTILINE)
    public_match = re.search(
        r"^(?:Password \(PublicKey\)|PublicKey):\s*(\S+)\s*$",
        stdout,
        re.MULTILINE,
    )
    if private_match is None or public_match is None:
        pytest.fail("Xray x25519 returned an unexpected document")
    return private_match.group(1), public_match.group(1)


async def _wait_for_listener(
    process: asyncio.subprocess.Process,
    host: str,
    port: int,
    *,
    timeout: float = 8.0,
) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if process.returncode is not None:
            stdout, stderr = await process.communicate()
            detail = (stderr or stdout).decode("utf-8", "replace")[-1500:]
            pytest.fail(f"Xray server exited before readiness: {detail}")
        writer: asyncio.StreamWriter | None = None
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=0.25
            )
            return
        except (OSError, asyncio.TimeoutError):
            await asyncio.sleep(0.05)
        finally:
            if writer is not None:
                writer.close()
                await writer.wait_closed()
    pytest.fail("Xray server did not open its local listener")


async def _stop_process(process: asyncio.subprocess.Process) -> tuple[str, str]:
    if process.returncode is None:
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=3)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
    stdout_bytes, stderr_bytes = await process.communicate()
    return (
        stdout_bytes.decode("utf-8", "replace"),
        stderr_bytes.decode("utf-8", "replace"),
    )


@asynccontextmanager
async def _running_xray_server(
    binary: str,
    config: Mapping[str, Any],
    config_path: Path,
    host: str,
    port: int,
) -> AsyncIterator[asyncio.subprocess.Process]:
    config_path.write_text(
        json.dumps(config, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8",
    )
    config_path.chmod(0o600)
    await _run_command(binary, "run", "-test", "-config", os.fspath(config_path))
    process = await asyncio.create_subprocess_exec(
        binary,
        "run",
        "-config",
        os.fspath(config_path),
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    try:
        await _wait_for_listener(process, host, port)
        yield process
    finally:
        stdout, stderr = await _stop_process(process)
        if process.returncode not in {0, -15}:
            pytest.fail(f"Xray server shutdown failed: {(stderr or stdout)[-1500:]}")


@asynccontextmanager
async def _http_origin(
    *,
    bind_host: str = "127.0.0.1",
    ssl_context: ssl.SSLContext | None = None,
) -> AsyncIterator[int]:
    async def respond(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=3)
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                + f"Content-Length: {len(_RESPONSE_BODY)}\r\n".encode("ascii")
                + b"Content-Type: text/plain; charset=utf-8\r\n"
                + b"Connection: close\r\n\r\n"
                + _RESPONSE_BODY
            )
            await writer.drain()
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    server = await asyncio.start_server(
        respond,
        host=bind_host,
        port=0,
        ssl=ssl_context,
    )
    sockets = server.sockets or []
    if len(sockets) != 1:
        server.close()
        await server.wait_closed()
        pytest.fail("local HTTP test origin did not expose one listener")
    try:
        yield int(sockets[0].getsockname()[1])
    finally:
        server.close()
        await server.wait_closed()


@asynccontextmanager
async def _peer_ip_origin(*, bind_host: str = "0.0.0.0") -> AsyncIterator[int]:
    """Return the TCP peer IP so tests can prove which Xray outbound was used."""

    async def respond(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=3)
            peer = writer.get_extra_info("peername")
            if not isinstance(peer, tuple) or not peer:
                raise ConnectionError("peer address is unavailable")
            body = f"{peer[0]}\n".encode("ascii")
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                + f"Content-Length: {len(body)}\r\n".encode("ascii")
                + b"Content-Type: text/plain; charset=utf-8\r\n"
                + b"Connection: close\r\n\r\n"
                + body
            )
            await writer.drain()
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    server = await asyncio.start_server(respond, host=bind_host, port=0)
    sockets = server.sockets or []
    if len(sockets) != 1:
        server.close()
        await server.wait_closed()
        pytest.fail("local peer-IP origin did not expose one listener")
    try:
        yield int(sockets[0].getsockname()[1])
    finally:
        server.close()
        await server.wait_closed()


def _tls_context(certificate: Mapping[str, Sequence[str]]) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(
        certificate["certificate_path"][0],
        certificate["key_path"][0],
    )
    context.set_alpn_protocols(["http/1.1"])
    return context


def _server_config(
    *,
    server_port: int,
    user_id: str,
    transport: str,
    security: str,
    certificate: Mapping[str, Sequence[str]],
    reality_private_key: str | None,
    reality_target_port: int | None,
    short_id: str,
    outbound_send_through: str | None = None,
) -> dict[str, Any]:
    stream: dict[str, Any] = {"network": transport, "security": security}
    if transport == "raw":
        stream["rawSettings"] = {"header": {"type": "none"}}
    else:
        stream["xhttpSettings"] = {"path": "/integration-xhttp", "mode": "stream-one"}

    if security == "tls":
        stream["tlsSettings"] = {
            "alpn": ["http/1.1"],
            "certificates": [
                {
                    "certificate": list(certificate["certificate"]),
                    "key": list(certificate["key"]),
                }
            ],
        }
    else:
        assert reality_private_key is not None
        assert reality_target_port is not None
        stream["realitySettings"] = {
            "target": f"127.0.0.1:{reality_target_port}",
            "serverNames": ["localhost"],
            "privateKey": reality_private_key,
            "shortIds": [short_id],
        }

    direct_outbound: dict[str, Any] = {"tag": "direct", "protocol": "freedom"}
    if outbound_send_through is not None:
        direct_outbound["sendThrough"] = outbound_send_through

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "integration-vless",
                "listen": "0.0.0.0",
                "port": server_port,
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": user_id}],
                    "decryption": "none",
                },
                "streamSettings": stream,
            }
        ],
        "outbounds": [direct_outbound],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {
                    "type": "field",
                    "inboundTag": ["integration-vless"],
                    "outboundTag": "direct",
                }
            ],
        },
    }


def _vless_uri(
    *,
    server_host: str,
    server_port: int,
    user_id: str,
    transport: str,
    security: str,
    reality_public_key: str | None,
    short_id: str,
) -> str:
    parameters: list[tuple[str, str]] = [
        ("encryption", "none"),
        ("security", security),
        ("type", transport),
        ("sni", "localhost"),
    ]
    if security == "tls":
        # Older URI producers commonly include this strict-value boilerplate.
        # The importer must consume it without emitting Xray's removed field;
        # the real config-test performed below enforces that compatibility.
        parameters.append(("allowInsecure", "false"))
        parameters.append(("alpn", "http/1.1"))
    else:
        assert reality_public_key is not None
        parameters.extend(
            [
                ("fp", "chrome"),
                ("pbk", reality_public_key),
                ("sid", short_id),
                ("spx", "/"),
            ]
        )
    if transport == "raw":
        parameters.append(("headerType", "none"))
    else:
        parameters.extend(
            [
                ("path", "/integration-xhttp"),
                ("mode", "stream-one"),
            ]
        )
    query = urlencode(parameters, quote_via=quote)
    return f"vless://{user_id}@{server_host}:{server_port}?{query}#integration"


def _private_server_host() -> str:
    host = os.environ.get("XRAY_TEST_SERVER_HOST") or socket.gethostname()
    if host.casefold() in {"localhost", "localhost.localdomain"} or host.casefold().endswith(
        (".localhost", ".local", ".localdomain")
    ):
        pytest.fail(
            "XRAY_TEST_SERVER_HOST must be a non-local-looking alias mapped to this host; "
            "the runtime intentionally rejects localhost endpoint names"
        )
    try:
        resolved = socket.gethostbyname(host)
        address = ipaddress.ip_address(resolved)
    except (OSError, ValueError) as exc:
        pytest.skip(f"local Xray server alias cannot be resolved: {exc}")
    if address.is_global or address.is_multicast or address.is_unspecified:
        pytest.fail("XRAY_TEST_SERVER_HOST must resolve to a local-only address")
    return host


@pytest.mark.asyncio
async def test_integration_binary_is_the_pinned_xray_release() -> None:
    assert _XRAY_BINARY is not None
    stdout, _ = await _run_command(_XRAY_BINARY, "version")
    assert f"Xray {_EXPECTED_XRAY_VERSION}" in stdout.splitlines()[0]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("transport", "security", "credential_fault"),
    [
        pytest.param("raw", "tls", None, id="vless-raw-tls"),
        pytest.param("raw", "reality", None, id="vless-raw-reality"),
        pytest.param("xhttp", "tls", None, id="vless-xhttp-tls"),
        pytest.param("xhttp", "reality", None, id="vless-xhttp-reality"),
        pytest.param("raw", "tls", "uuid", id="vless-wrong-uuid"),
        pytest.param("raw", "reality", "reality-key", id="vless-wrong-reality-key"),
    ],
)
async def test_imported_vless_end_to_end_through_real_xray(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    transport: str,
    security: str,
    credential_fault: str | None,
) -> None:
    assert _XRAY_BINARY is not None
    server_host = _private_server_host()
    server_port = _free_tcp_port()
    user_id = str(uuid.uuid4())
    short_id = os.urandom(8).hex()
    certificate = await _ephemeral_certificate(_XRAY_BINARY, tmp_path)
    # Go's SystemCertPool honors SSL_CERT_FILE on Linux.  Trusting this one-use
    # root lets the test exercise strict TLS verification without the removed
    # allowInsecure switch or a committed test CA.
    monkeypatch.setenv("SSL_CERT_FILE", certificate["certificate_path"][0])
    private_key: str | None = None
    public_key: str | None = None
    if security == "reality":
        private_key, public_key = await _ephemeral_x25519(_XRAY_BINARY)
    client_user_id = str(uuid.uuid4()) if credential_fault == "uuid" else user_id
    if credential_fault == "reality-key":
        _, public_key = await _ephemeral_x25519(_XRAY_BINARY)

    # The target remains local-only, but is expressed as a hostname so the
    # SOCKS request exercises Xray-side DNS instead of application-side resolve.
    async with _http_origin(bind_host="0.0.0.0") as origin_port:
        if security == "reality":
            camouflage = _http_origin(ssl_context=_tls_context(certificate))
        else:
            camouflage = _null_port()
        async with camouflage as reality_target_port:
            server_config = _server_config(
                server_port=server_port,
                user_id=user_id,
                transport=transport,
                security=security,
                certificate=certificate,
                reality_private_key=private_key,
                reality_target_port=reality_target_port,
                short_id=short_id,
            )
            uri = _vless_uri(
                server_host=server_host,
                server_port=server_port,
                user_id=client_user_id,
                transport=transport,
                security=security,
                reality_public_key=public_key,
                short_id=short_id,
            )
            imported = import_content(
                uri,
                SourceFormat.VLESS,
                source_id="integration_source",
            )
            assert len(imported) == 1
            assert imported[0].transport == transport
            assert imported[0].security == security

            async with _running_xray_server(
                _XRAY_BINARY,
                server_config,
                tmp_path / "xray-server.json",
                server_host,
                server_port,
            ):
                manager = XrayRuntimeManager(
                    _XRAY_BINARY,
                    runtime_dir=tmp_path / "client-runtimes",
                    startup_timeout=8,
                    config_test_timeout=8,
                )
                runtime = None
                try:
                    runtime = await manager.start_for(imported[0], CheckMode.CONNECTION)
                    target_set = TargetSetConfig(
                        target_set_id="integration_targets",
                        name="Integration targets",
                        targets=[
                            TargetConfig(
                                target_id="local_origin",
                                name="Local HTTP origin",
                                url=f"http://{server_host}:{origin_port}/probe",
                                timeout=3 if credential_fault else 8,
                                body=BodyMatcher(
                                    kind=BodyMatchKind.EXACT,
                                    value=_RESPONSE_BODY.decode("ascii"),
                                ),
                            )
                        ],
                        quorum=1,
                    )
                    reachability, egress = await Checker(
                        request_timeout=8,
                        max_parallel_requests=1,
                    ).check_target_set(target_set, runtime.socks_port)
                    assert egress == []
                    diagnostic = (
                        transport,
                        security,
                        credential_fault,
                        reachability.model_dump(mode="json"),
                        runtime.diagnostics,
                    )
                    if credential_fault is None:
                        assert reachability.state is ReachabilityState.SUCCESS, diagnostic
                        assert reachability.success_count == 1
                        assert reachability.targets[0].http_status == 200
                        assert reachability.targets[0].bytes_read == len(_RESPONSE_BODY)
                    else:
                        # SOCKS cannot reliably distinguish a bad VLESS UUID
                        # from a bad REALITY key.  What matters here is that
                        # neither failure can become a direct-path success.
                        assert reachability.state is not ReachabilityState.SUCCESS, diagnostic
                        assert reachability.success_count == 0
                        assert reachability.targets[0].reason is not None
                finally:
                    if runtime is not None:
                        await runtime.stop()
                    await manager.close()


@pytest.mark.asyncio
async def test_profile_routing_and_connection_mode_use_the_intended_outbound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Prove routing with observable loopback source IPs, not config inspection."""

    assert _XRAY_BINARY is not None
    server_host = _private_server_host()
    server_port = _free_tcp_port()
    user_id = str(uuid.uuid4())
    short_id = os.urandom(8).hex()
    certificate = await _ephemeral_certificate(_XRAY_BINARY, tmp_path)
    monkeypatch.setenv("SSL_CERT_FILE", certificate["certificate_path"][0])

    uri = _vless_uri(
        server_host=server_host,
        server_port=server_port,
        user_id=user_id,
        transport="raw",
        security="tls",
        reality_public_key=None,
        short_id=short_id,
    )
    vless_outbound = vless_uri_to_outbound(uri, tag="via-vless")

    async with (
        _peer_ip_origin() as direct_origin_port,
        _peer_ip_origin() as vless_origin_port,
    ):
        profile = {
            "inbounds": [
                {
                    "tag": "profile-client",
                    "listen": "127.0.0.1",
                    "port": 1080,
                    "protocol": "socks",
                    "settings": {"auth": "noauth", "udp": False},
                }
            ],
            "outbounds": [
                vless_outbound,
                {"tag": "direct", "protocol": "freedom"},
            ],
            "routing": {
                "domainStrategy": "AsIs",
                "rules": [
                    {
                        "type": "field",
                        "inboundTag": ["profile-client"],
                        "port": str(direct_origin_port),
                        "outboundTag": "direct",
                    },
                    {
                        "type": "field",
                        "inboundTag": ["profile-client"],
                        "outboundTag": "via-vless",
                    },
                ],
            },
        }
        imported = import_content(
            json.dumps(profile),
            SourceFormat.XRAY_JSON,
            source_id="profile_source",
        )[0]
        server_config = _server_config(
            server_port=server_port,
            user_id=user_id,
            transport="raw",
            security="tls",
            certificate=certificate,
            reality_private_key=None,
            reality_target_port=None,
            short_id=short_id,
            # Linux owns the whole 127/8 loopback range.  The server-side
            # source address makes a VLESS hop distinguishable from direct.
            outbound_send_through="127.0.0.2",
        )
        async with _running_xray_server(
            _XRAY_BINARY,
            server_config,
            tmp_path / "routing-server.json",
            server_host,
            server_port,
        ):
            manager = XrayRuntimeManager(
                _XRAY_BINARY,
                runtime_dir=tmp_path / "routing-runtimes",
                startup_timeout=8,
                config_test_timeout=8,
            )
            profile_runtime = None
            connection_runtime = None
            bad_runtime = None
            try:
                profile_runtime = await manager.start_for(imported, CheckMode.PROFILE)
                profile_targets = TargetSetConfig(
                    target_set_id="profile_routes",
                    name="Profile route assertions",
                    targets=[
                        TargetConfig(
                            target_id="direct_route",
                            name="Direct route",
                            url=f"http://{server_host}:{direct_origin_port}/direct",
                            body=BodyMatcher(
                                kind=BodyMatchKind.EXACT,
                                value="127.0.0.1\n",
                            ),
                        ),
                        TargetConfig(
                            target_id="vless_route",
                            name="VLESS route",
                            url=f"http://{server_host}:{vless_origin_port}/vless",
                            body=BodyMatcher(
                                kind=BodyMatchKind.EXACT,
                                value="127.0.0.2\n",
                            ),
                        ),
                    ],
                    quorum=2,
                )
                reachability, _ = await Checker(
                    request_timeout=8,
                    max_parallel_requests=2,
                ).check_target_set(profile_targets, profile_runtime.socks_port)
                assert reachability.state is ReachabilityState.SUCCESS
                assert [item.state for item in reachability.targets] == [
                    ReachabilityState.SUCCESS,
                    ReachabilityState.SUCCESS,
                ]
                await profile_runtime.stop()
                profile_runtime = None

                # Connection mode must replace the profile's direct-port rule.
                # Both the target and egress assertion therefore emerge from
                # the server-side 127.0.0.2 address through selected VLESS.
                connection_runtime = await manager.start_for(
                    imported,
                    CheckMode.CONNECTION,
                    outbound_tag="via-vless",
                )
                connection_targets = TargetSetConfig(
                    target_set_id="connection_route",
                    name="Connection route assertion",
                    targets=[
                        TargetConfig(
                            target_id="forced_vless",
                            name="Forced VLESS route",
                            url=f"http://{server_host}:{direct_origin_port}/forced",
                            body=BodyMatcher(
                                kind=BodyMatchKind.EXACT,
                                value="127.0.0.2\n",
                            ),
                        )
                    ],
                    quorum=1,
                )
                egress_assertion = EgressAssertionConfig(
                    assertion_id="real_vless_egress",
                    name="Real VLESS egress source",
                    url=f"http://{server_host}:{vless_origin_port}/egress",
                    expected_cidrs=["127.0.0.2/32"],
                )
                reachability, egress = await Checker(
                    request_timeout=8,
                    max_parallel_requests=2,
                ).check_target_set(
                    connection_targets,
                    connection_runtime.socks_port,
                    egress_assertions=[egress_assertion],
                )
                assert reachability.state is ReachabilityState.SUCCESS
                assert egress[0].state is EgressState.MATCH
                assert egress[0].observed_ip == "127.0.0.2"
                await connection_runtime.stop()
                connection_runtime = None

                # A bad selected credential must not fall back to the direct
                # outbound retained in the imported profile.
                bad_uri = _vless_uri(
                    server_host=server_host,
                    server_port=server_port,
                    user_id=str(uuid.uuid4()),
                    transport="raw",
                    security="tls",
                    reality_public_key=None,
                    short_id=short_id,
                )
                bad_profile = dict(profile)
                bad_profile["outbounds"] = [
                    vless_uri_to_outbound(bad_uri, tag="via-vless"),
                    {"tag": "direct", "protocol": "freedom"},
                ]
                bad_imported = import_content(
                    json.dumps(bad_profile),
                    SourceFormat.XRAY_JSON,
                    source_id="profile_source",
                )[0]
                bad_runtime = await manager.start_for(
                    bad_imported,
                    CheckMode.CONNECTION,
                    outbound_tag="via-vless",
                )
                failed, _ = await Checker(
                    request_timeout=3,
                    max_parallel_requests=1,
                ).check_target_set(connection_targets, bad_runtime.socks_port)
                assert failed.state is not ReachabilityState.SUCCESS
                assert failed.success_count == 0
            finally:
                for runtime in (profile_runtime, connection_runtime, bad_runtime):
                    if runtime is not None:
                        await runtime.stop()
                await manager.close()


def _compiled_connection(
    uri: str,
    *,
    generation: str,
    target_set: TargetSetConfig,
) -> CompiledCheck:
    imported = import_content(
        uri,
        SourceFormat.VLESS,
        source_id="credential_source",
    )[0]
    entry = imported.to_entry_record("credential_entry", generation)
    definition = CheckDefinition(
        check_id=f"credential_check_{generation}",
        entry_id=entry.entry_id,
        source_id=entry.source_id,
        target_set_id=target_set.target_set_id,
        mode=CheckMode.CONNECTION,
        generation=generation,
    )
    return CompiledCheck(
        definition=definition,
        entry=entry,
        target_set=target_set,
        egress_assertions=(),
        assignment_reason="integration",
    )


@pytest.mark.asyncio
async def test_fresh_lifecycle_does_not_reuse_a_session_after_credential_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _XRAY_BINARY is not None
    server_host = _private_server_host()
    server_port = _free_tcp_port()
    user_id = str(uuid.uuid4())
    short_id = os.urandom(8).hex()
    certificate = await _ephemeral_certificate(_XRAY_BINARY, tmp_path)
    monkeypatch.setenv("SSL_CERT_FILE", certificate["certificate_path"][0])
    server_config = _server_config(
        server_port=server_port,
        user_id=user_id,
        transport="raw",
        security="tls",
        certificate=certificate,
        reality_private_key=None,
        reality_target_port=None,
        short_id=short_id,
    )
    target_set = TargetSetConfig(
        target_set_id="credential_targets",
        name="Credential targets",
        targets=[
            TargetConfig(
                target_id="credential_origin",
                name="Credential origin",
                url="http://placeholder.invalid/",
                timeout=3,
            )
        ],
        quorum=1,
    )

    async with _http_origin(bind_host="0.0.0.0") as origin_port:
        target_set.targets[0].url = f"http://{server_host}:{origin_port}/credential"
        async with _running_xray_server(
            _XRAY_BINARY,
            server_config,
            tmp_path / "credential-server.json",
            server_host,
            server_port,
        ):
            good_uri = _vless_uri(
                server_host=server_host,
                server_port=server_port,
                user_id=user_id,
                transport="raw",
                security="tls",
                reality_public_key=None,
                short_id=short_id,
            )
            bad_uri = _vless_uri(
                server_host=server_host,
                server_port=server_port,
                user_id=str(uuid.uuid4()),
                transport="raw",
                security="tls",
                reality_public_key=None,
                short_id=short_id,
            )
            good_check = _compiled_connection(
                good_uri,
                generation="generation_1",
                target_set=target_set,
            )
            bad_check = _compiled_connection(
                bad_uri,
                generation="generation_2",
                target_set=target_set,
            )
            manager = XrayRuntimeManager(
                _XRAY_BINARY,
                runtime_dir=tmp_path / "fresh-runtimes",
                startup_timeout=8,
                config_test_timeout=8,
            )
            pool = RuntimePool(manager, limit=1, observatory_warmup_delay=0)
            checker = Checker(request_timeout=3, max_parallel_requests=1)
            first_runtime = None
            try:
                async with pool.acquire(good_check) as runtime:
                    first_runtime = runtime
                    first_path = runtime.config_path
                    first, _ = await checker.check_target_set(
                        target_set,
                        runtime.socks_port,
                    )
                    assert first.state is ReachabilityState.SUCCESS
                assert first_runtime is not None
                assert not first_runtime.alive
                assert manager.active == ()

                async with pool.acquire(bad_check) as runtime:
                    assert runtime is not first_runtime
                    assert runtime.config_path != first_path
                    second, _ = await checker.check_target_set(
                        target_set,
                        runtime.socks_port,
                    )
                    assert second.state is not ReachabilityState.SUCCESS
                    assert second.success_count == 0
                assert manager.active == ()
            finally:
                await pool.close()


@pytest.mark.asyncio
async def test_real_observatory_least_ping_profile_honors_fixed_live_warmup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise the deterministic one-candidate leastPing subset on real Xray."""

    assert _XRAY_BINARY is not None
    server_host = _private_server_host()
    server_port = _free_tcp_port()
    user_id = str(uuid.uuid4())
    short_id = os.urandom(8).hex()
    certificate = await _ephemeral_certificate(_XRAY_BINARY, tmp_path)
    monkeypatch.setenv("SSL_CERT_FILE", certificate["certificate_path"][0])
    server_config = _server_config(
        server_port=server_port,
        user_id=user_id,
        transport="raw",
        security="tls",
        certificate=certificate,
        reality_private_key=None,
        reality_target_port=None,
        short_id=short_id,
    )

    async with _http_origin(bind_host="0.0.0.0") as origin_port:
        uri = _vless_uri(
            server_host=server_host,
            server_port=server_port,
            user_id=user_id,
            transport="raw",
            security="tls",
            reality_public_key=None,
            short_id=short_id,
        )
        profile = {
            "inbounds": [
                {
                    "tag": "profile-client",
                    "listen": "127.0.0.1",
                    "port": 1080,
                    "protocol": "socks",
                    "settings": {"auth": "noauth", "udp": False},
                }
            ],
            "outbounds": [vless_uri_to_outbound(uri, tag="observed-vless")],
            "routing": {
                "domainStrategy": "AsIs",
                "rules": [
                    {
                        "type": "field",
                        "inboundTag": ["profile-client"],
                        "balancerTag": "single-vless",
                    }
                ],
                "balancers": [
                    {
                        "tag": "single-vless",
                        "selector": ["observed-vless"],
                        "strategy": {"type": "leastPing"},
                    }
                ],
            },
            "observatory": {
                "subjectSelector": ["observed-vless"],
                "probeUrl": f"http://{server_host}:{origin_port}/observatory",
                "probeInterval": "100ms",
                "enableConcurrency": False,
            },
        }
        imported = import_content(
            json.dumps(profile),
            SourceFormat.XRAY_JSON,
            source_id="observatory_source",
        )[0]
        target_set = TargetSetConfig(
            target_set_id="observatory_targets",
            name="Observatory targets",
            targets=[
                TargetConfig(
                    target_id="observatory_origin",
                    name="Observatory origin",
                    url=f"http://{server_host}:{origin_port}/probe",
                    timeout=5,
                    body=BodyMatcher(
                        kind=BodyMatchKind.EXACT,
                        value=_RESPONSE_BODY.decode("ascii"),
                    ),
                )
            ],
            quorum=1,
        )
        entry = imported.to_entry_record("observatory_entry", "generation_1")
        definition = CheckDefinition(
            check_id="observatory_check",
            entry_id=entry.entry_id,
            source_id=entry.source_id,
            target_set_id=target_set.target_set_id,
            mode=CheckMode.PROFILE,
            generation=entry.generation,
            inbound_tag="profile-client",
        )
        check = CompiledCheck(
            definition=definition,
            entry=entry,
            target_set=target_set,
            egress_assertions=(),
            assignment_reason="integration",
        )

        async with _running_xray_server(
            _XRAY_BINARY,
            server_config,
            tmp_path / "observatory-server.json",
            server_host,
            server_port,
        ):
            manager = XrayRuntimeManager(
                _XRAY_BINARY,
                runtime_dir=tmp_path / "observatory-runtimes",
                startup_timeout=8,
                config_test_timeout=8,
            )
            warmup_delay = 0.35
            pool = RuntimePool(
                manager,
                limit=1,
                observatory_warmup_delay=warmup_delay,
                observatory_warmup_timeout=2,
            )
            await pool.reconcile([check])
            started = asyncio.get_running_loop().time()
            try:
                async with pool.acquire(check) as first_runtime:
                    elapsed = asyncio.get_running_loop().time() - started
                    assert elapsed >= warmup_delay - 0.03
                    result, _ = await Checker(
                        request_timeout=5,
                        max_parallel_requests=1,
                    ).check_target_set(target_set, first_runtime.socks_port)
                    assert result.state is ReachabilityState.SUCCESS
                assert first_runtime.alive
                async with pool.acquire(check) as second_runtime:
                    assert second_runtime is first_runtime
            finally:
                await pool.close()


@asynccontextmanager
async def _null_port() -> AsyncIterator[None]:
    yield None
