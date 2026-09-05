from __future__ import annotations

import asyncio
import json
import stat
import sys
import threading
from pathlib import Path

import pytest

from xray_e2e_prober import runtime as runtime_module
from xray_e2e_prober.importers import import_content
from xray_e2e_prober.models import CheckMode, EntryRecord
from xray_e2e_prober.runtime import (
    EffectiveConfigError,
    XrayConfigError,
    XrayRuntimeManager,
    XrayStartError,
    _redaction_literals,
    build_connection_config,
    build_profile_config,
    sanitize_diagnostic,
)


def _profile() -> dict:
    return {
        "log": {"loglevel": "debug", "access": "/tmp/leak.log"},
        "dns": {"servers": ["1.1.1.1"]},
        "inbounds": [
            {
                "tag": "client-in",
                "listen": "0.0.0.0",
                "port": 1080,
                "protocol": "http",
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
            }
        ],
        "outbounds": [
            {
                "tag": "selected",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": "proxy.secret.example",
                            "port": 443,
                            "users": [{"id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}],
                        }
                    ]
                },
                "streamSettings": {
                    "network": "raw",
                    "security": "tls",
                    "tlsSettings": {"serverName": "proxy.secret.example"},
                    "rawSettings": {"header": {"type": "none"}},
                },
                "proxySettings": {"tag": "transport-hop"},
            },
            {"tag": "unused-direct", "protocol": "freedom"},
            {"tag": "transport-hop", "protocol": "freedom"},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {
                    "type": "field",
                    "inboundTag": ["client-in"],
                    "domain": ["example.org"],
                    "outboundTag": "unused-direct",
                }
            ],
        },
        "observatory": {"subjectSelector": ["selected"]},
    }


def test_runtime_diagnostics_redact_any_uuid_case_variants_and_short_secrets() -> None:
    literals = _redaction_literals({
        "publicKey": "MiXeD-Secret",
        "shortId": "aB",
        "tag": "xy",
        "operator-private-extension": {"enabled": True},
    })
    output = sanitize_diagnostic(
        "mixed-secret AB xy OPERATOR-PRIVATE-EXTENSION "
        "11111111-2222-f333-0444-555555555555",
        literals,
    )

    assert "mixed-secret" not in output.casefold()
    assert "ab" not in output.casefold()
    assert "operator-private-extension" not in output.casefold()
    assert "11111111-2222-f333-0444-555555555555" not in output.casefold()
    assert "xy" in output
    assert output.count("[redacted]") >= 3


def test_runtime_diagnostics_fail_closed_for_oversized_redaction_set() -> None:
    literals = _redaction_literals(
        {f"source-controlled-extension-{index}": f"value-{index}" for index in range(300)}
    )

    assert sanitize_diagnostic("otherwise harmless parser output", literals) == (
        "[diagnostic redacted]"
    )


def test_connection_config_forces_selected_outbound_and_keeps_chain() -> None:
    effective = build_connection_config(_profile(), 12080, outbound_tag="selected")

    assert effective["inbounds"] == [
        {
            "tag": "xray-e2e-prober-socks",
            "listen": "127.0.0.1",
            "port": 12080,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        }
    ]
    assert [item["tag"] for item in effective["outbounds"]] == [
        "selected",
        "transport-hop",
    ]
    assert effective["routing"] == {
        "domainStrategy": "AsIs",
        "rules": [
            {
                "type": "field",
                "inboundTag": ["xray-e2e-prober-socks"],
                "outboundTag": "selected",
            }
        ],
    }
    assert "observatory" not in effective
    assert effective["log"] == {"loglevel": "none", "dnsLog": False}


def test_profile_config_preserves_routing_order_and_inbound_semantics() -> None:
    original = _profile()
    effective = build_profile_config(original, 12081, inbound_tag="client-in")

    assert effective["routing"] == original["routing"]
    assert effective["dns"] == original["dns"]
    assert effective["outbounds"] == original["outbounds"]
    assert effective["observatory"] == original["observatory"]
    assert effective["inbounds"][0]["tag"] == "client-in"
    assert effective["inbounds"][0]["sniffing"] == original["inbounds"][0]["sniffing"]
    assert effective["inbounds"][0]["listen"] == "127.0.0.1"
    assert effective["inbounds"][0]["protocol"] == "socks"
    assert original["inbounds"][0]["listen"] == "0.0.0.0"  # no input mutation


def test_profile_config_does_not_add_tags_to_untagged_outbounds() -> None:
    original = _profile()
    original["outbounds"][1].pop("tag")

    effective = build_profile_config(original, 12081, inbound_tag="client-in")

    assert "tag" not in effective["outbounds"][1]
    assert effective["outbounds"] == original["outbounds"]


def test_connection_config_assigns_collision_free_tag_to_selected_outbound() -> None:
    original = _profile()
    original["outbounds"][0].pop("tag")
    original["outbounds"][1]["tag"] = "xray-e2e-prober-outbound-0"
    original["outbounds"][0].pop("proxySettings")

    effective = build_connection_config(original, 12081)

    assert effective["outbounds"][0]["tag"] == "xray-e2e-prober-outbound-0-1"
    assert (
        effective["routing"]["rules"][0]["outboundTag"]
        == "xray-e2e-prober-outbound-0-1"
    )


def test_untagged_profile_inbound_uses_tag_absent_from_routing_selectors() -> None:
    original = _profile()
    original["inbounds"][0].pop("tag")
    original["routing"]["rules"].extend(
        [
            {"type": "field", "inboundTag": ["xray-e2e-prober-socks"]},
            {"type": "field", "inboundTag": "xray-e2e-prober-socks-1"},
        ]
    )

    effective = build_profile_config(original, 12081)

    assert effective["inbounds"][0]["tag"] == "xray-e2e-prober-socks-2"
    assert effective["routing"] == original["routing"]


def test_connection_config_accepts_imported_and_persisted_raw_vless_entries() -> None:
    uri = (
        "vless://aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa@proxy.example:443"
        "?encryption=none&security=reality&type=tcp&sni=cdn.example&pbk=public-key#edge"
    )
    record = EntryRecord(
        entry_id="entry",
        source_id="source",
        name="edge",
        mode=CheckMode.CONNECTION,
        payload=uri,
        generation="generation",
    )
    imported = import_content(uri, source_id="source")[0]

    for entry in (imported, record):
        effective = build_connection_config(entry, 12082)
        assert effective["outbounds"][0]["tag"] == "probe-selected"
        assert effective["outbounds"][0]["protocol"] == "vless"
        assert effective["routing"]["rules"][0]["outboundTag"] == "probe-selected"


def test_profile_import_auto_selects_only_one_compatible_inbound() -> None:
    profile = _profile()
    profile["inbounds"].append(
        {"tag": "server-in", "listen": "0.0.0.0", "port": 443, "protocol": "vless"}
    )

    imported = import_content(json.dumps(profile), source_id="source")[0]

    assert imported.inbound_tag == "client-in"
    effective = build_profile_config(imported, 12083)
    assert effective["inbounds"][0]["tag"] == "client-in"


def test_profile_import_leaves_multiple_compatible_inbounds_for_explicit_selection() -> None:
    profile = _profile()
    profile["inbounds"].append(
        {"tag": "second-client", "listen": "127.0.0.1", "port": 1081, "protocol": "socks"}
    )

    imported = import_content(json.dumps(profile), source_id="source")[0]

    assert imported.inbound_tag is None
    with pytest.raises(EffectiveConfigError, match="explicit inbound"):
        build_profile_config(imported, 12084)
    effective = build_profile_config(imported, 12084, inbound_tag="second-client")
    assert effective["inbounds"][0]["tag"] == "second-client"


@pytest.mark.parametrize(
    "change",
    [
        lambda profile: profile.update({"api": {"tag": "api"}}),
        lambda profile: profile.update({"env": {"XRAY_LOCATION_ASSET": "/untrusted"}}),
        lambda profile: profile["routing"]["rules"][0].update({"source": ["10.0.0.0/8"]}),
        lambda profile: profile["routing"]["rules"][0].update(
            {"domain": ["ext:/mounted/private.dat:route"]}
        ),
        lambda profile: profile["outbounds"][0]
        .setdefault("streamSettings", {})
        .update({"sockopt": {"interface": "eth0"}}),
        lambda profile: profile["outbounds"][0].update(
            {"sendThrough": "192.0.2.10"}
        ),
        lambda profile: profile["dns"].update({"servers": ["127.0.0.53"]}),
        lambda profile: profile["dns"].update(
            {"servers": [{"address": "https://localhost/dns-query"}]}
        ),
        lambda profile: profile["dns"].update(
            {"servers": ["https+local://dns.example/dns-query"]}
        ),
        lambda profile: profile["outbounds"][0]["settings"]["vnext"][0].update(
            {"address": "::1"}
        ),
    ],
)
def test_profile_rejects_features_that_cannot_be_safely_reproduced(change) -> None:
    profile = _profile()
    change(profile)
    with pytest.raises(EffectiveConfigError):
        build_profile_config(profile)


def _write_fake_xray(path: Path) -> None:
    path.write_text(
        """
import json
import signal
import socket
import sys

config_path = sys.argv[-1]
with open(config_path, encoding="utf-8") as source:
    config = json.load(source)
server = config["outbounds"][0].get("settings", {}).get("vnext", [{}])[0]
secret_address = server.get("address", "no-address")
secret_id = server.get("users", [{}])[0].get("id", "no-id")
secret_key = next((key for key in config if key.startswith("operator-private")), "no-key")
if "--bad-test" in sys.argv:
    sys.stderr.write("invalid " + secret_address + " " + secret_id + " " + secret_key + "\\n")
    sys.stderr.flush()
    raise SystemExit(23)
if "--test" in sys.argv:
    raise SystemExit(0)
signal.signal(signal.SIGTERM, signal.SIG_IGN)
if "--no-listen" in sys.argv:
    while True:
        signal.pause()
port = config["inbounds"][0]["port"]
listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", port))
listener.listen()
sys.stderr.write((secret_address + " " + secret_id + " X" * 100000) + "\\n")
sys.stderr.flush()
while True:
    connection, _ = listener.accept()
    greeting = connection.recv(3)
    if greeting == b"\\x05\\x01\\x00":
        connection.sendall(b"\\x05\\x00")
    connection.close()
""".strip(),
        encoding="utf-8",
    )


@pytest.mark.asyncio
async def test_runtime_real_subprocess_readiness_bounded_output_and_kill(tmp_path: Path) -> None:
    fake = tmp_path / "fake_xray.py"
    _write_fake_xray(fake)
    manager = XrayRuntimeManager(
        sys.executable,
        runtime_dir=tmp_path / "runtime",
        test_args=(str(fake), "--test"),
        run_args=(str(fake), "--run"),
        startup_timeout=2,
        stop_timeout=0.05,
        output_limit_bytes=512,
    )
    runtime = await manager.start(build_connection_config(_profile()))
    config_path = runtime.config_path

    assert runtime.alive
    assert config_path.exists()
    assert stat.S_IMODE(config_path.stat().st_mode) == 0o600
    reader, writer = await asyncio.open_connection(runtime.socks_host, runtime.socks_port)
    del reader
    writer.close()
    await writer.wait_closed()

    await runtime.stop()  # fake ignores TERM, so the manager must escalate to kill
    diagnostics = runtime.diagnostics.stderr
    assert runtime.returncode is not None
    assert not config_path.exists()
    assert len(diagnostics.encode()) <= 512
    assert "oversized diagnostic line discarded" in diagnostics
    assert "proxy.secret.example" not in diagnostics
    assert "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" not in diagnostics
    await manager.close()


@pytest.mark.asyncio
async def test_failed_config_test_is_sanitized_and_reaped(tmp_path: Path) -> None:
    fake = tmp_path / "fake_xray.py"
    _write_fake_xray(fake)
    runtime_dir = tmp_path / "runtime"
    manager = XrayRuntimeManager(
        sys.executable,
        runtime_dir=runtime_dir,
        test_args=(str(fake), "--bad-test"),
        run_args=(str(fake), "--run"),
        output_limit_bytes=1024,
    )

    effective = build_connection_config(_profile())
    effective["operator-private-extension"] = {"enabled": True}
    with pytest.raises(XrayConfigError) as raised:
        await manager.start(effective)
    message = str(raised.value)
    assert raised.value.reason == "config_invalid"
    assert "proxy.secret.example" not in message
    assert "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" not in message
    assert "operator-private-extension" not in message
    assert "[redacted]" in message
    assert list(runtime_dir.glob("runtime-*.json")) == []
    await manager.close()


@pytest.mark.asyncio
async def test_validate_for_only_runs_bounded_config_test_and_cleans_file(
    tmp_path: Path,
) -> None:
    fake = tmp_path / "fake_xray.py"
    _write_fake_xray(fake)
    runtime_dir = tmp_path / "runtime"
    manager = XrayRuntimeManager(
        sys.executable,
        runtime_dir=runtime_dir,
        test_args=(str(fake), "--test"),
        run_args=(str(fake), "--run"),
        config_test_timeout=2,
    )
    spawned_arguments = []
    original_spawn = manager._spawn

    async def recording_spawn(arguments):
        spawned_arguments.append(tuple(arguments))
        return await original_spawn(arguments)

    manager._spawn = recording_spawn
    await manager.validate_for(_profile(), CheckMode.PROFILE, inbound_tag="client-in")

    assert len(spawned_arguments) == 1
    assert "--test" in spawned_arguments[0]
    assert "--run" not in spawned_arguments[0]
    assert manager.active == ()
    assert list(runtime_dir.glob("runtime-*.json")) == []
    await manager.close()


@pytest.mark.asyncio
async def test_validate_for_failure_is_sanitized_and_cleans_file(tmp_path: Path) -> None:
    fake = tmp_path / "fake_xray.py"
    _write_fake_xray(fake)
    runtime_dir = tmp_path / "runtime"
    manager = XrayRuntimeManager(
        sys.executable,
        runtime_dir=runtime_dir,
        test_args=(str(fake), "--bad-test"),
        output_limit_bytes=1024,
    )

    with pytest.raises(XrayConfigError) as raised:
        await manager.validate_for(_profile(), CheckMode.PROFILE, inbound_tag="client-in")

    assert "proxy.secret.example" not in str(raised.value)
    assert "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" not in str(raised.value)
    assert "[redacted]" in str(raised.value)
    assert manager.active == ()
    assert list(runtime_dir.glob("runtime-*.json")) == []
    await manager.close()


@pytest.mark.asyncio
async def test_cancelled_start_still_kills_waits_and_removes_config(tmp_path: Path) -> None:
    fake = tmp_path / "fake_xray.py"
    _write_fake_xray(fake)
    runtime_dir = tmp_path / "runtime"
    manager = XrayRuntimeManager(
        sys.executable,
        runtime_dir=runtime_dir,
        test_args=(str(fake), "--test"),
        run_args=(str(fake), "--no-listen"),
        startup_timeout=10,
        stop_timeout=0.05,
    )
    spawned = []
    original_spawn = manager._spawn

    async def recording_spawn(arguments):
        process = await original_spawn(arguments)
        spawned.append(process)
        return process

    manager._spawn = recording_spawn
    start_task = asyncio.create_task(manager.start(build_connection_config(_profile())))
    while len(spawned) < 2:
        await asyncio.sleep(0.01)

    start_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await start_task

    assert spawned[-1].returncode is not None
    assert list(runtime_dir.glob("runtime-*.json")) == []
    await manager.close()


@pytest.mark.asyncio
async def test_cancelled_start_waits_for_delayed_config_writer_before_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime_dir = tmp_path / "runtime"
    manager = XrayRuntimeManager("/usr/bin/true", runtime_dir=runtime_dir)
    original_write = runtime_module._write_private_json
    writing = threading.Event()
    release_write = threading.Event()

    def delayed_write(path: Path, config) -> None:
        writing.set()
        assert release_write.wait(timeout=2)
        original_write(path, config)

    monkeypatch.setattr(runtime_module, "_write_private_json", delayed_write)
    start = asyncio.create_task(manager.start(build_connection_config(_profile())))
    assert await asyncio.to_thread(writing.wait, 1)
    start.cancel()
    await asyncio.sleep(0)
    release_write.set()

    with pytest.raises(asyncio.CancelledError):
        await start
    assert list(runtime_dir.glob("runtime-*.json")) == []
    assert manager.active == ()
    await manager.close()


@pytest.mark.asyncio
async def test_close_racing_blocked_start_reaps_child_and_removes_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Reservation:
        def close(self) -> None:
            return None

    class EmptyStream:
        async def read(self, _size: int) -> bytes:
            return b""

    class ControlledProcess:
        def __init__(self) -> None:
            self.returncode = None
            self.stdout = EmptyStream()
            self.stderr = EmptyStream()
            self.stopped = asyncio.Event()

        def terminate(self) -> None:
            self.returncode = -15
            self.stopped.set()

        def kill(self) -> None:
            self.returncode = -9
            self.stopped.set()

        async def wait(self) -> int:
            await self.stopped.wait()
            assert self.returncode is not None
            return self.returncode

    runtime_dir = tmp_path / "runtime"
    manager = XrayRuntimeManager("unused", runtime_dir=runtime_dir)
    monkeypatch.setattr(
        runtime_module, "_reserve_port", lambda _port: (Reservation(), 12345)
    )
    process = ControlledProcess()
    startup_blocked = asyncio.Event()
    release_startup = asyncio.Event()

    async def accept_config(_path, _secrets) -> None:
        return None

    async def spawn_runtime(_arguments):
        return process

    async def block_readiness(_runtime, *, timeout=None) -> None:
        del timeout
        startup_blocked.set()
        await release_startup.wait()

    manager._run_config_test = accept_config
    manager._spawn = spawn_runtime
    manager._wait_ready = block_readiness

    start = asyncio.create_task(manager.start(build_connection_config(_profile())))
    await asyncio.wait_for(startup_blocked.wait(), timeout=1)
    config_paths = list(runtime_dir.glob("runtime-*.json"))
    assert len(config_paths) == 1
    assert process.returncode is None

    close = asyncio.create_task(manager.close())
    await asyncio.sleep(0)
    assert not close.done()
    release_startup.set()

    with pytest.raises(XrayStartError, match="manager is closed"):
        await start
    await close

    assert process.returncode is not None
    assert process.stopped.is_set()
    assert manager.active == ()
    assert list(runtime_dir.glob("runtime-*.json")) == []


@pytest.mark.asyncio
async def test_cancelled_close_finishes_blocked_start_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Reservation:
        def close(self) -> None:
            return None

    runtime_dir = tmp_path / "runtime"
    manager = XrayRuntimeManager("unused", runtime_dir=runtime_dir)
    monkeypatch.setattr(
        runtime_module, "_reserve_port", lambda _port: (Reservation(), 12345)
    )
    startup_blocked = asyncio.Event()
    release_startup = asyncio.Event()

    async def block_config_test(_path, _secrets) -> None:
        startup_blocked.set()
        await release_startup.wait()

    manager._run_config_test = block_config_test
    start = asyncio.create_task(manager.start(build_connection_config(_profile())))
    await asyncio.wait_for(startup_blocked.wait(), timeout=1)
    assert len(list(runtime_dir.glob("runtime-*.json"))) == 1

    close = asyncio.create_task(manager.close())
    await asyncio.sleep(0)
    close.cancel()
    release_startup.set()

    with pytest.raises(XrayStartError, match="manager is closed"):
        await start
    with pytest.raises(asyncio.CancelledError):
        await close

    assert manager.active == ()
    assert list(runtime_dir.glob("runtime-*.json")) == []
    # Repeated close observes the completed shared cleanup operation.
    await manager.close()


@pytest.mark.asyncio
async def test_private_config_writer_internal_cancellation_does_not_spin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def cancelled_write(_path: Path, _config) -> None:
        raise asyncio.CancelledError

    monkeypatch.setattr(runtime_module, "_write_private_json", cancelled_write)

    with pytest.raises(asyncio.CancelledError):
        await runtime_module._write_private_json_complete(
            tmp_path / "runtime.json", {"log": {}}
        )


@pytest.mark.asyncio
async def test_cancel_during_spawn_reaps_late_child_and_removes_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Reservation:
        def close(self) -> None:
            return None

    class ControlledProcess:
        def __init__(self) -> None:
            self.returncode = None
            self.stopped = asyncio.Event()

        def terminate(self) -> None:
            self.returncode = -15
            self.stopped.set()

        def kill(self) -> None:
            self.returncode = -9
            self.stopped.set()

        async def wait(self) -> int:
            await self.stopped.wait()
            assert self.returncode is not None
            return self.returncode

    runtime_dir = tmp_path / "runtime"
    manager = XrayRuntimeManager("unused", runtime_dir=runtime_dir)
    monkeypatch.setattr(
        runtime_module, "_reserve_port", lambda _port: (Reservation(), 12345)
    )
    process = ControlledProcess()
    child_created = asyncio.Event()
    release_spawn = asyncio.Event()

    async def accept_config(_path, _secrets) -> None:
        return None

    async def delayed_spawn(_arguments):
        child_created.set()
        await release_spawn.wait()
        return process

    manager._run_config_test = accept_config
    manager._spawn = delayed_spawn
    start = asyncio.create_task(manager.start(build_connection_config(_profile())))
    await asyncio.wait_for(child_created.wait(), timeout=1)
    assert len(list(runtime_dir.glob("runtime-*.json"))) == 1

    start.cancel()
    await asyncio.sleep(0)
    release_spawn.set()

    with pytest.raises(asyncio.CancelledError):
        await start
    assert process.stopped.is_set()
    assert process.returncode is not None
    assert manager.active == ()
    assert list(runtime_dir.glob("runtime-*.json")) == []
    await manager.close()


@pytest.mark.asyncio
async def test_stop_all_waits_for_every_runtime_before_raising(tmp_path: Path) -> None:
    class FailingRuntime:
        alive = True

        async def stop(self) -> None:
            raise RuntimeError("stop failed")

    class SlowRuntime:
        alive = True

        def __init__(self) -> None:
            self.finished = False

        async def stop(self) -> None:
            await asyncio.sleep(0.01)
            self.finished = True

    manager = XrayRuntimeManager("unused", runtime_dir=tmp_path / "runtime")
    slow = SlowRuntime()
    manager._runtimes.update({FailingRuntime(), slow})

    with pytest.raises(RuntimeError, match="stop failed"):
        await manager.stop_all()

    assert slow.finished
    manager._runtimes.clear()
    await manager.close()


@pytest.mark.asyncio
async def test_repeated_config_test_cancellation_still_kills_and_reaps(
    tmp_path: Path,
) -> None:
    class EmptyStream:
        def __init__(self, stopped: asyncio.Event) -> None:
            self._stopped = stopped

        async def read(self, _size: int) -> bytes:
            await self._stopped.wait()
            return b""

    class TermResistantProcess:
        def __init__(self) -> None:
            self.returncode = None
            self.terminate_called = asyncio.Event()
            self.stopped = asyncio.Event()
            self.waiting = asyncio.Event()
            self.stdout = EmptyStream(self.stopped)
            self.stderr = EmptyStream(self.stopped)

        def terminate(self) -> None:
            self.terminate_called.set()

        def kill(self) -> None:
            self.returncode = -9
            self.stopped.set()

        async def wait(self) -> int:
            self.waiting.set()
            await self.stopped.wait()
            assert self.returncode is not None
            return self.returncode

    manager = XrayRuntimeManager(
        "unused", runtime_dir=tmp_path / "runtime", stop_timeout=0.01
    )
    process = TermResistantProcess()

    async def spawn_config_test(_arguments):
        return process

    manager._spawn = spawn_config_test
    config_test = asyncio.create_task(
        manager._run_config_test(tmp_path / "unused.json", ())
    )
    await asyncio.wait_for(process.waiting.wait(), timeout=1)

    config_test.cancel()
    await asyncio.wait_for(process.terminate_called.wait(), timeout=1)
    config_test.cancel()

    with pytest.raises(asyncio.CancelledError):
        await config_test
    assert process.returncode == -9
    assert process.stopped.is_set()
    await manager.close()
