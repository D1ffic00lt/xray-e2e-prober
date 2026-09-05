import asyncio
import stat
import uuid
from pathlib import Path

import pytest

from xray_e2e_prober.control import ControlServer, request


@pytest.mark.asyncio
async def test_control_socket_is_private_and_dispatches() -> None:
    async def handler(command, params):
        return {"command": command, "value": params.get("value")}

    # macOS limits AF_UNIX paths to 104 bytes; pytest's temporary root is longer.
    path = Path.cwd() / f".xep-{uuid.uuid4().hex[:8]}.sock"
    server = ControlServer(path, handler)
    await server.start()
    try:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert await request(path, "status", {"value": 7}) == {
            "command": "status",
            "value": 7,
        }
    finally:
        await server.stop()
    assert not path.exists()


@pytest.mark.asyncio
async def test_stop_cancels_and_drains_active_handlers() -> None:
    entered = asyncio.Event()
    cleaned = asyncio.Event()

    async def handler(command, params):
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            # An async cleanup proves ControlServer.stop awaits the handler task,
            # rather than merely closing the listening socket.
            await asyncio.sleep(0)
            cleaned.set()

    path = Path.cwd() / f".xep-{uuid.uuid4().hex[:8]}.sock"
    server = ControlServer(path, handler)
    await server.start()
    client = asyncio.create_task(request(path, "refresh", timeout=1))
    await asyncio.wait_for(entered.wait(), timeout=1)

    await asyncio.wait_for(server.stop(), timeout=1)

    assert cleaned.is_set()
    assert not server._handlers
    assert not path.exists()
    await asyncio.gather(client, return_exceptions=True)
