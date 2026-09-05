"""Local newline-delimited JSON control protocol over a mode-0600 Unix socket."""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from .security import redact_text

MAX_CONTROL_MESSAGE = 4 * 1024 * 1024


class ControlError(RuntimeError):
    pass


Handler = Callable[[str, dict[str, Any]], Awaitable[Any]]


class ControlServer:
    def __init__(self, path: str | Path, handler: Handler) -> None:
        self.path = Path(path)
        self.handler = handler
        self._server: asyncio.AbstractServer | None = None
        self._handlers: set[asyncio.Task[None]] = set()
        self._stopping = False
        self._stop_lock = asyncio.Lock()

    async def start(self) -> None:
        self._stopping = False
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            if await control_available(self.path):
                raise ControlError("another daemon owns the control socket")
            self.path.unlink()
        self._server = await asyncio.start_unix_server(
            self._handle,
            path=str(self.path),
            limit=MAX_CONTROL_MESSAGE + 1,
        )
        os.chmod(self.path, 0o600)

    async def stop(self) -> None:
        async with self._stop_lock:
            self._stopping = True
            server, self._server = self._server, None
            if server is not None:
                server.close()

            # Accepted connections are not owned by asyncio.Server once their
            # callback task has started. Cancel and drain them explicitly so a
            # state-mutating command cannot outlive service shutdown.
            current = asyncio.current_task()
            handlers = tuple(
                task for task in self._handlers if task is not current
            )
            for task in handlers:
                task.cancel()
            if handlers:
                await asyncio.gather(*handlers, return_exceptions=True)
            if server is not None:
                # Python 3.13 waits for accepted connections as well as listener
                # sockets, so handlers must be cancelled before this await.
                await server.wait_closed()
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._handlers.add(task)
        try:
            if self._stopping:
                return
            response: dict[str, Any]
            try:
                raw = await asyncio.wait_for(reader.readline(), timeout=10)
                if not raw or len(raw) > MAX_CONTROL_MESSAGE or not raw.endswith(b"\n"):
                    raise ControlError("invalid control request")
                request = json.loads(raw)
                if not isinstance(request, dict) or not isinstance(request.get("command"), str):
                    raise ControlError("invalid control request")
                params = request.get("params", {})
                if not isinstance(params, dict):
                    raise ControlError("invalid control params")
                result = await self.handler(request["command"], params)
                response = {"ok": True, "result": result}
            except Exception as exc:
                response = {"ok": False, "error": redact_text(exc)}
            writer.write(json.dumps(response, separators=(",", ":")).encode() + b"\n")
            await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
            if task is not None:
                self._handlers.discard(task)


async def request(
    path: str | Path,
    command: str,
    params: dict[str, Any] | None = None,
    *,
    timeout: float = 60,
) -> Any:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_unix_connection(
                str(path), limit=MAX_CONTROL_MESSAGE + 1
            ),
            timeout=min(timeout, 5),
        )
    except (OSError, TimeoutError) as exc:
        raise ControlError("daemon control socket is unavailable") from exc
    try:
        payload = {"command": command, "params": params or {}}
        writer.write(json.dumps(payload, separators=(",", ":")).encode() + b"\n")
        await writer.drain()
        raw = await asyncio.wait_for(reader.readline(), timeout=timeout)
        if not raw or len(raw) > MAX_CONTROL_MESSAGE:
            raise ControlError("invalid daemon response")
        response = json.loads(raw)
        if not response.get("ok"):
            raise ControlError(str(response.get("error", "daemon command failed")))
        return response.get("result")
    finally:
        writer.close()
        await writer.wait_closed()


async def control_available(path: str | Path) -> bool:
    try:
        result = await request(path, "ping", timeout=1)
    except (ControlError, OSError, TimeoutError, json.JSONDecodeError):
        return False
    return bool(result and result.get("pong"))
