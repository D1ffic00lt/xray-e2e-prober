"""Read-only FastAPI surface over the shared application service."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Protocol

from fastapi import FastAPI, HTTPException, Request, Response, status


class ServiceLike(Protocol):
    ready: bool
    main_loop_alive: bool
    metrics: Any

    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    def status_snapshot(self) -> dict[str, Any]: ...

    def checks_snapshot(self) -> list[dict[str, Any]]: ...

    def check_snapshot(self, check_id: str) -> dict[str, Any] | None: ...


def create_app(
    service: ServiceLike | None = None,
    *,
    data_dir: str | Path | None = None,
    config_path: str | Path | None = None,
    xray_binary: str | Path | None = None,
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        instance = service
        if instance is None:
            from .service import ProberService

            instance = ProberService.from_paths(
                data_dir=data_dir, config_path=config_path, xray_binary=xray_binary
            )
        app.state.prober = instance
        await instance.start()
        try:
            yield
        finally:
            await instance.stop()

    app = FastAPI(
        title="Xray E2E Prober",
        version="0.1.1",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    def current(request: Request) -> ServiceLike:
        return request.app.state.prober

    @app.get("/health/live")
    async def live(request: Request) -> Response:
        running = current(request).main_loop_alive
        return Response(
            content='{"status":"live"}' if running else '{"status":"stopped"}',
            status_code=status.HTTP_200_OK if running else status.HTTP_503_SERVICE_UNAVAILABLE,
            media_type="application/json",
        )

    @app.get("/health/ready")
    async def ready(request: Request) -> Response:
        is_ready = current(request).ready
        return Response(
            content='{"status":"ready"}' if is_ready else '{"status":"not_ready"}',
            status_code=status.HTTP_200_OK if is_ready else status.HTTP_503_SERVICE_UNAVAILABLE,
            media_type="application/json",
        )

    @app.get("/api/v1/status")
    async def prober_status(request: Request) -> dict[str, Any]:
        return current(request).status_snapshot()

    @app.get("/api/v1/checks")
    async def checks(request: Request) -> dict[str, Any]:
        return {"checks": current(request).checks_snapshot()}

    @app.get("/api/v1/checks/{check_id}")
    async def check(request: Request, check_id: str) -> dict[str, Any]:
        result = current(request).check_snapshot(check_id)
        if result is None:
            raise HTTPException(status_code=404, detail="check not found")
        return result

    @app.get("/metrics")
    async def metrics(request: Request) -> Response:
        return Response(
            content=current(request).metrics.render(),
            media_type="text/plain; version=0.0.4; charset=utf-8",
            headers={"Cache-Control": "no-store"},
        )

    return app
