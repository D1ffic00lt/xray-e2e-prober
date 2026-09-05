import asyncio
import time
from pathlib import Path

import httpx
import pytest

from xray_e2e_prober.sources import SourceFetchError, SourceLoader
from xray_e2e_prober.models import SourceKind


@pytest.mark.asyncio
async def test_local_source_is_bounded(tmp_path: Path) -> None:
    path = tmp_path / "subscription.txt"
    path.write_text("vless://example", encoding="utf-8")
    source = {"kind": "file", "location": str(path), "max_bytes": 4}
    with pytest.raises(SourceFetchError, match="could not be read"):
        await SourceLoader().fetch(source)


@pytest.mark.asyncio
async def test_plain_http_requires_explicit_opt_in() -> None:
    with pytest.raises(SourceFetchError, match="allow_insecure_http"):
        await SourceLoader().fetch({"kind": "url", "location": "http://example.test/x"})


@pytest.mark.asyncio
async def test_malformed_url_port_does_not_escape_in_fetch_error() -> None:
    secret = "DO-NOT-LOG-THIS"
    with pytest.raises(SourceFetchError, match="source URL is invalid") as caught:
        await SourceLoader().fetch(
            {"kind": "url", "location": f"https://example.test:{secret}/subscription"}
        )
    assert secret not in str(caught.value)


@pytest.mark.asyncio
async def test_directory_keeps_json_documents_separate(tmp_path: Path) -> None:
    (tmp_path / "one.json").write_text('{"outbounds": []}', encoding="utf-8")
    (tmp_path / "two.json").write_text('{"outbounds": []}', encoding="utf-8")
    payload = await SourceLoader().fetch(
        {"kind": "directory", "location": str(tmp_path), "max_bytes": 1024}
    )
    assert len(payload.documents) == 2
    assert payload.content == b""


@pytest.mark.asyncio
async def test_http_source_timeout_is_a_total_deadline(monkeypatch) -> None:
    real_client = httpx.AsyncClient

    class Trickle(httpx.AsyncByteStream):
        async def __aiter__(self):
            while True:
                await asyncio.sleep(0.03)
                yield b"x"

    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, request=request, stream=Trickle())
    )

    def client(**kwargs):
        return real_client(transport=transport, **kwargs)

    monkeypatch.setattr("xray_e2e_prober.sources.httpx.AsyncClient", client)
    started = time.monotonic()
    with pytest.raises(SourceFetchError, match="source request failed"):
        await SourceLoader().fetch(
            {
                "kind": "url",
                "location": "http://source.example.test/subscription",
                "allow_insecure_http": True,
                "timeout": 0.08,
                "max_bytes": 1024,
            }
        )
    assert time.monotonic() - started < 0.5


@pytest.mark.asyncio
async def test_relative_secret_reference_uses_config_base_directory(tmp_path: Path) -> None:
    subscription = tmp_path / "subscription.txt"
    subscription.write_bytes(b"payload")
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / "source-location").write_text(str(subscription), encoding="utf-8")
    payload = await SourceLoader(base_dir=tmp_path).fetch(
        {
            "kind": "file",
            "location_ref": {"file": "secrets/source-location"},
            "max_bytes": 1024,
        }
    )
    assert payload.content == b"payload"


@pytest.mark.asyncio
async def test_cross_origin_redirect_drops_every_user_configured_header(
    monkeypatch,
) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.host == "source.example.test":
            return httpx.Response(
                302,
                headers={"location": "https://cdn.example.test/subscription"},
                request=request,
            )
        return httpx.Response(200, content=b"payload", request=request)

    real_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(
        "xray_e2e_prober.sources.httpx.AsyncClient",
        lambda **kwargs: real_client(transport=transport, **kwargs),
    )
    payload = await SourceLoader().fetch(
        {
            "kind": "http",
            "location": "https://source.example.test/subscription",
            "headers": {
                "Authorization": "Bearer secret",
                "X-Subscription-Token": "also-secret",
                "X-Tenant": "private-context",
            },
        }
    )
    assert payload.content == b"payload"
    assert requests[0].headers["authorization"] == "Bearer secret"
    assert "authorization" not in requests[1].headers
    assert "x-subscription-token" not in requests[1].headers
    assert "x-tenant" not in requests[1].headers

@pytest.mark.asyncio
async def test_declared_source_kind_is_not_guessed_from_location(tmp_path: Path) -> None:
    local = tmp_path / "source.txt"
    local.write_bytes(b"ok")
    loader = SourceLoader()
    payload = await loader.fetch({"kind": SourceKind.FILE, "location": str(local)})
    assert payload.content == b"ok"
    with pytest.raises(SourceFetchError):
        await loader.fetch({"kind": SourceKind.HTTP, "location": str(local)})
    with pytest.raises(SourceFetchError):
        await loader.fetch({"kind": SourceKind.FILE, "location": "https://example.test"})


@pytest.mark.asyncio
async def test_empty_directory_is_returned_for_allow_empty_policy(tmp_path: Path) -> None:
    payload = await SourceLoader().fetch(
        {"kind": SourceKind.DIRECTORY, "location": str(tmp_path)}
    )
    assert payload.documents == ()
    assert payload.content == b""
