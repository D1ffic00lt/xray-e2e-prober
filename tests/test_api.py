from fastapi.testclient import TestClient

from xray_e2e_prober.api import create_app
from xray_e2e_prober.metrics import Metrics


class FakeService:
    ready = True
    main_loop_alive = True

    def __init__(self):
        self.started = False
        self.metrics = Metrics(self.status_snapshot)

    async def start(self):
        self.started = True

    async def stop(self):
        self.started = False

    def status_snapshot(self):
        return {
            "instance_id": "i1",
            "ready": self.ready,
            "config_reload_success": True,
            "checks": self.checks_snapshot(),
        }

    def checks_snapshot(self):
        return [
            {
                "check_id": "c1",
                "source_id": "s1",
                "mode": "connection",
                "target_set_id": "t1",
                "state": "unknown",
            }
        ]

    def check_snapshot(self, check_id):
        return self.checks_snapshot()[0] if check_id == "c1" else None


def test_api_lifecycle_readiness_and_check_lookup() -> None:
    service = FakeService()
    with TestClient(create_app(service)) as client:
        assert service.started
        assert client.get("/health/live").status_code == 200
        assert client.get("/health/ready").status_code == 200
        assert client.get("/api/v1/checks/c1").json()["state"] == "unknown"
        assert client.get("/api/v1/checks/missing").status_code == 404
        assert "synthetic_check_info" in client.get("/metrics").text
    assert not service.started
