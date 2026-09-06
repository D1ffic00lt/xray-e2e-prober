from prometheus_client.parser import text_string_to_metric_families

from xray_e2e_prober.metrics import Metrics


def _sample_values(text: str, metric: str) -> list[float]:
    for family in text_string_to_metric_families(text):
        if family.name == metric:
            return [sample.value for sample in family.samples]
    return []


def test_metrics_keep_unknown_distinct_from_failure_and_remove_deleted_checks() -> None:
    state = {
        "instance_id": "instance-a",
        "config_reload_success": True,
        "checks": [
            {
                "check_id": "c1",
                "source_id": "s1",
                "entry_name": "RU Primary XTLS",
                "mode": "connection",
                "target_set_id": "ts1",
                "state": "unknown",
            }
        ],
    }
    metrics = Metrics(lambda: state)
    first = metrics.render().decode()
    assert (
        'synthetic_check_info{check_id="c1",entry_name="RU Primary XTLS",'
        'instance_id="instance-a",mode="connection",source_id="s1",target_set_id="ts1"}'
        " 1.0"
    ) in first
    assert (
        'synthetic_check_state{check_id="c1",instance_id="instance-a",state="unknown"}'
        " 1.0"
    ) in first
    assert _sample_values(first, "synthetic_check_status") == []

    state["checks"] = []
    second = metrics.render().decode()
    assert 'check_id="c1"' not in second
    assert _sample_values(second, "synthetic_prober_runtime_active") == [0.0]
