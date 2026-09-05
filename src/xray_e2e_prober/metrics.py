"""Low-cardinality Prometheus projection of the current in-memory snapshot."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from prometheus_client import CollectorRegistry, generate_latest
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily

CHECK_STATES = ("unknown", "success", "failure", "error", "stale", "disabled")
TARGET_STATES = ("unknown", "success", "failure", "error", "stale", "disabled")
EGRESS_STATES = ("match", "mismatch", "unknown", "error", "stale", "disabled")


class CurrentStateCollector:
    """Build metrics at scrape time so removed checks disappear immediately."""

    def __init__(self, snapshot: Callable[[], dict[str, Any]]) -> None:
        self._snapshot = snapshot

    def collect(self) -> Iterable[GaugeMetricFamily | CounterMetricFamily]:
        snapshot = self._snapshot()
        instance = str(snapshot.get("instance_id", "unconfigured"))
        checks = snapshot.get("checks", [])

        info = GaugeMetricFamily(
            "synthetic_check_info",
            "Accepted check inventory",
            labels=["check_id", "instance_id", "source_id", "mode", "target_set_id"],
        )
        state = GaugeMetricFamily(
            "synthetic_check_state",
            "One-hot current check state",
            labels=["check_id", "instance_id", "state"],
        )
        status = GaugeMetricFamily(
            "synthetic_check_status",
            "One for success and zero for confirmed failure",
            labels=["check_id", "instance_id"],
        )
        target_success = GaugeMetricFamily(
            "synthetic_check_target_success",
            "Last confirmed target network result",
            labels=["check_id", "instance_id", "target_id"],
        )
        target_state = GaugeMetricFamily(
            "synthetic_check_target_state",
            "One-hot current target state",
            labels=["check_id", "instance_id", "target_id", "state"],
        )
        duration = GaugeMetricFamily(
            "synthetic_check_duration_seconds",
            "HTTP attempt duration",
            labels=["check_id", "instance_id", "target_id"],
        )
        ttfb = GaugeMetricFamily(
            "synthetic_check_ttfb_seconds",
            "Observed time to first response byte",
            labels=["check_id", "instance_id", "target_id"],
        )
        last_run = GaugeMetricFamily(
            "synthetic_check_last_run_timestamp_seconds",
            "Completion time for the current generation",
            labels=["check_id", "instance_id"],
        )
        egress_state = GaugeMetricFamily(
            "synthetic_check_egress_state",
            "One-hot current egress assertion state",
            labels=["check_id", "instance_id", "assertion_id", "state"],
        )
        egress_match = GaugeMetricFamily(
            "synthetic_check_egress_match",
            "One for match and zero for confirmed mismatch",
            labels=["check_id", "instance_id", "assertion_id"],
        )
        errors = CounterMetricFamily(
            "synthetic_check_errors",
            "Executor and confirmed check errors",
            labels=["check_id", "instance_id", "reason"],
        )

        for check in checks:
            check_id = str(check["check_id"])
            labels = [check_id, instance]
            info.add_metric(
                [
                    check_id,
                    instance,
                    str(check["source_id"]),
                    str(check["mode"]),
                    str(check["target_set_id"]),
                ],
                1,
            )
            current_state = str(check.get("state", "unknown"))
            for possible in CHECK_STATES:
                state.add_metric(labels + [possible], float(current_state == possible))
            if current_state in {"success", "failure"}:
                status.add_metric(labels, float(current_state == "success"))
            last_run.add_metric(labels, float(check.get("last_run_timestamp", 0) or 0))

            for target in check.get("targets", []):
                target_id = str(target["target_id"])
                target_labels = labels + [target_id]
                current_target_state = str(target.get("state", "unknown"))
                for possible in TARGET_STATES:
                    target_state.add_metric(
                        target_labels + [possible], float(current_target_state == possible)
                    )
                if current_target_state in {"success", "failure"}:
                    target_success.add_metric(
                        target_labels, float(current_target_state == "success")
                    )
                if target.get("duration_seconds") is not None:
                    duration.add_metric(target_labels, float(target["duration_seconds"]))
                if target.get("ttfb_seconds") is not None:
                    ttfb.add_metric(target_labels, float(target["ttfb_seconds"]))

            for assertion in check.get("egress", []):
                assertion_id = str(assertion["assertion_id"])
                assertion_labels = labels + [assertion_id]
                current_egress_state = str(assertion.get("state", "unknown"))
                for possible in EGRESS_STATES:
                    egress_state.add_metric(
                        assertion_labels + [possible],
                        float(current_egress_state == possible),
                    )
                if current_egress_state in {"match", "mismatch"}:
                    egress_match.add_metric(
                        assertion_labels, float(current_egress_state == "match")
                    )

            for reason, count in check.get("errors_total", {}).items():
                errors.add_metric(labels + [str(reason)], float(count))

        reload_success = GaugeMetricFamily(
            "synthetic_prober_config_last_reload_successful",
            "Whether the last configuration reload succeeded",
            labels=["instance_id"],
        )
        reload_success.add_metric([instance], float(bool(snapshot.get("config_reload_success"))))

        source_refresh = GaugeMetricFamily(
            "synthetic_prober_source_refresh_success",
            "Whether the last source refresh succeeded",
            labels=["instance_id", "source_id"],
        )
        source_timestamp = GaugeMetricFamily(
            "synthetic_prober_source_last_success_timestamp_seconds",
            "Last accepted source refresh",
            labels=["instance_id", "source_id"],
        )
        for source in snapshot.get("sources", []):
            source_labels = [instance, str(source["source_id"])]
            source_refresh.add_metric(source_labels, float(bool(source.get("refresh_success"))))
            source_timestamp.add_metric(
                source_labels, float(source.get("last_success_timestamp", 0) or 0)
            )

        active = GaugeMetricFamily(
            "synthetic_prober_runtime_active",
            "Active Xray runtimes",
            labels=["instance_id"],
        )
        active.add_metric([instance], float(snapshot.get("runtime_active", 0)))
        queue_size = GaugeMetricFamily(
            "synthetic_prober_scheduler_queue_size",
            "Queued checks",
            labels=["instance_id"],
        )
        queue_size.add_metric([instance], float(snapshot.get("queue_size", 0)))

        yield from (
            info,
            state,
            status,
            target_success,
            target_state,
            duration,
            ttfb,
            last_run,
            egress_state,
            egress_match,
            errors,
            reload_success,
            source_refresh,
            source_timestamp,
            active,
            queue_size,
        )


class Metrics:
    def __init__(self, snapshot: Callable[[], dict[str, Any]]) -> None:
        self.registry = CollectorRegistry(auto_describe=True)
        self.registry.register(CurrentStateCollector(snapshot))

    def render(self) -> bytes:
        return generate_latest(self.registry)

