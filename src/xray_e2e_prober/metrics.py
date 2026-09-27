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
            labels=[
                "check_id",
                "instance_id",
                "source_id",
                "entry_name",
                "mode",
                "target_set_id",
            ],
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
        download_state = GaugeMetricFamily(
            "synthetic_check_download_state",
            "One-hot current state of a bounded throughput measurement",
            labels=["check_id", "instance_id", "target_id", "state"],
        )
        download_success = GaugeMetricFamily(
            "synthetic_check_download_success",
            "One for a complete throughput download and zero for confirmed failure",
            labels=["check_id", "instance_id", "target_id"],
        )
        download_bytes = GaugeMetricFamily(
            "synthetic_check_download_bytes",
            "Bytes read by the last bounded throughput measurement",
            labels=["check_id", "instance_id", "target_id"],
        )
        download_transfer = GaugeMetricFamily(
            "synthetic_check_download_transfer_seconds",
            "Body transfer duration of the last bounded throughput measurement",
            labels=["check_id", "instance_id", "target_id"],
        )
        download_mbps = GaugeMetricFamily(
            "synthetic_check_download_mbps",
            "Measured download throughput in decimal megabits per second",
            labels=["check_id", "instance_id", "target_id"],
        )
        download_timestamp = GaugeMetricFamily(
            "synthetic_check_download_last_run_timestamp_seconds",
            "Completion time of the last throughput measurement",
            labels=["check_id", "instance_id", "target_id"],
        )
        upload_state = GaugeMetricFamily(
            "synthetic_check_upload_state",
            "One-hot current state of a bounded upload measurement",
            labels=["check_id", "instance_id", "target_id", "state"],
        )
        upload_success = GaugeMetricFamily(
            "synthetic_check_upload_success",
            "One for a complete throughput upload and zero for confirmed failure",
            labels=["check_id", "instance_id", "target_id"],
        )
        upload_bytes = GaugeMetricFamily(
            "synthetic_check_upload_bytes",
            "Bytes written by the last bounded throughput measurement",
            labels=["check_id", "instance_id", "target_id"],
        )
        upload_transfer = GaugeMetricFamily(
            "synthetic_check_upload_transfer_seconds",
            "Request body transfer duration of the last bounded throughput measurement",
            labels=["check_id", "instance_id", "target_id"],
        )
        upload_mbps = GaugeMetricFamily(
            "synthetic_check_upload_mbps",
            "Measured upload throughput in decimal megabits per second",
            labels=["check_id", "instance_id", "target_id"],
        )
        upload_timestamp = GaugeMetricFamily(
            "synthetic_check_upload_last_run_timestamp_seconds",
            "Completion time of the last upload throughput measurement",
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
                    str(check.get("entry_name", "")),
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
                if target.get("kind", "reachability") == "throughput":
                    is_upload = target.get("direction", "download") == "upload"
                    throughput_state = upload_state if is_upload else download_state
                    throughput_success = upload_success if is_upload else download_success
                    throughput_bytes = upload_bytes if is_upload else download_bytes
                    throughput_transfer = upload_transfer if is_upload else download_transfer
                    throughput_mbps = upload_mbps if is_upload else download_mbps
                    throughput_timestamp = upload_timestamp if is_upload else download_timestamp
                    for possible in TARGET_STATES:
                        throughput_state.add_metric(
                            target_labels + [possible],
                            float(current_target_state == possible),
                        )
                    if current_target_state in {"success", "failure"}:
                        throughput_success.add_metric(
                            target_labels,
                            float(current_target_state == "success"),
                        )
                    byte_field = "bytes_written" if is_upload else "bytes_read"
                    if target.get(byte_field) is not None:
                        throughput_bytes.add_metric(
                            target_labels, float(target[byte_field])
                        )
                    if target.get("transfer_seconds") is not None:
                        throughput_transfer.add_metric(
                            target_labels, float(target["transfer_seconds"])
                        )
                    if target.get("throughput_mbps") is not None:
                        throughput_mbps.add_metric(
                            target_labels, float(target["throughput_mbps"])
                        )
                    if target.get("measurement_timestamp") is not None:
                        throughput_timestamp.add_metric(
                            target_labels,
                            float(target["measurement_timestamp"]),
                        )
                    continue
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
            download_state,
            download_success,
            download_bytes,
            download_transfer,
            download_mbps,
            download_timestamp,
            upload_state,
            upload_success,
            upload_bytes,
            upload_transfer,
            upload_mbps,
            upload_timestamp,
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
