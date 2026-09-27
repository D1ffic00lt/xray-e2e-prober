# Prometheus rules example

These files are optional: the prober runs without Prometheus or Alertmanager.

Load `recording_rules.yaml` before `alerting_rules.yaml`. Copy
`inventory.example.yaml`, replace its labels with
`prober config export --json` → `expected_inventory`, and manage that inventory
independently from the prober instances. Use only entries whose `enabled` value
is true. Without an independent inventory, a disappeared series cannot tell
Prometheus which check or observation point was expected.

The example uses these policy values:

- fresh result: at most 10 minutes old;
- multi-instance confirmation: at least two distinct `instance_id` values;
- source refresh failure: last success more than 30 minutes ago;
- disabled checks never raise the stale alert, even with an old/zero timestamp;
- egress `error`, `unknown`, or `stale`: continuously present for 5 minutes;
- alert `for` values and severities are in `alerting_rules.yaml`.

Tune them before production use. `instance_id` must identify an observation
point and must not be added by a scrape replica. A third successful observation
does not negate two failures; the corresponding alert deliberately says
"multiple observation instances", not "global outage".

## Grafana: download throughput

Throughput-targets intentionally have no bundled alert rules. First collect a
baseline and use the dedicated metrics without mixing them into reachability:

```promql
# Current Mbps, enriched with the safe inbound display name.
synthetic_check_download_mbps
  * on (check_id, instance_id) group_left (entry_name)
    synthetic_check_info

# Mean / median / p10 over 24 hours. Grafana unit: Mbit/s.
avg_over_time(synthetic_check_download_mbps[24h])
quantile_over_time(0.50, synthetic_check_download_mbps[24h])
quantile_over_time(0.10, synthetic_check_download_mbps[24h])

# Measurement age; alerting or dashboards must not treat an old value as fresh.
time() - synthetic_check_download_last_run_timestamp_seconds
```

Use `entry_name`, `instance_id`, and `target_id` as dashboard dimensions. A
download target is excluded from `synthetic_check_target_*` and quorum by
design, so a slow controlled origin cannot turn a reachability check into a VPN
outage. Compare at least two controlled origins before attributing a regression
to the inbound or its egress path.

A ready importable dashboard with these filters and last/mean/median/p10 panels
is in [`../grafana/inbound-throughput.json`](../grafana/inbound-throughput.json).

Validate locally with the same pinned Prometheus image used by CI:

```console
docker run --rm --entrypoint /bin/promtool \
  -v "$PWD:/workspace:ro" -w /workspace \
  prom/prometheus:v3.5.0@sha256:63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996 \
  check rules examples/prometheus/recording_rules.yaml \
  examples/prometheus/alerting_rules.yaml \
  examples/prometheus/inventory.example.yaml

docker run --rm --entrypoint /bin/promtool \
  -v "$PWD:/workspace:ro" -w /workspace \
  prom/prometheus:v3.5.0@sha256:63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996 \
  test rules examples/prometheus/rules.test.yaml
```
