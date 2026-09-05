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
- alert `for` values and severities are in `alerting_rules.yaml`.

Tune them before production use. `instance_id` must identify an observation
point and must not be added by a scrape replica. A third successful observation
does not negate two failures; the corresponding alert deliberately says
"multiple observation instances", not "global outage".

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
