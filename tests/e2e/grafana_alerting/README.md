# Manual e2e runbook — `grafana_alerting` output format

This is the manual verification step for the `grafana_alerting` output
format. The automated test in
[`../test_grafana_alerting_provisioning.py`](../test_grafana_alerting_provisioning.py)
proves that Grafana's provisioning loader accepts the YAML
**structurally**. That alone is not enough: the
[victoriametrics-logs-datasource](https://grafana.com/grafana/plugins/victoriametrics-logs-datasource/)
plugin owns the `model.queryType` enum and the `expr` shape it expects,
and those are only validated when an alert actually evaluates a query.

Run this runbook:

* Before tagging a release that touches the `grafana_alerting` format.
* After bumping the pinned VL datasource plugin commit referenced in
  `sigma/backends/victorialogs/victorialogs.py`.
* When upgrading to a new Grafana major version.

## What you need

* Docker / docker-compose.
* `sigma-cli` with this backend installed: `pip install -e .` from the
  repo root, then `sigma plugin install victorialogs`.
* About 10 minutes.

## Stack

A minimal compose stack is sufficient: Grafana 11, VictoriaLogs, and the
VL datasource plugin. Drop this `docker-compose.yml` somewhere temporary:

```yaml
services:
  victorialogs:
    image: victoriametrics/victoria-logs:v1.50.0
    ports: ["9428:9428"]

  grafana:
    image: grafana/grafana:11.0.0
    depends_on: [victorialogs]
    environment:
      GF_INSTALL_PLUGINS: victoriametrics-logs-datasource
      GF_AUTH_ANONYMOUS_ENABLED: "true"
      GF_AUTH_ANONYMOUS_ORG_ROLE: Admin
    volumes:
      - ./provisioning:/etc/grafana/provisioning:ro
    ports: ["3000:3000"]
```

## Steps

### 1. Provision the VL datasource

```bash
mkdir -p provisioning/datasources
cat > provisioning/datasources/victorialogs.yaml <<'EOF'
apiVersion: 1
datasources:
  - name: VictoriaLogs
    type: victoriametrics-logs-datasource
    uid: vl-runbook
    access: proxy
    url: http://victorialogs:9428
    isDefault: false
EOF
```

The `uid: vl-runbook` value is what you'll pass to the backend.

### 2. Generate the alert YAML

Use any Sigma rule with an `id`. The cmd-exec rule below is enough:

```bash
cat > /tmp/rule.yml <<'EOF'
title: Runbook smoke rule
id: 99999999-9999-4999-8999-999999999999
status: experimental
description: Runbook smoke — flags cmd.exe with powershell on the command line.
level: high
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\cmd.exe'
    CommandLine|contains: 'powershell'
  condition: selection
EOF

mkdir -p provisioning/alerting
sigma convert -t victorialogs -f grafana_alerting \
    -O grafana_datasource_uid=vl-runbook \
    /tmp/rule.yml > provisioning/alerting/sigma.yaml
```

### 3. Boot the stack and confirm provisioning

```bash
docker compose up -d
docker compose logs -f grafana | grep -iE 'provision|alert|error' &
```

Expected within ~15s:

* No lines containing `could not provision`, `failed to provision`, or
  `invalid alert rule`.
* A line indicating the rule group loaded (exact text varies by Grafana
  minor version, but always references our group name `sigma`).

Open `http://localhost:3000` → **Alerting** → **Alert rules**. The rule
`Runbook smoke rule` should appear under the `sigma` folder, in `OK`
state (no matching events yet).

### 4. Drive the rule to firing

Ingest an event that satisfies the rule:

```bash
curl -s -X POST 'http://localhost:9428/insert/jsonline?_stream_fields=host' \
    -H 'Content-Type: application/stream+json' \
    --data-binary @- <<EOF
{"_time":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","Image":"C:\\\\Windows\\\\System32\\\\cmd.exe","CommandLine":"cmd.exe /c powershell -enc Zm9v","host":"runbook-1"}
EOF
```

Wait for the next evaluation interval (default `1m`). The rule state
should transition to `Firing` in the UI.

### 5. Verify the labels and annotations

In the firing alert's detail pane:

* `severity` label = `warning` (from Sigma `level: high`).
* `sigma_id` label = `99999999-9999-4999-8999-999999999999`.
* `summary` annotation = `Runbook smoke rule`.
* `description` annotation present.

If any of the above is missing or wrong, the field-mapping table in
`finalize_query_grafana_alerting` has drifted from expectations —
investigate before releasing.

## When something fails

| Symptom | Likely cause | Where to look |
|---------|--------------|---------------|
| Grafana logs `could not provision` on boot | YAML structural issue — schema drift | Re-run automated provisioning test; compare against Grafana docs `file-provisioning/index.md` |
| Rule loads but stays `Error` state | `model.queryType` not accepted by VL plugin | `victorialogs-datasource/src/types.ts` `QueryType` enum; update pinned commit + constant in `victorialogs.py` |
| Rule loads, query runs, but never fires on matching events | `expr` shape (stats pipe / filter) mismatched with VL stats endpoint | Run the same `expr` against `/select/logsql/stats_query` directly via `curl` to isolate |
| Rule fires but labels/annotations missing | `finalize_query_grafana_alerting` mapping | `sigma/backends/victorialogs/victorialogs.py` |

## Tear-down

```bash
docker compose down -v
```
