# pySigma backend for VictoriaLogs (LogsQL)

[![CI](https://github.com/aris1009/pySigma-backend-victorialogs/actions/workflows/test.yml/badge.svg)](https://github.com/aris1009/pySigma-backend-victorialogs/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/pySigma-backend-victorialogs.svg)](https://pypi.org/project/pySigma-backend-victorialogs/)
[![Python](https://img.shields.io/pypi/pyversions/pySigma-backend-victorialogs.svg)](https://pypi.org/project/pySigma-backend-victorialogs/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Convert [Sigma](https://github.com/SigmaHQ/sigma) detection rules to
[LogsQL](https://docs.victoriametrics.com/victorialogs/logsql/) queries
that run against [VictoriaLogs](https://docs.victoriametrics.com/victorialogs/).

```text
Sigma rule (YAML)
        │
        ▼
   pySigma core
        │
        ▼
 VictoriaLogsBackend  ──►  field:="value" AND other:~"regex"
```

---

## Install

The recommended way is via `sigma-cli`'s plugin system:

```bash
pip install sigma-cli
sigma plugin install victorialogs
```

Or directly as a library:

```bash
pip install pysigma-backend-victorialogs
```

## First query

```bash
sigma convert -t victorialogs path/to/rule.yml
```

Programmatic use:

```python
from sigma.collection import SigmaCollection
from sigma.backends.victorialogs import VictoriaLogsBackend

rule = SigmaCollection.from_yaml("""
title: SSH login failure
logsource:
    product: linux
    service: auth
detection:
    sel:
        program: sshd
        message|contains: "Failed password"
    condition: sel
""")

print(VictoriaLogsBackend().convert(rule)[0])
# program:="sshd" AND message:~"Failed password"
```

See [docs/getting_started.md](docs/getting_started.md) for the full
walkthrough including a local VictoriaLogs container.

---

## Compatibility

| Component       | Supported versions     |
|-----------------|------------------------|
| Python          | 3.10, 3.11, 3.12, 3.13, 3.14 |
| pySigma         | `^1.1.0`               |
| VictoriaLogs    | `v1.50.0` (pinned by digest in CI) |

CI pins `victoriametrics/victoria-logs:v1.50.0` by sha256 digest for
reproducibility; bumps follow the procedure in
[CONTRIBUTING.md](CONTRIBUTING.md#bumping-the-pinned-victorialogs-image).
Older or newer VL versions are not actively tested but should work as
long as they parse the LogsQL constructs listed in
[docs/mapping.md](docs/mapping.md).

## Mapping summary

| Sigma feature                | LogsQL output                                            |
|------------------------------|----------------------------------------------------------|
| `field: value`               | `field:="value"`                                         |
| `field\|contains: x`         | `field:~"x"` (regex)                                     |
| `field\|startswith: x`       | `field:="x"*` (native prefix)                            |
| `field\|endswith: x`         | `field:~"x$"` (regex anchor)                             |
| `field\|re: pattern`         | `field:~"pattern"`                                       |
| `field\|cidr: 10.0.0.0/8`    | `field:ipv4_range("10.0.0.0/8")`                         |
| `field\|cidr: ::1/128`       | `field:ipv6_range("::1/128")`                            |
| `field\|gte: 1024`           | `field:>=1024`                                           |
| `field\|fieldref: other`     | `field:eq_field(other)`                                  |
| `field\|exists: true`        | `field:*`                                                |
| `field: null`                | `field:""`                                               |
| field IN [a, b]              | `field:in("a", "b")`                                     |
| event_count correlation      | `_time:Xm <search> \| stats by (g) count() as event_count \| filter event_count:>=N` |

Full reference: [docs/mapping.md](docs/mapping.md).

## Pipelines

Sigma rules use a neutral field taxonomy (`Image`, `CommandLine`,
`EventID`, …) that does not match how any specific log shipper writes
records. Pick a pipeline that matches your ingestion path:

| Pipeline                          | Targets                                 | Renames                                        |
|-----------------------------------|-----------------------------------------|------------------------------------------------|
| `victorialogs`                    | (no-op placeholder)                     | none                                           |
| `victorialogs_windows_eventlog`   | Winlogbeat / Vector ECS Windows ingest  | `EventID`→`winlog.event_id`, EventData→`winlog.event_data.*`, channel selectors |
| `victorialogs_journald`           | systemd-journal native fields           | `Image`→`_EXE`, `CommandLine`→`_CMDLINE`, `Message`→`MESSAGE`, … |
| `victorialogs_caddy`              | Caddy v2 JSON access logs               | `cs-method`→`request.method`, `cs-uri-*`→`request.uri`, `sc-status`→`status`, … |
| `victorialogs_suricata`           | Suricata EVE JSON                       | `dst_ip`→`dest_ip`, `QueryName`→`dns.rrname`, `TlsServerName`→`tls.sni`, … |
| `victorialogs_podman`             | podman/docker journald `CONTAINER_*`    | `ContainerName`→`CONTAINER_NAME`, `ImageName`→`IMAGE_NAME`, … |

```bash
sigma convert -t victorialogs -p victorialogs_journald rule.yml
sigma convert -t victorialogs -p victorialogs_windows_eventlog rule.yml
sigma convert -t victorialogs -p victorialogs_caddy rule.yml
```

Each pipeline applies only to rules whose `logsource` matches its target
(e.g. `product: linux` for journald, `category: webserver` for Caddy,
`category: network` or `product: zeek|suricata` for the EVE pipeline);
other rules pass through untouched. Stack pipelines with multiple `-p`
flags when, for example, podman containers ship through journald.

## Output formats

| Format             | Output                                                           |
|--------------------|------------------------------------------------------------------|
| `default`          | Plain LogsQL query strings (one per rule)                        |
| `vmalert`          | vmalert rule group YAML (`type: vlogs`) for VictoriaLogs         |
| `grafana_alerting` | Grafana Alerting provisioning YAML (apiVersion: 1) for the [victoriametrics-logs-datasource](https://grafana.com/grafana/plugins/victoriametrics-logs-datasource/) plugin |

### vmalert (deploy as alerting rules)

```bash
sigma convert -t victorialogs -f vmalert -p victorialogs_journald \
    rules/*.yml > sigma-rules.yaml
```

The output is a single rule group ready to feed to
[vmalert](https://docs.victoriametrics.com/victorialogs/vmalert/) pointed
at a VictoriaLogs datasource:

```bash
vmalert \
    -datasource.url=http://victorialogs:9428 \
    -rule.defaultRuleType=vlogs \
    -rule=sigma-rules.yaml \
    -notifier.url=http://alertmanager:9093
```

Each Sigma rule becomes one alert with `expr` wrapped as
`<query> | stats count() as matches | filter matches:>0` (correlation
rules already aggregate and pass through unwrapped). vmalert auto-prepends
`_time:<group_interval>`, so the emitted expressions are time-agnostic by
design — change the evaluation window via the group `interval` (default
`5m`) rather than editing every query. Sigma `level` maps to
`labels.severity` and `id` to `labels.sigma_id`. Requires vmalert ≥ v1.93
(when `type: vlogs` was added). See
[docs/mapping.md §14](docs/mapping.md#14-vmalert-output-format) for the
full mapping.

### grafana_alerting (deploy as Grafana provisioned alert rules)

```bash
sigma convert -t victorialogs -f grafana_alerting \
    -O grafana_datasource_uid=<your-vl-uid> \
    rules/*.yml > /etc/grafana/provisioning/alerting/sigma.yaml
```

The output is an `apiVersion: 1` provisioning document that Grafana loads
on boot. Pass the UID of the VictoriaLogs datasource as configured in
your Grafana install — the placeholder default (`victorialogs`) keeps the
emitted YAML valid but will not load until substituted.

Each Sigma rule becomes one alert rule with a two-node `data` array:

* refId `A` runs the LogsQL stats query against the
  [victoriametrics-logs-datasource](https://grafana.com/grafana/plugins/victoriametrics-logs-datasource/)
  plugin's `/select/logsql/stats_query` endpoint (Grafana ≥ 10.4 required).
* refId `B` is a server-side threshold expression that fires when A returns
  a non-zero count. `condition: B` is the rule's firing condition.

The Sigma → Grafana severity bucket is:

| Sigma `level`   | `labels.severity` |
|-----------------|-------------------|
| `critical`      | `critical`        |
| `high`          | `warning`         |
| `medium`        | `info`            |
| `low`           | `info`            |
| `informational` | `info`            |

Backend options (`-O <name>=<value>`):

| Option                       | Default        | Meaning                                                |
|------------------------------|----------------|--------------------------------------------------------|
| `grafana_datasource_uid`     | `victorialogs` | UID of the VictoriaLogs datasource in your Grafana.    |
| `grafana_folder`             | `sigma`        | Folder the alert-rule group is stored in.              |
| `grafana_org_id`             | `1`            | Grafana org ID.                                        |
| `grafana_interval`           | `1m`           | Group evaluation interval.                             |
| `grafana_relative_time_from` | `600`          | Lookback in seconds for the query (`to` is always 0).  |

Deploying the rule provisioning file does **not** create the VictoriaLogs
datasource itself — provision the datasource separately, then point the
generated rules at it via `grafana_datasource_uid`. A complete deployment
walkthrough (datasource provisioning + alert provisioning + alert-firing
sanity check) lives at
[tests/e2e/grafana_alerting/README.md](tests/e2e/grafana_alerting/README.md).

## Limitations

- **Temporal correlations** (`temporal`, `temporal_ordered`) are
  unsupported — LogsQL has no native multi-event window join.
- **`-search.maxQueryLen`** defaults to 16 KiB; seven SigmaHQ rules
  emit queries above this. Raise the flag at VL startup if you need
  them: `victoria-logs -search.maxQueryLen=524288 ...`
- **No native single-character wildcard** — Sigma `?` routes to regex.
- **Case-sensitivity** is the default (LogsQL `:=`).

Full details and workarounds: [docs/limitations.md](docs/limitations.md).

## Verifying releases

From v0.2.0 onward, every tagged release is signed with [Sigstore][sigstore]
via GitHub Actions OIDC. The signature bundles (`*.sigstore.json`) are attached
to the corresponding GitHub release; the wheel and sdist on PyPI also carry a
[PEP 740][pep740] attestation (shown as a "Verified" badge on pypi.org).

Verify a downloaded artefact with [`sigstore-python`][sigstore-python]:

```bash
gh release download v0.2.0 \
  --repo aris1009/pySigma-backend-victorialogs \
  --pattern '*.whl' --pattern '*.whl.sigstore.json'

pip install sigstore
sigstore verify github \
  --cert-identity "https://github.com/aris1009/pySigma-backend-victorialogs/.github/workflows/release-please.yml@refs/heads/main" \
  pysigma_backend_victorialogs-0.2.0-py3-none-any.whl
```

The `cert-identity` is the path of the workflow that produced the signature;
because release-please publishes on push-to-`main`, the ref is `refs/heads/main`
rather than the release tag.

[sigstore]: https://www.sigstore.dev/
[sigstore-python]: https://github.com/sigstore/sigstore-python
[pep740]: https://peps.python.org/pep-0740/

## Documentation

- [Getting started](docs/getting_started.md) — install → first query → live VL.
- [Mapping reference](docs/mapping.md) — exhaustive Sigma → LogsQL spec.
- [Architecture](docs/architecture.md) — how the backend works (for contributors).
- [Limitations](docs/limitations.md) — what we cannot do, and why.
- [Security policy](SECURITY.md) — threat model + reporting.
- [Contributing](CONTRIBUTING.md) — dev setup + Conventional Commits.

## License

[MIT](LICENSE) © aris1009
