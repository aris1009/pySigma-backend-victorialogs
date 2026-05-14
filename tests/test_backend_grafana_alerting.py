"""
Unit tests for the ``grafana_alerting`` output format.

Asserts the emitted YAML round-trips through ``yaml.safe_load`` into the exact
shape Grafana's provisioning loader expects. Structural validity against a
live Grafana is covered by the container test under ``tests/e2e/``.
"""

from __future__ import annotations

import hashlib

import pytest
import yaml as pyyaml
from sigma.collection import SigmaCollection

from sigma.backends.victorialogs import VictoriaLogsBackend


@pytest.fixture
def backend() -> VictoriaLogsBackend:
    return VictoriaLogsBackend()


def _convert(backend: VictoriaLogsBackend, yaml_text: str) -> dict:
    out = backend.convert(SigmaCollection.from_yaml(yaml_text), output_format="grafana_alerting")
    assert isinstance(out, str), f"expected YAML str, got {out!r}"
    doc = pyyaml.safe_load(out)
    assert isinstance(doc, dict)
    return doc


def _rule_yaml(*, with_id: bool = True, title: str = "T", level: str | None = None) -> str:
    parts = [f"title: {title}", "status: test"]
    if with_id:
        parts.append("id: 12345678-1234-1234-1234-123456789abc")
    if level:
        parts.append(f"level: {level}")
    parts.extend(
        [
            "logsource: { category: test }",
            "detection:",
            "    sel:",
            "        fieldA: valueA",
            "    condition: sel",
        ]
    )
    return "\n".join(parts) + "\n"


def test_format_registered(backend):
    assert "grafana_alerting" in backend.formats
    assert "Grafana" in backend.formats["grafana_alerting"]


def test_envelope_is_apiversion_1_provisioning_doc(backend):
    doc = _convert(backend, _rule_yaml())
    assert doc["apiVersion"] == 1
    assert list(doc.keys()) == ["apiVersion", "groups"]
    assert len(doc["groups"]) == 1
    group = doc["groups"][0]
    assert group["orgId"] == 1
    assert group["name"] == "sigma"
    assert group["folder"] == "sigma"
    assert group["interval"] == "1m"
    assert len(group["rules"]) == 1


def test_minimal_rule_shape(backend):
    """Top-level alert-rule fields match Grafana's provisioning schema."""
    rule = _convert(backend, _rule_yaml())["groups"][0]["rules"][0]
    assert rule["uid"] == "12345678-1234-1234-1234-123456789abc"
    assert rule["title"] == "T"
    assert rule["condition"] == "B"
    assert rule["for"] == "0s"
    assert rule["noDataState"] == "OK"
    assert rule["execErrState"] == "OK"
    assert rule["isPaused"] is False
    assert rule["annotations"]["summary"] == "T"
    # No level → no severity label; id is present so sigma_id is set.
    assert rule["labels"] == {"sigma_id": "12345678-1234-1234-1234-123456789abc"}


def test_data_array_is_two_node_query_plus_threshold(backend):
    """refId A: VL stats query; refId B: threshold > 0; condition references B."""
    rule = _convert(backend, _rule_yaml())["groups"][0]["rules"][0]
    assert rule["condition"] == "B"
    assert len(rule["data"]) == 2

    a, b = rule["data"]
    # A — datasource query
    assert a["refId"] == "A"
    assert a["queryType"] == "stats"
    assert a["relativeTimeRange"] == {"from": 600, "to": 0}
    assert a["datasourceUid"] == "victorialogs"
    assert a["model"]["refId"] == "A"
    assert a["model"]["datasource"] == {
        "type": "victoriametrics-logs-datasource",
        "uid": "victorialogs",
    }
    assert a["model"]["queryType"] == "stats"
    assert "| stats count() as matches | filter matches:>0" in a["model"]["expr"]

    # B — server-side threshold expression
    assert b["refId"] == "B"
    assert b["datasourceUid"] == "__expr__"
    assert b["model"]["type"] == "threshold"
    assert b["model"]["expression"] == "A"
    assert b["model"]["datasource"] == {"type": "__expr__", "uid": "__expr__"}
    cond = b["model"]["conditions"][0]
    assert cond["evaluator"] == {"type": "gt", "params": [0]}
    assert cond["type"] == "query"


@pytest.mark.parametrize(
    ("sigma_level", "expected_severity"),
    [
        ("critical", "critical"),
        ("high", "warning"),
        ("medium", "info"),
        ("low", "info"),
        ("informational", "info"),
    ],
)
def test_severity_mapping(backend, sigma_level, expected_severity):
    """Sigma level → Grafana severity follows the documented bucket map."""
    doc = _convert(backend, _rule_yaml(level=sigma_level))
    assert doc["groups"][0]["rules"][0]["labels"]["severity"] == expected_severity


def test_uid_from_sigma_id_passes_through(backend):
    """Sigma UUIDs (36 chars with hyphens) are valid Grafana UIDs unchanged."""
    rule = _convert(backend, _rule_yaml(with_id=True))["groups"][0]["rules"][0]
    assert rule["uid"] == "12345678-1234-1234-1234-123456789abc"


def test_uid_fallback_is_md5_prefix_of_title(backend):
    """When Sigma id is absent, derive a 14-char MD5 prefix of the title."""
    rule = _convert(backend, _rule_yaml(with_id=False, title="My Detection"))["groups"][0]["rules"][
        0
    ]
    expected = hashlib.md5(b"My Detection").hexdigest()[:14]
    assert rule["uid"] == expected
    assert len(rule["uid"]) == 14


def test_uid_is_within_grafana_constraints(backend):
    """Sigma id is a UUID (36 chars, [0-9a-f-]) — fits Grafana's <=40 / [A-Za-z0-9_-]."""
    rule = _convert(backend, _rule_yaml(with_id=True))["groups"][0]["rules"][0]
    uid = rule["uid"]
    assert len(uid) <= 40
    assert all(c.isalnum() or c in "_-" for c in uid)

    # Fallback path (no id) — MD5 prefix is 14 chars of hex.
    rule_no_id = _convert(backend, _rule_yaml(with_id=False))["groups"][0]["rules"][0]
    assert len(rule_no_id["uid"]) == 14
    assert all(c in "0123456789abcdef" for c in rule_no_id["uid"])


def test_datasource_uid_override():
    """-O grafana_datasource_uid plumbs into AlertQuery and model.datasource."""
    backend = VictoriaLogsBackend(grafana_datasource_uid="vl-prod-7")
    rule = _convert(backend, _rule_yaml())["groups"][0]["rules"][0]
    a = rule["data"][0]
    assert a["datasourceUid"] == "vl-prod-7"
    assert a["model"]["datasource"]["uid"] == "vl-prod-7"


def test_folder_org_interval_overrides():
    backend = VictoriaLogsBackend(
        grafana_folder="security",
        grafana_org_id=42,
        grafana_interval="30s",
        grafana_relative_time_from=300,
    )
    doc = _convert(backend, _rule_yaml())
    group = doc["groups"][0]
    assert group["folder"] == "security"
    assert group["orgId"] == 42
    assert group["interval"] == "30s"
    assert doc["groups"][0]["rules"][0]["data"][0]["relativeTimeRange"]["from"] == 300


def test_full_metadata_annotations_and_labels(backend):
    yaml_text = """
title: Suspicious Activity
id: 11111111-1111-1111-1111-111111111111
status: test
description: Detects suspicious activity.
references:
  - https://example.com/a
  - https://example.com/b
level: critical
logsource: { category: test }
detection:
    sel: { fieldA: a }
    condition: sel
"""
    rule = _convert(backend, yaml_text)["groups"][0]["rules"][0]
    assert rule["annotations"]["summary"] == "Suspicious Activity"
    assert rule["annotations"]["description"] == "Detects suspicious activity."
    assert rule["annotations"]["references"] == "https://example.com/a\nhttps://example.com/b"
    assert rule["labels"] == {
        "severity": "critical",
        "sigma_id": "11111111-1111-1111-1111-111111111111",
    }


def test_stats_pipe_wrap_not_doubled_for_correlations(backend):
    """Correlation rules already emit `| stats …`; the wrap must not re-apply."""
    yaml_text = """
title: parent
name: parent
status: test
logsource: { category: test }
detection:
    sel: { fieldA: a }
    condition: sel
---
title: corr
status: test
correlation:
    type: event_count
    rules: [parent]
    group-by: actor
    timespan: 5m
    condition:
        gte: 10
"""
    out = VictoriaLogsBackend().convert(
        SigmaCollection.from_yaml(yaml_text),
        output_format="grafana_alerting",
    )
    doc = pyyaml.safe_load(out)
    rules = doc["groups"][0]["rules"]
    assert len(rules) == 1
    expr = rules[0]["data"][0]["model"]["expr"]
    assert "| stats " in expr
    assert expr.count("| stats ") == 1
    assert "matches:>0" not in expr


def test_multi_rule_collection_emits_one_group(backend):
    yaml_text = """
title: rule_one
id: 11111111-1111-1111-1111-111111111111
status: test
logsource: { category: test }
detection:
    sel: { fieldA: a }
    condition: sel
---
title: rule_two
id: 22222222-2222-2222-2222-222222222222
status: test
logsource: { category: test }
detection:
    sel: { fieldB: b }
    condition: sel
"""
    doc = _convert(backend, yaml_text)
    rules = doc["groups"][0]["rules"]
    assert [r["title"] for r in rules] == ["rule_one", "rule_two"]
    assert [r["uid"] for r in rules] == [
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
    ]


def test_output_is_safe_dump_yaml(backend):
    """Emitted YAML must parse back via safe_load — no python-specific tags."""
    out = VictoriaLogsBackend().convert(
        SigmaCollection.from_yaml(_rule_yaml()),
        output_format="grafana_alerting",
    )
    assert isinstance(out, str)
    # safe_load would raise on python/object: tags.
    pyyaml.safe_load(out)
