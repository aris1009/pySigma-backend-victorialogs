"""
Unit tests for the VictoriaLogs backend.

Each test asserts the **exact** LogsQL output for a known Sigma input. Every
expected string in this file has been independently validated against a live
VictoriaLogs instance (see `dev/validate_queries.sh`); a regression here means
either a backend change or a deliberate output reformat that should also be
re-validated.
"""

import pytest
from sigma.collection import SigmaCollection

from sigma.backends.victorialogs import VictoriaLogsBackend


@pytest.fixture
def backend() -> VictoriaLogsBackend:
    return VictoriaLogsBackend()


def test_placeholder_pipeline_loads():
    """Phase 1 ships a no-op pipeline; assert it imports and constructs.
    Phase 3 fills it with real log-source mappings."""
    from sigma.pipelines.victorialogs import victorialogs_pipeline

    pipeline = victorialogs_pipeline()
    assert pipeline.name == "VictoriaLogs placeholder pipeline"
    assert pipeline.priority == 20
    assert pipeline.items == []


def _convert(backend: VictoriaLogsBackend, yaml: str) -> str:
    out = backend.convert(SigmaCollection.from_yaml(yaml))
    assert isinstance(out, list) and len(out) == 1, f"expected one query, got {out!r}"
    return out[0]


def _rule(detection: str) -> str:
    return f"""
title: T
status: test
logsource:
    category: test
detection:
{detection}
"""


# ----------------------------- equality / boolean -----------------------------


def test_simple_eq(backend):
    q = _convert(backend, _rule("    sel:\n        fieldA: valueA\n    condition: sel"))
    assert q == 'fieldA:="valueA"'


def test_and_two_fields(backend):
    q = _convert(
        backend,
        _rule("    sel:\n        fieldA: valueA\n        fieldB: valueB\n    condition: sel"),
    )
    assert q == 'fieldA:="valueA" AND fieldB:="valueB"'


def test_or_via_in_list(backend):
    q = _convert(
        backend,
        _rule(
            "    sel:\n"
            "        fieldA:\n"
            "            - v1\n"
            "            - v2\n"
            "            - v3\n"
            "    condition: sel"
        ),
    )
    assert q == 'fieldA:in("v1", "v2", "v3")'


def test_negation(backend):
    q = _convert(backend, _rule("    sel:\n        fieldA: bad\n    condition: not sel"))
    assert q == 'NOT fieldA:="bad"'


# ----------------------------- string modifiers -------------------------------


def test_contains_uses_native_phrase_filter(backend):
    """Plain `contains` should use LogsQL's native phrase filter, not regex —
    it's faster and avoids regex-injection issues for plain values."""
    q = _convert(backend, _rule("    sel:\n        fieldA|contains: needle\n    condition: sel"))
    assert q == 'fieldA:"needle"'


def test_startswith_uses_native_prefix(backend):
    q = _convert(backend, _rule("    sel:\n        fieldA|startswith: prefix\n    condition: sel"))
    assert q == 'fieldA:="prefix"*'


def test_endswith_emits_regex_with_suffix_anchor(backend):
    q = _convert(backend, _rule("    sel:\n        fieldA|endswith: .exe\n    condition: sel"))
    # LogsQL requires backslashes inside a double-quoted regex to be doubled
    # (docs: "the \ char inside the regexp must be encoded as \\"). The literal
    # `.` in the Sigma value becomes `\.` in regex, then `\\.` after string-escape.
    assert q == 'fieldA:~"\\\\.exe$"'


def test_regex_modifier(backend):
    q = _convert(backend, _rule("    sel:\n        fieldA|re: foo.*bar\n    condition: sel"))
    assert q == 'fieldA:~"foo.*bar"'


def test_wildcard_inside_value_routed_to_regex(backend):
    q = _convert(backend, _rule("    sel:\n        fieldA: foo*bar\n    condition: sel"))
    assert q == 'fieldA:~"foo.*bar"'


def test_single_char_wildcard_routes_to_regex(backend):
    """Regression: `wildcard_single = '?'` must remain set
    (non-None) so pySigma routes Sigma single-char wildcard values through the
    regex template. Setting it to None would make the backend refuse the rule
    entirely; resetting it to anything else would change the emitted regex."""
    q = _convert(backend, _rule("    sel:\n        fieldA: foo?bar\n    condition: sel"))
    assert q == 'fieldA:~"foo.bar"'


def test_cased_modifier_uses_exact_match(backend):
    q = _convert(backend, _rule("    sel:\n        fieldA|cased: ExactCase\n    condition: sel"))
    assert q == 'fieldA:="ExactCase"'


# ----------------------------- numeric / range --------------------------------


def test_compare_gte(backend):
    q = _convert(backend, _rule("    sel:\n        bytes|gte: 1024\n    condition: sel"))
    assert q == "bytes:>=1024"


def test_compare_lt(backend):
    q = _convert(backend, _rule("    sel:\n        bytes|lt: 100\n    condition: sel"))
    assert q == "bytes:<100"


# ----------------------------- CIDR / IP --------------------------------------


def test_cidr_emits_ipv4_range(backend):
    q = _convert(
        backend, _rule("    sel:\n        src_ip|cidr: 192.168.0.0/16\n    condition: sel")
    )
    assert q == 'src_ip:ipv4_range("192.168.0.0/16")'


def test_cidr_ipv6_emits_ipv6_range(backend):
    """Regression: bare IPv6 CIDR was being routed through
    `ipv4_range`, which VL rejects with HTTP 400."""
    q = _convert(backend, _rule("    sel:\n        src_ip|cidr: ::1/128\n    condition: sel"))
    assert q == 'src_ip:ipv6_range("::1/128")'


def test_cidr_ipv6_link_local(backend):
    """Regression: a representative link-local IPv6 CIDR
    must round-trip through the v6 template unchanged."""
    q = _convert(backend, _rule("    sel:\n        src_ip|cidr: fe80::/10\n    condition: sel"))
    assert q == 'src_ip:ipv6_range("fe80::/10")'


def test_cidr_mixed_v4_v6_list(backend):
    """Regression: a |cidr list mixing v4 and v6 must
    dispatch each network to the correct range function."""
    q = _convert(
        backend,
        _rule(
            "    sel:\n"
            "        src_ip|cidr:\n"
            "            - 10.0.0.0/8\n"
            "            - ::1/128\n"
            "    condition: sel"
        ),
    )
    assert q == 'src_ip:ipv4_range("10.0.0.0/8") OR src_ip:ipv6_range("::1/128")'


# ----------------------------- exists / null ----------------------------------


def test_exists_true(backend):
    q = _convert(backend, _rule("    sel:\n        fieldA|exists: true\n    condition: sel"))
    assert q == "fieldA:*"


def test_exists_false(backend):
    q = _convert(backend, _rule("    sel:\n        fieldA|exists: false\n    condition: sel"))
    assert q == "NOT fieldA:*"


def test_null_value(backend):
    q = _convert(backend, _rule("    sel:\n        fieldA: null\n    condition: sel"))
    assert q == 'fieldA:""'


# ----------------------------- field reference --------------------------------


def test_fieldref(backend):
    q = _convert(backend, _rule("    sel:\n        fieldA|fieldref: fieldB\n    condition: sel"))
    assert q == "fieldA:eq_field(fieldB)"


# ----------------------------- unbound (keyword) ------------------------------


def test_unbound_keyword(backend):
    q = _convert(backend, _rule("    keywords:\n        - badword\n    condition: keywords"))
    assert q == '"badword"'


# ----------------------------- correlations -----------------------------------


def test_event_count_correlation(backend):
    q = _convert(
        backend,
        """
title: parent
name: parent_rule
status: test
logsource: { category: test }
detection:
    sel:
        fieldA: x
    condition: sel
---
title: corr
status: test
correlation:
    type: event_count
    rules: parent_rule
    group-by: fieldB
    timespan: 5m
    condition:
        gte: 10
""",
    )
    assert q == (
        '_time:5m fieldA:="x" | stats by (fieldB) count() as event_count | filter event_count:>=10'
    )


def test_value_count_correlation(backend):
    q = _convert(
        backend,
        """
title: parent
name: parent_rule
status: test
logsource: { category: test }
detection:
    sel:
        fieldA: x
    condition: sel
---
title: corr
status: test
correlation:
    type: value_count
    rules: parent_rule
    group-by: fieldB
    timespan: 5m
    condition:
        gte: 3
        field: fieldC
""",
    )
    assert q == (
        '_time:5m fieldA:="x" | stats by (fieldB) count_uniq(fieldC) as value_count | '
        "filter value_count:>=3"
    )


# ----------------------------- bug-fix regressions ----------------------------


def test_unbound_regex_is_quoted(backend):
    """Regression: an earlier template emitted `_msg:~foo.*bar` (unquoted),
    which LogsQL rejects with `missing whitespace or ':' between "." and "*"`.
    The fix wraps the regex in double quotes."""
    q = _convert(
        backend,
        _rule("    sel:\n        '|re': foo.*bar\n    condition: sel"),
    )
    assert q == '_msg:~"foo.*bar"'


def test_bare_wildcard_value_means_field_exists(backend):
    """Regression: `fieldA: '*'` previously emitted `fieldA:=""*`, which LogsQL
    parses as the AND of an empty equality and a top-level `*` — matching every
    record regardless of fieldA. The override routes single-wildcard values to
    the exists template."""
    q = _convert(backend, _rule("    sel:\n        fieldA: '*'\n    condition: sel"))
    assert q == "fieldA:*"


def test_field_with_whitespace_quoted_without_backslash_escape(backend):
    """Regression: an earlier escape rule prepended a backslash before
    whitespace inside double-quoted field names. Inside `"..."` LogsQL needs no
    such escape and the redundant `\\` was visually noisy. Quotation alone is
    sufficient."""
    q = _convert(backend, _rule("    sel:\n        'My Field': value\n    condition: sel"))
    assert q == '"My Field":="value"'


def test_correlation_includes_timespan_filter(backend):
    """Regression: `_time:{timespan}` was missing from the correlation
    template, so a 5-minute event_count rule evaluated over the entire
    retention window."""
    q = _convert(
        backend,
        """
title: parent
name: parent_rule
status: test
logsource: { category: test }
detection:
    sel:
        fieldA: x
    condition: sel
---
title: corr
status: test
correlation:
    type: event_count
    rules: parent_rule
    group-by: fieldB
    timespan: 30s
    condition:
        gte: 5
""",
    )
    assert q.startswith("_time:30s ")


# ----------------------------- escape edge cases ------------------------------


def test_value_with_double_quote_is_escaped(backend):
    q = _convert(backend, _rule("    sel:\n        fieldA: 'has\"quote'\n    condition: sel"))
    # The `"` inside the value is escaped via the LogsQL string-escape `\"`.
    assert q == 'fieldA:="has\\"quote"'


def test_value_with_backslash_is_escaped(backend):
    q = _convert(
        backend,
        _rule("    sel:\n        fieldA: 'C:\\Windows\\System32'\n    condition: sel"),
    )
    # Backslashes are doubled inside a LogsQL double-quoted string.
    assert q == 'fieldA:="C:\\\\Windows\\\\System32"'


def test_literal_star_escape_emits_bare_star(backend):
    """Regression: the Sigma source escape `\\*` carries a
    LITERAL asterisk through pySigma. Inside a LogsQL `:="..."` value the only
    valid escape sequences are `\\\\` and `\\"`; `\\*` is rejected with
    `compound token cannot start with "\\""`. The literal asterisk must survive
    bare."""
    q = _convert(backend, _rule("    sel:\n        path: '\\*foo'\n    condition: sel"))
    assert q == 'path:="*foo"'


def test_literal_question_escape_emits_bare_question(backend):
    """Regression: same logic as the `\\*` case for `\\?`."""
    q = _convert(backend, _rule("    sel:\n        path: 'foo\\?bar'\n    condition: sel"))
    assert q == 'path:="foo?bar"'


def test_literal_star_escape_with_backslash_run(backend):
    """Regression: the canonical `\\\\*\\IPC$` shadow-copy
    path mixes a real `\\\\` (literal backslash) with a `\\*` (literal asterisk).
    The literal backslashes must double, the literal asterisk must stay bare."""
    q = _convert(backend, _rule("    sel:\n        path: '\\\\\\*\\IPC$'\n    condition: sel"))
    assert q == 'path:="\\\\*\\\\IPC$"'


def test_literal_question_escape_with_backslash_run(backend):
    """Regression: the canonical `\\\\?\\GLOBALROOT\\Device`
    NT-namespace path. Same rules: doubled backslashes, bare `?`."""
    q = _convert(
        backend,
        _rule("    sel:\n        path: '\\\\\\?\\GLOBALROOT\\Device'\n    condition: sel"),
    )
    assert q == 'path:="\\\\?\\\\GLOBALROOT\\\\Device"'


def test_temporal_correlation_is_unsupported(backend):
    """LogsQL has no native multi-event sliding-window join. pySigma raises
    NotImplementedError when it tries to build the multi-rule search expression
    that we deliberately leave undefined."""
    yaml = """
title: parent_a
name: a
status: test
logsource: { category: test }
detection:
    sel:
        fieldA: a
    condition: sel
---
title: parent_b
name: b
status: test
logsource: { category: test }
detection:
    sel:
        fieldA: b
    condition: sel
---
title: corr
status: test
correlation:
    type: temporal
    rules: [a, b]
    group-by: actor
    timespan: 5m
"""
    with pytest.raises(NotImplementedError):
        backend.convert(SigmaCollection.from_yaml(yaml))


# ----------------------------- vmalert output format -----------------------------


def _convert_vmalert(backend: VictoriaLogsBackend, yaml_text: str) -> str:
    out = backend.convert(SigmaCollection.from_yaml(yaml_text), output_format="vmalert")
    assert isinstance(out, str), f"expected YAML str, got {out!r}"
    return out


def test_vmalert_format_registered(backend):
    """vmalert appears in the public formats dict so sigma-cli can list it."""
    assert "vmalert" in backend.formats
    assert "vlogs" in backend.formats["vmalert"]


def test_vmalert_minimal_rule_yaml_roundtrip(backend):
    """A bare rule round-trips through yaml.safe_load and matches schema shape."""
    import yaml as pyyaml

    out = _convert_vmalert(
        backend,
        _rule("    sel:\n        fieldA: valueA\n    condition: sel"),
    )
    doc = pyyaml.safe_load(out)
    assert isinstance(doc, dict) and list(doc.keys()) == ["groups"]
    group = doc["groups"][0]
    assert group["name"] == "Sigma rules"
    assert group["type"] == "vlogs"
    assert group["interval"] == "5m"
    rules = group["rules"]
    assert len(rules) == 1
    rule = rules[0]
    assert rule["alert"] == "T"
    assert rule["expr"] == 'fieldA:="valueA" | stats count() as matches | filter matches:>0'
    assert rule["for"] == "0s"
    assert rule["labels"] == {}
    assert rule["annotations"] == {"summary": "T"}


def test_vmalert_full_rule_metadata_mapped(backend):
    """All Sigma metadata fields land on the vmalert rule dict."""
    import yaml as pyyaml

    yaml_text = """
title: Suspicious Activity
id: 11111111-1111-1111-1111-111111111111
status: test
description: Detects suspicious activity in the wild.
author: alice
references:
  - https://example.com/a
  - https://example.com/b
level: high
tags:
  - attack.execution
  - attack.t1059
logsource:
    category: test
detection:
    sel:
        fieldA: valueA
    condition: sel
"""
    doc = pyyaml.safe_load(_convert_vmalert(backend, yaml_text))
    rule = doc["groups"][0]["rules"][0]
    assert rule["alert"] == "Suspicious_Activity"
    assert rule["labels"] == {
        "severity": "high",
        "sigma_id": "11111111-1111-1111-1111-111111111111",
    }
    assert rule["annotations"]["summary"] == "Suspicious Activity"
    assert rule["annotations"]["description"] == "Detects suspicious activity in the wild."
    assert rule["annotations"]["author"] == "alice"
    assert rule["annotations"]["tags"] == "attack.execution, attack.t1059"
    assert rule["annotations"]["references"] == "https://example.com/a\nhttps://example.com/b"


def test_vmalert_alert_name_sanitised(backend):
    """Non-[A-Za-z0-9_] characters collapse into _ and edges are stripped."""
    import yaml as pyyaml

    yaml_text = """
title: "  T1059: PowerShell / Encoded * Command!!  "
status: test
logsource: { category: test }
detection:
    sel:
        fieldA: x
    condition: sel
"""
    doc = pyyaml.safe_load(_convert_vmalert(backend, yaml_text))
    assert doc["groups"][0]["rules"][0]["alert"] == "T1059_PowerShell_Encoded_Command"


def test_vmalert_skips_wrap_when_query_already_has_stats(backend):
    """Correlation rules already emit `| stats ...` — don't double-wrap."""
    import yaml as pyyaml

    yaml_text = """
title: parent
name: parent
status: test
logsource: { category: test }
detection:
    sel:
        fieldA: a
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
    out = backend.convert(SigmaCollection.from_yaml(yaml_text), output_format="vmalert")
    doc = pyyaml.safe_load(out)
    rules = doc["groups"][0]["rules"]
    assert len(rules) == 1
    expr = rules[0]["expr"]
    assert "| stats " in expr
    # Must not be double-wrapped.
    assert expr.count("| stats ") == 1
    assert "matches:>0" not in expr


def test_vmalert_multi_rule_collection(backend):
    """Multiple rules produce one group with one rules entry per Sigma rule."""
    import yaml as pyyaml

    yaml_text = """
title: rule_one
status: test
logsource: { category: test }
detection:
    sel:
        fieldA: a
    condition: sel
---
title: rule_two
status: test
logsource: { category: test }
detection:
    sel:
        fieldB: b
    condition: sel
"""
    doc = pyyaml.safe_load(_convert_vmalert(backend, yaml_text))
    rules = doc["groups"][0]["rules"]
    assert [r["alert"] for r in rules] == ["rule_one", "rule_two"]
    assert all("| stats count() as matches" in r["expr"] for r in rules)
