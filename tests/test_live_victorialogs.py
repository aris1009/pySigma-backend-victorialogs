"""
End-to-end integration test: convert a curated set of Sigma rules and verify
each emitted query parses against a live VictoriaLogs instance.

Skipped unless `VICTORIALOGS_URL` is set:

    VICTORIALOGS_URL=http://localhost:9428 poetry run pytest tests/test_live_victorialogs.py -v

The cases reuse the same fragments as `dev/show_queries.py` so the human
spot-check tool and CI cover identical ground.
"""

from __future__ import annotations

import os
import urllib.parse
import urllib.request
from collections.abc import Iterable

import pytest
from sigma.collection import SigmaCollection

from sigma._dev.wrap import wrap_query
from sigma.backends.victorialogs import VictoriaLogsBackend

VL_URL = os.environ.get("VICTORIALOGS_URL")
pytestmark = pytest.mark.skipif(
    not VL_URL, reason="set VICTORIALOGS_URL=http://host:9428 to enable"
)


# (name, sigma yaml). Mirrors dev/show_queries.py — kept here so both consumers
# stay in lockstep and the fragment list lives next to the assertions.
CASES: list[tuple[str, str]] = [
    ("simple_eq", "    sel:\n        fieldA: valueA\n    condition: sel"),
    (
        "and_two_fields",
        "    sel:\n        fieldA: valueA\n        fieldB: valueB\n    condition: sel",
    ),
    (
        "or_via_in_list",
        "    sel:\n        fieldA:\n            - v1\n            - v2\n            - v3\n"
        "    condition: sel",
    ),
    ("contains", "    sel:\n        fieldA|contains: needle\n    condition: sel"),
    ("startswith", "    sel:\n        fieldA|startswith: prefix\n    condition: sel"),
    ("endswith", "    sel:\n        fieldA|endswith: .exe\n    condition: sel"),
    ("regex", "    sel:\n        fieldA|re: foo.*bar\n    condition: sel"),
    ("cidr", "    sel:\n        src_ip|cidr: 192.168.0.0/16\n    condition: sel"),
    ("compare_gte", "    sel:\n        bytes|gte: 1024\n    condition: sel"),
    ("exists_true", "    sel:\n        fieldA|exists: true\n    condition: sel"),
    ("exists_false", "    sel:\n        fieldA|exists: false\n    condition: sel"),
    ("fieldref", "    sel:\n        fieldA|fieldref: fieldB\n    condition: sel"),
    ("unbound_keyword", "    keywords:\n        - badword\n    condition: keywords"),
    # Regression: a keyword that contains a literal ` | ` must round-trip
    # through the wrap helper without being mis-split into a fake pipe stage.
    # Real corpus rules emit shapes like this.
    (
        "unbound_keyword_with_pipe",
        "    keywords:\n        - 'wget * - http* | sh'\n    condition: keywords",
    ),
    ("negation", "    sel:\n        fieldA: bad\n    condition: not sel"),
    ("case_sensitive", "    sel:\n        fieldA|cased: ExactCase\n    condition: sel"),
    ("wildcard_in_value", "    sel:\n        fieldA: foo*bar\n    condition: sel"),
    ("single_char_wildcard", "    sel:\n        fieldA: foo?bar\n    condition: sel"),
    ("bare_wildcard_value", "    sel:\n        fieldA: '*'\n    condition: sel"),
    # CIDR — IPv6 + mixed (IPv6 family dispatch regression)
    ("cidr_ipv6", "    sel:\n        src_ip|cidr: ::1/128\n    condition: sel"),
    ("cidr_ipv6_link_local", "    sel:\n        src_ip|cidr: fe80::/10\n    condition: sel"),
    (
        "cidr_mixed_v4_v6",
        "    sel:\n"
        "        src_ip|cidr:\n"
        "            - 10.0.0.0/8\n"
        "            - ::1/128\n"
        "    condition: sel",
    ),
    # Sigma literal `\*` / `\?` source escapes (escape-preservation regression)
    ("literal_star_escape", "    sel:\n        path: '\\*foo'\n    condition: sel"),
    ("literal_question_escape", "    sel:\n        path: 'foo\\?bar'\n    condition: sel"),
    (
        "literal_star_with_backslash_run",
        "    sel:\n        path: '\\\\\\*\\IPC$'\n    condition: sel",
    ),
    (
        "literal_question_with_backslash_run",
        "    sel:\n        path: '\\\\\\?\\GLOBALROOT\\Device'\n    condition: sel",
    ),
]

CORRELATION_CASES: list[tuple[str, str]] = [
    (
        "event_count_correlation",
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
    ),
    (
        "value_count_correlation",
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
    ),
]


def _wrap(query: str) -> str:
    """Thin alias for `sigma._dev.wrap.wrap_query`. Kept so the test reads as
    `_wrap(q)` without leaking the helper's name."""
    return wrap_query(query)


def _logsql_parses(query: str) -> tuple[bool, str]:
    assert VL_URL  # narrows for type checker
    url = f"{VL_URL}/select/logsql/query?" + urllib.parse.urlencode({"query": query, "limit": "1"})
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
            return True, ""
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        return False, f"HTTP {exc.code}: {body[:200]}"


def _all_cases() -> Iterable[tuple[str, str]]:
    yield from CASES
    yield from CORRELATION_CASES


@pytest.fixture(scope="module")
def backend() -> VictoriaLogsBackend:
    return VictoriaLogsBackend()


@pytest.mark.parametrize("name,detection", CASES, ids=[n for n, _ in CASES])
def test_simple_query_parses_live(backend, name, detection):
    yaml = f"""
title: T
status: test
logsource:
    category: test
detection:
{detection}
"""
    queries = backend.convert(SigmaCollection.from_yaml(yaml))
    assert queries, f"no query produced for {name}"
    for q in queries:
        wrapped = _wrap(q)
        ok, err = _logsql_parses(wrapped)
        assert ok, f"{name}: {q!r} -> {err}"


@pytest.mark.parametrize("name,yaml", CORRELATION_CASES, ids=[n for n, _ in CORRELATION_CASES])
def test_correlation_query_parses_live(backend, name, yaml):
    queries = backend.convert(SigmaCollection.from_yaml(yaml))
    assert queries, f"no query produced for {name}"
    for q in queries:
        wrapped = _wrap(q)
        ok, err = _logsql_parses(wrapped)
        assert ok, f"{name}: {q!r} -> {err}"
