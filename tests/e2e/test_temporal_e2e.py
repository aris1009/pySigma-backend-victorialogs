"""End-to-end temporal correlation correctness against a recorded log slice.

The fixture is a 10-minute projection of recorded journald events, derived by
``dev/derive_fixture.py``. Rows carry ``offset_ms``, ``_HOSTNAME`` and
``SYSLOG_IDENTIFIER``; hosts are labelled by activity rank and times are
relative to the slice start. Each case selects rows from that slice, rebases
them so the last row lands at "now" (see ``ingest_fixture_rebased``), converts
a Sigma temporal rule and asserts the number of returned stats rows.

Cases cover the three ways a temporal match can fail to be a match:

* ``reversed``      - both rules fired, but in the opposite order (ordered only)
* ``out_of_window`` - both rules fired, further apart than the timespan
* ``b_only``        - rule B fired on a host where rule A never did
  (regression: without the ``t0:* t1:*`` guards, ``lt_field`` accepts the
  empty ``t0`` and reports a false positive)

Gated behind the ``e2e`` marker; bring the stack up with ``make e2e-up``.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest
from sigma.collection import SigmaCollection

from sigma.backends.victorialogs import VictoriaLogsBackend
from tests.e2e._runtime import (
    ingest_fixture_rebased,
    logsql_query,
    wait_until_count,
)

pytestmark = pytest.mark.e2e

FIXTURE = Path(__file__).parent / "fixtures" / "journald_temporal_cases.ndjson"
STREAM_FIELDS = "dataset_label,SYSLOG_IDENTIFIER"
TIMESPAN_MS = 300_000


def _by(rows: list[dict], host: str, ident: str) -> list[dict]:
    return [r for r in rows if r["_HOSTNAME"] == host and r["SYSLOG_IDENTIFIER"] == ident]


def _after(base: dict, candidates: list[dict], *, min_gap: int, max_gap: int | None) -> dict:
    for candidate in candidates:
        gap = candidate["offset_ms"] - base["offset_ms"]
        if gap < min_gap:
            continue
        if max_gap is not None and gap > max_gap:
            break
        return candidate
    raise AssertionError(f"fixture has no partner for {base} within [{min_gap}, {max_gap}]")


def _cases() -> dict[str, tuple[list[dict], str, str, int, int]]:
    """name -> (rows, first rule identifier, second rule identifier, temporal, ordered)."""
    rows = [json.loads(line) for line in FIXTURE.read_text().splitlines() if line.strip()]
    sudo = _by(rows, "host-a", "sudo")
    systemd = _by(rows, "host-a", "systemd")

    first_sudo = sudo[0]
    in_window = [first_sudo, _after(first_sudo, systemd, min_gap=0, max_gap=TIMESPAN_MS)]
    first_systemd = systemd[0]
    reversed_pair = [first_systemd, _after(first_systemd, sudo, min_gap=0, max_gap=TIMESPAN_MS)]
    out_of_window = [first_sudo, _after(first_sudo, systemd, min_gap=TIMESPAN_MS + 1, max_gap=None)]
    b_only = [_by(rows, "host-b", "systemd")[0]]

    return {
        "in_window": (in_window, "sudo", "systemd", 1, 1),
        # Same rules, opposite arrival order: temporal still matches, ordered must not.
        "reversed": (reversed_pair, "sudo", "systemd", 1, 0),
        "out_of_window": (out_of_window, "sudo", "systemd", 0, 0),
        "b_only": (b_only, "sudo", "systemd", 0, 0),
    }


CASES = _cases()


def _rule(first: str, second: str, correlation_type: str) -> str:
    return f"""
title: parent_a
name: parent_a
status: test
logsource: {{ category: test }}
detection:
    sel:
        SYSLOG_IDENTIFIER: {first}
    condition: sel
---
title: parent_b
name: parent_b
status: test
logsource: {{ category: test }}
detection:
    sel:
        SYSLOG_IDENTIFIER: {second}
    condition: sel
---
title: corr
status: test
correlation:
    type: {correlation_type}
    rules: [parent_a, parent_b]
    group-by: _HOSTNAME
    timespan: 5m
"""


def _convert(first: str, second: str, correlation_type: str) -> str:
    queries = VictoriaLogsBackend().convert(
        SigmaCollection.from_yaml(_rule(first, second, correlation_type))
    )
    assert isinstance(queries, list) and len(queries) == 1
    return queries[0]


@pytest.mark.parametrize("name", list(CASES), ids=list(CASES))
def test_temporal_correlation_matches_only_real_co_occurrences(vl_url: str, name: str) -> None:
    rows, first, second, expected_temporal, expected_ordered = CASES[name]
    label = f"temporal-{uuid.uuid4().hex[:8]}-{name}"
    ingest_fixture_rebased(vl_url, rows, stream_fields=STREAM_FIELDS, dataset_label=label)
    # Ingest is asynchronous; the raw rows must be visible before the stats query runs.
    wait_until_count(vl_url, f'dataset_label:="{label}"', expected=len(rows))

    for correlation_type, expected in (
        ("temporal", expected_temporal),
        ("temporal_ordered", expected_ordered),
    ):
        query = f'dataset_label:="{label}" AND {_convert(first, second, correlation_type)}'
        if expected:
            got = wait_until_count(vl_url, query, expected=expected)
        else:
            got = len(logsql_query(vl_url, query))
        assert got == expected, (
            f"{name}/{correlation_type}: expected {expected} stats rows, got {got}.\n"
            f"  query: {query}\n"
            f"  rows: {rows}"
        )
