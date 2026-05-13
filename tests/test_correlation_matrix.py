"""
Correlation matrix.

Pins the LogsQL stats-pipe shape across:
- `event_count` and `value_count`
- single, multi-field, and absent group-by
- every supported timespan unit (s/m/h/d)
- every supported condition operator (gte/lte/gt/lt/eq)

Temporal correlations are intentionally absent — see test_backend_victorialogs.py::test_temporal_correlation_is_unsupported.
"""

import pytest
from sigma.collection import SigmaCollection

from sigma.backends.victorialogs import VictoriaLogsBackend


@pytest.fixture
def backend() -> VictoriaLogsBackend:
    return VictoriaLogsBackend()


def _convert(backend: VictoriaLogsBackend, yaml: str) -> str:
    out = backend.convert(SigmaCollection.from_yaml(yaml))
    assert isinstance(out, list) and len(out) == 1
    return out[0]


def _event_count_rule(*, group_by: str, timespan: str, op: str, count: int) -> str:
    return f"""
title: parent
name: parent_rule
status: test
logsource: {{ category: test }}
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
    group-by: {group_by}
    timespan: {timespan}
    condition:
        {op}: {count}
"""


def _value_count_rule(
    *, group_by: str, count_field: str, timespan: str, op: str, count: int
) -> str:
    return f"""
title: parent
name: parent_rule
status: test
logsource: {{ category: test }}
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
    group-by: {group_by}
    timespan: {timespan}
    condition:
        {op}: {count}
        field: {count_field}
"""


# ----------------------------- timespan units ---------------------------------


@pytest.mark.parametrize(
    "timespan",
    ["1s", "30s", "5m", "1h", "24h", "1d", "7d"],
)
def test_event_count_timespan_units(backend, timespan):
    q = _convert(
        backend,
        _event_count_rule(group_by="fieldB", timespan=timespan, op="gte", count=10),
    )
    assert q == (
        f'_time:{timespan} fieldA:="x" | stats by (fieldB) count() as event_count'
        " | filter event_count:>=10"
    )


# ----------------------------- condition operators ----------------------------


@pytest.mark.parametrize(
    "op, expected_op",
    [
        ("gte", ">="),
        ("gt", ">"),
        ("lte", "<="),
        ("lt", "<"),
        ("eq", "=="),
    ],
)
def test_event_count_condition_operators(backend, op, expected_op):
    q = _convert(
        backend,
        _event_count_rule(group_by="fieldB", timespan="5m", op=op, count=3),
    )
    assert q.endswith(f"| filter event_count:{expected_op}3")


@pytest.mark.parametrize(
    "op, expected_op",
    [
        ("gte", ">="),
        ("gt", ">"),
        ("lte", "<="),
        ("lt", "<"),
        ("eq", "=="),
    ],
)
def test_value_count_condition_operators(backend, op, expected_op):
    q = _convert(
        backend,
        _value_count_rule(group_by="fieldB", count_field="fieldC", timespan="5m", op=op, count=2),
    )
    assert q.endswith(f"| filter value_count:{expected_op}2")


# ----------------------------- group-by shapes --------------------------------


def test_event_count_multi_field_groupby(backend):
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
    group-by:
        - fieldB
        - fieldC
    timespan: 5m
    condition:
        gte: 4
""",
    )
    assert q == (
        '_time:5m fieldA:="x" | stats by (fieldB, fieldC) count() as event_count'
        " | filter event_count:>=4"
    )


def test_value_count_multi_field_groupby(backend):
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
    group-by:
        - fieldB
        - fieldC
    timespan: 1h
    condition:
        gte: 5
        field: fieldD
""",
    )
    assert q == (
        '_time:1h fieldA:="x" | stats by (fieldB, fieldC) count_uniq(fieldD) as value_count'
        " | filter value_count:>=5"
    )


# ----------------------------- search clause variations -----------------------


def test_correlation_with_complex_search(backend):
    """The `<search>` clause carries the converted parent rule verbatim — every
    construct the base backend supports should compose with the stats pipe."""
    q = _convert(
        backend,
        """
title: parent
name: parent_rule
status: test
logsource: { category: test }
detection:
    sel:
        program: sshd
        message|contains: "Failed password"
    condition: sel
---
title: corr
status: test
correlation:
    type: event_count
    rules: parent_rule
    group-by: src_ip
    timespan: 5m
    condition:
        gte: 5
""",
    )
    assert q == (
        '_time:5m program:="sshd" AND message:"Failed password" '
        "| stats by (src_ip) count() as event_count "
        "| filter event_count:>=5"
    )
