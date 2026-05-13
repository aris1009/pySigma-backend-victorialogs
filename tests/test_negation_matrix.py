"""
Negation matrix.

The base unit suite asserts negation around plain equality. This file expands
to NOT around the full menu of expression shapes — IN-list, exists, regex,
contains/startswith/endswith, CIDR, numeric compare, fieldref, correlation
search — and to small De Morgan trees. Each case asserts the *exact* LogsQL
output so a regression that silently rewrites negation precedence is visible.
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


def _rule(detection: str) -> str:
    return f"""
title: T
status: test
logsource:
    category: test
detection:
{detection}
"""


# ----------------------------- NOT around primitives --------------------------


def test_not_eq(backend):
    q = _convert(backend, _rule("    sel:\n        fieldA: x\n    condition: not sel"))
    assert q == 'NOT fieldA:="x"'


def test_not_in_list(backend):
    """pySigma wraps the in-list in parentheses when negated, even though the
    expression is a single primitive — the grouped form keeps the precedence
    unambiguous if the surrounding shape grows."""
    q = _convert(
        backend,
        _rule(
            "    sel:\n        fieldA:\n            - v1\n            - v2\n    condition: not sel"
        ),
    )
    assert q == 'NOT (fieldA:in("v1", "v2"))'


def test_not_exists(backend):
    q = _convert(backend, _rule("    sel:\n        fieldA|exists: true\n    condition: not sel"))
    assert q == "NOT fieldA:*"


def test_not_contains(backend):
    q = _convert(
        backend, _rule("    sel:\n        fieldA|contains: needle\n    condition: not sel")
    )
    assert q == 'NOT fieldA:"needle"'


def test_not_startswith(backend):
    q = _convert(
        backend, _rule("    sel:\n        fieldA|startswith: prefix\n    condition: not sel")
    )
    assert q == 'NOT fieldA:="prefix"*'


def test_not_endswith(backend):
    q = _convert(backend, _rule("    sel:\n        fieldA|endswith: .exe\n    condition: not sel"))
    assert q == 'NOT fieldA:~"\\\\.exe$"'


def test_not_regex(backend):
    q = _convert(backend, _rule("    sel:\n        fieldA|re: foo.*bar\n    condition: not sel"))
    assert q == 'NOT fieldA:~"foo.*bar"'


def test_not_cidr_v4(backend):
    q = _convert(
        backend,
        _rule("    sel:\n        src_ip|cidr: 10.0.0.0/8\n    condition: not sel"),
    )
    assert q == 'NOT src_ip:ipv4_range("10.0.0.0/8")'


def test_not_cidr_v6(backend):
    q = _convert(backend, _rule("    sel:\n        src_ip|cidr: ::1/128\n    condition: not sel"))
    assert q == 'NOT src_ip:ipv6_range("::1/128")'


def test_not_compare_gte(backend):
    q = _convert(backend, _rule("    sel:\n        bytes|gte: 1024\n    condition: not sel"))
    assert q == "NOT bytes:>=1024"


def test_not_fieldref(backend):
    q = _convert(
        backend,
        _rule("    sel:\n        fieldA|fieldref: fieldB\n    condition: not sel"),
    )
    assert q == "NOT fieldA:eq_field(fieldB)"


def test_not_null(backend):
    q = _convert(backend, _rule("    sel:\n        fieldA: null\n    condition: not sel"))
    assert q == 'NOT fieldA:""'


def test_not_unbound_keyword(backend):
    q = _convert(backend, _rule("    keywords:\n        - badword\n    condition: not keywords"))
    assert q == 'NOT "badword"'


# ----------------------------- De Morgan trees --------------------------------


def test_not_around_and(backend):
    """`not (a and b)` keeps an explicit grouped form so the precedence reads
    correctly to the LogsQL parser."""
    q = _convert(
        backend,
        _rule("    sel:\n        fieldA: a\n        fieldB: b\n    condition: not sel"),
    )
    assert q == 'NOT (fieldA:="a" AND fieldB:="b")'


def test_not_around_or(backend):
    """`not (a or b)` over distinct fields stays grouped."""
    q = _convert(
        backend,
        _rule(
            "    sel1:\n"
            "        fieldA: a\n"
            "    sel2:\n"
            "        fieldB: b\n"
            "    condition: not (sel1 or sel2)"
        ),
    )
    assert q == 'NOT (fieldA:="a" OR fieldB:="b")'


def test_double_negation_preserved(backend):
    """pySigma does NOT eliminate double negation — the AST keeps both NOT
    nodes and the backend renders them. Logically equivalent to `sel`, but
    the LogsQL parser still accepts it (and the explicit form is faithful to
    the rule author's intent)."""
    q = _convert(backend, _rule("    sel:\n        fieldA: x\n    condition: not (not sel)"))
    assert q == 'NOT (NOT fieldA:="x")'


def test_and_with_not_branch(backend):
    """`sel and not other` retains both operators with correct precedence."""
    q = _convert(
        backend,
        _rule(
            "    sel:\n"
            "        fieldA: a\n"
            "    other:\n"
            "        fieldB: b\n"
            "    condition: sel and not other"
        ),
    )
    assert q == 'fieldA:="a" AND NOT fieldB:="b"'


def test_or_with_not_branch(backend):
    """`sel or not other` — OR with a negated rhs."""
    q = _convert(
        backend,
        _rule(
            "    sel:\n"
            "        fieldA: a\n"
            "    other:\n"
            "        fieldB: b\n"
            "    condition: sel or not other"
        ),
    )
    assert q == 'fieldA:="a" OR NOT fieldB:="b"'


# ----------------------------- exists ↔ not exists symmetry -------------------


def test_exists_false_equivalent_to_not_exists(backend):
    """`exists: false` and `not exists: true` should produce equivalent
    LogsQL; both go through `NOT field:*`."""
    q1 = _convert(backend, _rule("    sel:\n        fieldA|exists: false\n    condition: sel"))
    q2 = _convert(backend, _rule("    sel:\n        fieldA|exists: true\n    condition: not sel"))
    assert q1 == q2 == "NOT fieldA:*"
