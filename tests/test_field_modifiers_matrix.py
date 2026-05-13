"""
Field-modifier matrix.

Cross-product coverage of every Sigma field modifier the backend supports,
across bound (`field|mod: value`) and unbound (keyword) shapes where
applicable, with and without negation. The aim is to make it obvious when a
backend change shifts a modifier from the native form to the regex template
(or vice versa) by name.
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


# ----------------------------- string-shape modifiers -------------------------


@pytest.mark.parametrize(
    "modifier, value, expected",
    [
        ("", "value", 'fieldA:="value"'),
        ("|contains", "needle", 'fieldA:"needle"'),
        ("|startswith", "prefix", 'fieldA:="prefix"*'),
        ("|endswith", "suffix", 'fieldA:~"suffix$"'),
        ("|re", "foo.*", 'fieldA:~"foo.*"'),
        ("|cased", "Exact", 'fieldA:="Exact"'),
    ],
)
def test_string_modifier_bound(backend, modifier, value, expected):
    q = _convert(
        backend,
        _rule(f"    sel:\n        fieldA{modifier}: {value}\n    condition: sel"),
    )
    assert q == expected


@pytest.mark.parametrize(
    "modifier, value, expected",
    [
        ("", "value", 'NOT fieldA:="value"'),
        ("|contains", "needle", 'NOT fieldA:"needle"'),
        ("|startswith", "prefix", 'NOT fieldA:="prefix"*'),
        ("|endswith", "suffix", 'NOT fieldA:~"suffix$"'),
        ("|re", "foo.*", 'NOT fieldA:~"foo.*"'),
        ("|cased", "Exact", 'NOT fieldA:="Exact"'),
    ],
)
def test_string_modifier_bound_negated(backend, modifier, value, expected):
    q = _convert(
        backend,
        _rule(f"    sel:\n        fieldA{modifier}: {value}\n    condition: not sel"),
    )
    assert q == expected


# ----------------------------- numeric / range --------------------------------


@pytest.mark.parametrize(
    "modifier, value, expected_op",
    [
        ("|gt", 100, ">"),
        ("|gte", 100, ">="),
        ("|lt", 100, "<"),
        ("|lte", 100, "<="),
    ],
)
def test_numeric_compare(backend, modifier, value, expected_op):
    q = _convert(
        backend,
        _rule(f"    sel:\n        bytes{modifier}: {value}\n    condition: sel"),
    )
    assert q == f"bytes:{expected_op}{value}"


# ----------------------------- existence --------------------------------------


@pytest.mark.parametrize(
    "value, expected",
    [
        (True, "fieldA:*"),
        (False, "NOT fieldA:*"),
    ],
)
def test_exists_modifier(backend, value, expected):
    q = _convert(
        backend,
        _rule(f"    sel:\n        fieldA|exists: {str(value).lower()}\n    condition: sel"),
    )
    assert q == expected


def test_null_value(backend):
    q = _convert(backend, _rule("    sel:\n        fieldA: null\n    condition: sel"))
    assert q == 'fieldA:""'


# ----------------------------- fieldref ---------------------------------------


def test_fieldref_modifier(backend):
    q = _convert(backend, _rule("    sel:\n        fieldA|fieldref: fieldB\n    condition: sel"))
    assert q == "fieldA:eq_field(fieldB)"


# ----------------------------- CIDR -------------------------------------------


@pytest.mark.parametrize(
    "cidr, expected",
    [
        ("10.0.0.0/8", 'src_ip:ipv4_range("10.0.0.0/8")'),
        ("192.168.0.0/16", 'src_ip:ipv4_range("192.168.0.0/16")'),
        ("::1/128", 'src_ip:ipv6_range("::1/128")'),
        ("fe80::/10", 'src_ip:ipv6_range("fe80::/10")'),
        ("2001:db8::/32", 'src_ip:ipv6_range("2001:db8::/32")'),
    ],
)
def test_cidr_modifier(backend, cidr, expected):
    q = _convert(
        backend,
        _rule(f"    sel:\n        src_ip|cidr: {cidr}\n    condition: sel"),
    )
    assert q == expected


# ----------------------------- regex flags ------------------------------------


@pytest.mark.parametrize(
    "modifier, expected_prefix",
    [
        ("|re|i", "(?i)"),
        ("|re|m", "(?m)"),
        ("|re|s", "(?s)"),
    ],
)
def test_regex_flag_prefix(backend, modifier, expected_prefix):
    q = _convert(
        backend,
        _rule(f"    sel:\n        fieldA{modifier}: 'foo'\n    condition: sel"),
    )
    assert q == f'fieldA:~"{expected_prefix}foo"'


# ----------------------------- unbound (keyword) ------------------------------


def test_unbound_string_keyword(backend):
    q = _convert(backend, _rule("    keywords:\n        - badword\n    condition: keywords"))
    assert q == '"badword"'


def test_unbound_regex_keyword(backend):
    q = _convert(
        backend,
        _rule("    sel:\n        '|re': foo.*bar\n    condition: sel"),
    )
    assert q == '_msg:~"foo.*bar"'


def test_unbound_string_keyword_negated(backend):
    q = _convert(backend, _rule("    keywords:\n        - badword\n    condition: not keywords"))
    assert q == 'NOT "badword"'


# ----------------------------- IN-list / OR collapse --------------------------


def test_in_list_string(backend):
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


def test_in_list_with_wildcard_falls_back_to_or(backend):
    """`in_expressions_allow_wildcards = False` makes pySigma OR-expand the
    list whenever any element contains a wildcard. A trailing `*` routes
    through the native startswith template (`field:="prefix"*`); other
    wildcard placements would route through regex."""
    q = _convert(
        backend,
        _rule("    sel:\n        fieldA:\n            - v1\n            - v2*\n    condition: sel"),
    )
    assert q == 'fieldA:="v1" OR fieldA:="v2"*'


def test_in_list_with_midvalue_wildcard_routes_to_regex(backend):
    """A mid-value wildcard cannot use the native prefix shortcut and must
    fall through to regex."""
    q = _convert(
        backend,
        _rule("    sel:\n        fieldA:\n            - v1\n            - v*2\n    condition: sel"),
    )
    assert q == 'fieldA:="v1" OR fieldA:~"v.*2"'
