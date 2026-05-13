"""
Property-based tests for value-escape correctness.

Backend bugs concentrate around quoting and escaping edge cases — values that
contain `"`, `\\`, control characters, or unicode. The exact-string unit tests
in test_backend_victorialogs.py catch known cases; these tests fuzz the surface
to surface unknown cases.

Two invariants we assert:

1. Conversion never raises (any Python-string value should produce *some*
   LogsQL output, even if the resulting query matches nothing).
2. The output's surrounding quotation marks balance — exactly one opening `"`
   matched by one closing `"` per quoted segment.
"""

from __future__ import annotations

import string

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st
from sigma.collection import SigmaCollection

from sigma.backends.victorialogs import VictoriaLogsBackend

backend = VictoriaLogsBackend()

# Limit characters to printable ASCII for deterministic Sigma YAML embedding.
# Newlines and YAML's structural chars (`:`, `#`, `'`, `"`, `\`) are kept in
# the alphabet so we exercise the escape paths.
_FUZZ_CHARS = string.printable.replace("\n", "").replace("\r", "").replace("\t", "")


def _convert_value(raw: str) -> str:
    yaml = (
        "title: T\n"
        "status: test\n"
        "logsource:\n"
        "    category: test\n"
        "detection:\n"
        "    sel:\n"
        f"        fieldA: {raw!r}\n"
        "    condition: sel\n"
    )
    out = backend.convert(SigmaCollection.from_yaml(yaml))
    assert isinstance(out, list) and out
    return out[0]


@given(value=st.text(alphabet=_FUZZ_CHARS, min_size=1, max_size=32))
@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
def test_arbitrary_value_converts_without_raising(value: str):
    assume("'" not in value)  # YAML single-quote string can't embed `'`
    _convert_value(value)


def _logsql_quotes_balance(query: str) -> bool:
    """Walk a LogsQL query and verify every `"` opens or closes a string,
    respecting `\\"` as an escaped quote and `\\\\` as an escaped backslash."""
    in_str = False
    i = 0
    while i < len(query):
        ch = query[i]
        if in_str:
            if ch == "\\" and i + 1 < len(query):
                # Skip the escaped char (could be `"` or `\\`).
                i += 2
                continue
            if ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
        i += 1
    return not in_str


@given(value=st.text(alphabet=_FUZZ_CHARS, min_size=1, max_size=32))
@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
def test_quotes_balance_in_output(value: str):
    """Every opening `"` should have a matching closing `"` (with escapes
    respected). Unbalanced quotes would always be a parse error."""
    assume("'" not in value)
    out = _convert_value(value)
    assert _logsql_quotes_balance(out), f"unbalanced quotes in {out!r}"


@pytest.mark.parametrize(
    "raw, expected_substring",
    [
        ('a"b', 'a\\"b'),  # literal double-quote inside value
        ("a\\b", "a\\\\b"),  # backslash doubled for LogsQL string
        ("a*b", 'fieldA:~"a.*b"'),  # mid-value wildcard routed to regex
        ("é", "é"),  # unicode passthrough (é)
    ],
)
def test_known_escape_cases(raw: str, expected_substring: str):
    out = _convert_value(raw)
    assert expected_substring in out, f"expected {expected_substring!r} in {out!r}"


# ----------------------------- field-name fuzz --------------------------------
#
# pySigma allows YAML-keyable strings as field names. Inside a LogsQL
# double-quoted field name, only `"` and `\` need escaping; everything else
# (whitespace, `:`, `|`, unicode, control chars) survives verbatim.
#
# These properties fuzz arbitrary printable strings as field names and assert:
#
# 1. Conversion never raises.
# 2. The output's quotes still balance — the field-name escape path must not
#    leak an unbalanced `"` into the surrounding query.
# 3. When the field name contains a character outside the bare-identifier set
#    (`[A-Za-z_][A-Za-z0-9_.]*`), the output contains a quoted form.

# A narrower alphabet for field-name keys: ASCII printable minus the chars
# that pySigma uses as structural separators (`|` is the modifier separator,
# `:` is the YAML key terminator) or that YAML rejects as plain-scalar starts.
_FIELD_NAME_CHARS = string.ascii_letters + string.digits + " _-./@$%&()[]{}"


def _convert_with_field_name(field: str, value: str = "v") -> str:
    yaml = (
        "title: T\n"
        "status: test\n"
        "logsource:\n"
        "    category: test\n"
        "detection:\n"
        "    sel:\n"
        f"        {field!r}: {value!r}\n"
        "    condition: sel\n"
    )
    out = backend.convert(SigmaCollection.from_yaml(yaml))
    assert isinstance(out, list) and out
    return out[0]


_BARE_IDENT_CHARS = set(string.ascii_letters + string.digits + "_.")


def _is_bare_identifier(name: str) -> bool:
    if not name:
        return False
    if name[0].isdigit():
        return False
    return all(ch in _BARE_IDENT_CHARS for ch in name)


@given(field=st.text(alphabet=_FIELD_NAME_CHARS, min_size=1, max_size=24))
@settings(max_examples=150, suppress_health_check=[HealthCheck.too_slow])
def test_arbitrary_field_name_converts_without_raising(field: str):
    assume("'" not in field)
    _convert_with_field_name(field)


@given(field=st.text(alphabet=_FIELD_NAME_CHARS, min_size=1, max_size=24))
@settings(max_examples=150, suppress_health_check=[HealthCheck.too_slow])
def test_field_name_quotes_balance(field: str):
    assume("'" not in field)
    out = _convert_with_field_name(field)
    assert _logsql_quotes_balance(out), f"unbalanced quotes in {out!r}"


@given(
    field=st.text(alphabet=" /@%-", min_size=1, max_size=8),
)
@settings(max_examples=80, suppress_health_check=[HealthCheck.too_slow])
def test_irregular_field_name_is_quoted(field: str):
    """Field names containing characters outside the bare-identifier set must
    end up wrapped in `"..."`."""
    assume("'" not in field)
    assume(not _is_bare_identifier(field))
    out = _convert_with_field_name(field)
    assert '"' in out, f"expected quoted form in {out!r}"


@pytest.mark.parametrize(
    "field, expected_form",
    [
        ("plain_field", 'plain_field:="v"'),
        ("dotted.field", 'dotted.field:="v"'),
        ("with space", '"with space":="v"'),
        ('has"quote', '"has\\"quote":="v"'),
        ("dash-in-name", '"dash-in-name":="v"'),
    ],
)
def test_known_field_name_cases(field: str, expected_form: str):
    out = _convert_with_field_name(field)
    assert out == expected_form
