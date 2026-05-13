"""Unit tests for the shared live-VL wrap helper.

The original implementations (in `dev/validate_queries.sh` and inline in
`tests/test_live_victorialogs.py`) split on the first ` | ` regardless of
context. Any query with a quoted ` | ` (e.g. a Sigma keyword like
`"wget * - http* | sh"`) was mis-split into a fake search head and a fake
pipe stage, and the wrapped form was rejected by VictoriaLogs with a
misleading "missing ')'" parser error. The corpus validator hit this on
day one.
"""

from __future__ import annotations

from sigma._dev.wrap import _split_top_level_pipe, wrap_query


def test_split_top_level_pipe_no_pipe():
    assert _split_top_level_pipe("foo:=bar") == ("foo:=bar", "")


def test_split_top_level_pipe_simple():
    assert _split_top_level_pipe("foo:=bar | stats count()") == (
        "foo:=bar",
        " | stats count()",
    )


def test_split_top_level_pipe_inside_quotes_is_ignored():
    """The `|` inside the quoted keyword must not be treated as a pipe."""
    q = '"wget * - http* | sh" OR "other"'
    assert _split_top_level_pipe(q) == (q, "")


def test_split_top_level_pipe_quoted_then_real_pipe():
    """Quoted `|` first, real top-level pipe second — split must land on the
    real one, not the quoted one."""
    q = '"a | b" | stats count()'
    assert _split_top_level_pipe(q) == ('"a | b"', " | stats count()")


def test_split_top_level_pipe_escaped_quote_inside_string():
    """An escaped quote inside the string must not end string mode early."""
    q = '"a\\"b | c" | stats count()'
    assert _split_top_level_pipe(q) == ('"a\\"b | c"', " | stats count()")


def test_split_top_level_pipe_escaped_backslash():
    """`\\\\` inside a string is a literal backslash and the following `"`
    DOES close the string. The trailing top-level `|` is the split point."""
    q = '"a\\\\" | stats count()'
    assert _split_top_level_pipe(q) == ('"a\\\\"', " | stats count()")


def test_wrap_pure_search():
    assert wrap_query('foo:="bar"') == '_time:5m AND (foo:="bar") | limit 1'


def test_wrap_with_pipe_outside_quotes():
    assert wrap_query("foo:=x | stats by (b) count()") == (
        "_time:5m AND (foo:=x) | stats by (b) count() | limit 1"
    )


def test_wrap_preserves_quoted_pipe():
    """Regression: the literal `|` inside the keyword
    must end up *inside* the parenthesized search head, not as a fake pipe
    stage."""
    q = '"wget * - http* | sh" OR "other"'
    assert wrap_query(q) == ('_time:5m AND ("wget * - http* | sh" OR "other") | limit 1')


def test_wrap_correlation_query_skips_time_injection():
    """Backend already prepends `_time:{timespan}` for correlations; the
    wrapper must not inject another."""
    q = '_time:5m fieldA:="x" | stats by (b) count() as event_count'
    assert wrap_query(q) == ('_time:5m fieldA:="x" | stats by (b) count() as event_count | limit 1')


def test_wrap_custom_timespan_and_limit():
    assert wrap_query('foo:="bar"', timespan="1h", limit=10) == (
        '_time:1h AND (foo:="bar") | limit 10'
    )
