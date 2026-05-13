"""Wrap a LogsQL query with a `_time:5m AND` head and a `| limit 1` tail so
the live VictoriaLogs server bounds its scan and returns quickly.

Naive ` | ` splitting (parameter expansion in shell, `partition` in Python)
breaks for queries that legitimately contain ` | ` inside a quoted string —
e.g. `"wget * - http* | sh"`. The split helper here is quote-aware: it
respects double-quoted strings (with `\\"` and `\\\\` escape sequences) and
only treats a top-level ` | ` as a pipe.

Single source of truth used by both `tests/test_live_victorialogs.py` and
`dev/validate_queries.py`.
"""

from __future__ import annotations


def _split_top_level_pipe(q: str) -> tuple[str, str]:
    """Split `q` at the first ` | ` that is NOT inside a `"..."` string.

    Returns `(head, tail)` where `tail` includes the leading ` | ` so the
    caller can paste it back. Returns `(q, "")` if there is no top-level
    pipe.
    """
    in_str = False
    i = 0
    n = len(q)
    while i < n:
        ch = q[i]
        if in_str:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
            elif ch == " " and q[i : i + 3] == " | ":
                return q[:i], q[i:]
        i += 1
    return q, ""


def wrap_query(q: str, timespan: str = "5m", limit: int = 1) -> str:
    """Bound the query in time + result count so it can be safely sent to a
    live VictoriaLogs instance during validation.

    - If the query already starts with `_time:` (correlations), the time
      filter is left alone and only the limit is appended.
    - Otherwise a `_time:{timespan} AND (head)` is injected before the first
      top-level pipe; if there is no pipe, the entire query is wrapped.
    """
    if q.startswith("_time:"):
        return f"{q} | limit {limit}"
    head, tail = _split_top_level_pipe(q)
    if tail:
        return f"_time:{timespan} AND ({head}){tail} | limit {limit}"
    return f"_time:{timespan} AND ({q}) | limit {limit}"
