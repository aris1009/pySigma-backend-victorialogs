"""
RE2 regex-engine regression test.

The backend's threat model (SECURITY.md ➜ "ReDoS via |re:") asserts that
LogsQL's regex layer is RE2-backed and therefore immune to catastrophic
backtracking. RE2 is the regex package shipped with Go's standard library
(`regexp`), which VictoriaLogs uses for `:~"..."` filters and the
`|filter ... :~ ...` pipe stage.

If a future VL release silently swaps to a PCRE-style engine, Sigma rules
authored with `|re:` could become a DoS vector against the log store.
This test pins the assumption against live VL by checking two RE2
fingerprints:

1. **Linear-time on a PCRE-pathological pattern.** `(a+)+b` against a
   long all-`a` input would take exponential time on an NFA-with-backtrack
   engine. RE2 runs it in milliseconds. We assert the query returns
   quickly.

2. **Backreferences are rejected at parse time.** RE2 deliberately omits
   backreferences (the construct that makes ReDoS possible). A pattern
   with `\1` must come back as HTTP 400.

Skipped unless `VICTORIALOGS_URL` is set, like the other live integration
tests.
"""

from __future__ import annotations

import os
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest

VL_URL = os.environ.get("VICTORIALOGS_URL")
pytestmark = pytest.mark.skipif(
    not VL_URL, reason="set VICTORIALOGS_URL=http://host:9428 to enable"
)

# A pattern that runs in milliseconds under RE2 and would take minutes
# under a backtracking PCRE engine on any non-trivial all-`a` input.
PATHOLOGICAL_PATTERN = "(a+)+b"

# RE2 forbids backreferences. PCRE accepts them. This is the simplest
# fingerprint to tell the two engines apart at parse time.
BACKREF_PATTERN = r"(.+)\1"

# Wall-clock budget for the pathological-pattern query. RE2 finishes in
# well under a second even on cold caches; we give 5s of slack to absorb
# network jitter and VL search-path overhead. A backtracking engine would
# blow through this by orders of magnitude.
LINEAR_TIME_BUDGET_SEC = 5.0


def _query(logsql: str, timeout: float = 10.0) -> tuple[int, str, float]:
    """POST a LogsQL query and return (status_code, body, elapsed_seconds).

    HTTPError is captured rather than raised so the test can distinguish
    "fast 400" (RE2 rejected the pattern — desired) from "slow 200"
    (engine accepted but ran slowly — undesired).
    """
    assert VL_URL  # narrows for type checker
    url = f"{VL_URL}/select/logsql/query?" + urllib.parse.urlencode({"query": logsql, "limit": "1"})
    req = urllib.request.Request(url, method="GET")
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode(errors="replace")
            return resp.status, body, time.monotonic() - start
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        return exc.code, body, time.monotonic() - start


def test_re2_runs_pathological_pattern_in_linear_time():
    """RE2 must not catastrophically backtrack on `(a+)+b`."""
    # `_msg` is always present in VL; an empty store still parses and
    # executes the regex check against zero rows in ~constant time.
    logsql = f'_msg:~"{PATHOLOGICAL_PATTERN}"'
    status, body, elapsed = _query(logsql)
    assert status == 200, f"expected 200, got {status}: {body[:200]}"
    assert elapsed < LINEAR_TIME_BUDGET_SEC, (
        f"VL took {elapsed:.2f}s on a PCRE-pathological pattern — "
        f"this is the RE2 fingerprint test. If VL "
        f"swapped its regex engine, the threat-model claim in SECURITY.md "
        f"is invalid and the |re: code path is now a ReDoS vector."
    )


def test_re2_rejects_backreference_at_parse_time():
    """RE2 deliberately omits backreferences. A `\\1` pattern must 400."""
    logsql = f'_msg:~"{BACKREF_PATTERN}"'
    status, body, _ = _query(logsql)
    assert status == 400, (
        f"VL accepted a backreference pattern (status {status}) — "
        f"the regex engine is no longer RE2. {body[:200]}"
    )
