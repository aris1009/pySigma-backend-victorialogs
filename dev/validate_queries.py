#!/usr/bin/env python3
"""Run every query emitted by `dev/show_queries.py` against a live
VictoriaLogs instance to confirm it parses. Read-only — no writes.

Set ``VICTORIALOGS_URL=http://host:9428`` to point at a target instance.

Replaces the earlier `validate_queries.sh`. The bash version split queries
at the first ` | ` via parameter expansion, which broke for any query with a
literal ` | ` inside a quoted string. Both this script and the live pytest
harness now share the quote-aware wrapper in `sigma._dev.wrap`.
"""

from __future__ import annotations

import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# Allow running from the repo root without installing the dev script.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sigma._dev.wrap import wrap_query  # noqa: E402

_VL_RAW = os.environ.get("VICTORIALOGS_URL")
if not _VL_RAW:
    print(
        "ERROR: set VICTORIALOGS_URL=http://host:9428 to point at a live VictoriaLogs instance",
        file=sys.stderr,
    )
    sys.exit(2)
VL = _VL_RAW.rstrip("/")


def _check(query: str) -> tuple[int, str]:
    url = f"{VL}/select/logsql/query?" + urllib.parse.urlencode({"query": query, "limit": "1"})
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            resp.read(512)
            return resp.status, ""
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")[:200]
        return exc.code, body


def _iter_show_queries() -> list[tuple[str, str]]:
    import subprocess

    out = subprocess.check_output(
        ["poetry", "run", "python", "dev/show_queries.py"], cwd=ROOT, text=True
    )
    cases: list[tuple[str, str]] = []
    name = ""
    for line in out.splitlines():
        if line.startswith("## "):
            name = line[3:].strip()
        elif line.startswith("  ") and name:
            cases.append((name, line[2:]))
    return cases


def main() -> int:
    cases = _iter_show_queries()
    fail = 0
    for name, q in cases:
        wrapped = wrap_query(q)
        code, body = _check(wrapped)
        if code == 200:
            print(f"  PASS  {name:<30}  {q}")
        else:
            fail += 1
            print(f"  FAIL  {name:<30}  {q}")
            print(f"        HTTP {code}: {body}")
    print()
    print(f"TOTAL={len(cases)}  PASS={len(cases) - fail}  FAIL={fail}")
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
