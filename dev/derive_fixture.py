"""Derive the committed temporal e2e fixture from a VictoriaLogs instance.

Read-only: one /select/logsql/query call, no writes to the source.

Projects to three fields; host labels are assigned by activity rank and
timestamps become offsets from the slice start. The endpoint and window come
from the environment:

    VICTORIALOGS_URL=http://localhost:9428 \\
    FIXTURE_WINDOW=2026-01-01T00:00:00Z,2026-01-01T00:10:00Z \\
    python dev/derive_fixture.py

Regenerating over a different window yields different rows; the committed
file is what CI uses.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path

TIMESPAN_MS = 300_000
OUT = (
    Path(__file__).resolve().parents[1]
    / "tests"
    / "e2e"
    / "fixtures"
    / "journald_temporal_cases.ndjson"
)


def _window() -> tuple[str, str]:
    raw = os.environ.get("FIXTURE_WINDOW", "")
    start, _, end = raw.partition(",")
    if not start or not end:
        raise SystemExit('set FIXTURE_WINDOW="<start>,<end>" as RFC3339 timestamps')
    return start.strip(), end.strip()


def _host_map(rows: list[dict]) -> dict[str, str]:
    """Assign host-a, host-b, … by descending activity, ties broken by name."""
    counts = Counter(row["_HOSTNAME"] for row in rows)
    ordered = sorted(counts, key=lambda host: (-counts[host], host))
    if len(ordered) > 26:
        raise SystemExit(f"more than 26 hosts ({len(ordered)}); extend the naming scheme")
    return {host: f"host-{chr(ord('a') + index)}" for index, host in enumerate(ordered)}


def _case_rows(rows: list[dict]) -> list[dict]:
    """Select only the rows `tests/e2e/test_temporal_e2e.py::_cases` picks.

    Five events cover the four cases: the first row per host/identifier, a
    partner inside the timespan, the opposite arrival order, and a partner
    further apart than the timespan. Stay in sync with the test.
    """
    sudo = [r for r in rows if r["_HOSTNAME"] == "host-a" and r["SYSLOG_IDENTIFIER"] == "sudo"]
    systemd = [
        r for r in rows if r["_HOSTNAME"] == "host-a" and r["SYSLOG_IDENTIFIER"] == "systemd"
    ]
    b_only = [r for r in rows if r["_HOSTNAME"] == "host-b" and r["SYSLOG_IDENTIFIER"] == "systemd"]
    if not sudo or not systemd or not b_only:
        raise SystemExit("window must contain sudo+systemd on the busy host and systemd on another")

    first_sudo, first_systemd = sudo[0], systemd[0]
    in_window = next(
        r for r in systemd if 0 <= r["offset_ms"] - first_sudo["offset_ms"] <= TIMESPAN_MS
    )
    reversed_sudo = next(
        r for r in sudo if 0 <= r["offset_ms"] - first_systemd["offset_ms"] <= TIMESPAN_MS
    )
    out_of_window = next(
        r for r in systemd if r["offset_ms"] - first_sudo["offset_ms"] > TIMESPAN_MS
    )

    selected = {
        (r["offset_ms"], r["_HOSTNAME"], r["SYSLOG_IDENTIFIER"])
        for r in (first_sudo, first_systemd, in_window, reversed_sudo, out_of_window, b_only[0])
    }
    return [r for r in rows if (r["offset_ms"], r["_HOSTNAME"], r["SYSLOG_IDENTIFIER"]) in selected]


def main() -> None:
    url = os.environ["VICTORIALOGS_URL"].rstrip("/")
    start_at, end_at = _window()
    query = (
        f"_time:[{start_at},{end_at}] "
        '(SYSLOG_IDENTIFIER:="sudo" OR SYSLOG_IDENTIFIER:="systemd") '
        "| fields _time, _HOSTNAME, SYSLOG_IDENTIFIER | limit 5000"
    )
    endpoint = f"{url}/select/logsql/query?{urllib.parse.urlencode({'query': query})}"
    with urllib.request.urlopen(endpoint, timeout=60) as response:
        rows = [json.loads(line) for line in response.read().splitlines() if line.strip()]

    rows.sort(key=lambda row: row["_time"])
    start = dt.datetime.fromisoformat(rows[0]["_time"].replace("Z", "+00:00"))
    hosts = _host_map(rows)
    projected = []
    for row in rows:
        if set(row) != {"_time", "_HOSTNAME", "SYSLOG_IDENTIFIER"}:
            raise SystemExit(f"unexpected fields in export: {sorted(row)}")
        stamp = dt.datetime.fromisoformat(row["_time"].replace("Z", "+00:00"))
        projected.append(
            {
                "offset_ms": round((stamp - start).total_seconds() * 1000),
                "_HOSTNAME": hosts[row["_HOSTNAME"]],
                "SYSLOG_IDENTIFIER": row["SYSLOG_IDENTIFIER"],
            }
        )

    kept = _case_rows(projected)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("".join(json.dumps(row, separators=(",", ":")) + "\n" for row in kept))
    print(f"kept {len(kept)} of {len(projected)} rows in {OUT}")


if __name__ == "__main__":
    main()
