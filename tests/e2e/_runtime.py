"""Tiny VictoriaLogs HTTP client used by the e2e harness.

Stdlib-only on purpose: the e2e harness should not pull in extra runtime
dependencies (httpx, requests) just to wait, ingest, and query.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


def wait_until_healthy(url: str, *, timeout: float = 60.0, interval: float = 1.0) -> None:
    """Poll <url>/health until it returns 2xx or timeout. Raises on timeout.

    Fail-fast path: if the first three attempts hit ECONNREFUSED, give up — no
    listener means nothing is starting up, and burning the full 60s loop just
    delays the user's "VL not running" feedback.
    """
    deadline = time.monotonic() + timeout
    last_err: Exception | None = None
    refused_in_a_row = 0
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{url}/health", timeout=interval * 2) as resp:
                if 200 <= resp.status < 300:
                    return
        except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
            last_err = e
            reason = getattr(e, "reason", None)
            if isinstance(reason, ConnectionRefusedError) or isinstance(e, ConnectionRefusedError):
                refused_in_a_row += 1
                if refused_in_a_row >= 3:
                    raise TimeoutError(
                        f"VictoriaLogs at {url}: connection refused — nothing listening. "
                        "Bring the stack up via `make e2e-up`."
                    ) from e
            else:
                refused_in_a_row = 0
        time.sleep(interval)
    raise TimeoutError(
        f"VictoriaLogs at {url} did not become healthy within {timeout}s: {last_err}"
    )


def ingest_jsonline(url: str, path: Path, *, stream_field: str = "winlog.channel") -> int:
    """POST a NDJSON file to /insert/jsonline. Returns line count for sanity."""
    body = path.read_bytes()
    n = body.count(b"\n") + (0 if body.endswith(b"\n") else 1)
    qs = urllib.parse.urlencode({"_stream_fields": stream_field})
    req = urllib.request.Request(
        f"{url}/insert/jsonline?{qs}",
        data=body,
        method="POST",
        headers={"Content-Type": "application/stream+json"},
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        if resp.status >= 300:
            raise RuntimeError(f"ingest failed: HTTP {resp.status}: {resp.read()!r}")
    return n


def ingest_jsonline_stamp_now(
    url: str,
    path: Path,
    *,
    stream_field: str,
    msg_field: str | None = None,
    dataset_label: str | None = None,
) -> int:
    """Like ``ingest_jsonline`` but rewrites events for VL queryability.

    * ``_time`` is set to the current UTC timestamp on every event.
      Synthetic datasets are pinned by sha256, so their on-disk ``_time``
      derives from a fixed BASELINE months in the past — and VL's query
      API defaults to a 5-minute window and short retention drops stale
      data. Rewriting at ingest leaves the on-disk bytes deterministic.
    * ``msg_field`` (optional) copies an existing field's value into
      ``_msg``. Required when the rules under test contain unbound
      keyword filters (``"phrase"`` without a field selector) — those
      filter the ``_msg`` field by default. The source field is left in
      place so field-anchored queries against it still match (in
      contrast to VL's ``_msg_field`` ingest parameter, which consumes
      the source field).
    * ``dataset_label`` (optional) stamps a ``dataset_label`` field on
      every event so multiple datasets in the same VL can be query-scoped
      apart by wrapping ``dataset_label:="<label>" AND (...)``.
    """
    from datetime import UTC, datetime

    now = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    out_lines: list[bytes] = []
    for line in path.read_bytes().splitlines():
        if not line.strip():
            continue
        ev = json.loads(line)
        ev["_time"] = now
        if dataset_label is not None:
            ev["dataset_label"] = dataset_label
        if msg_field is not None:
            value = ev
            for part in msg_field.split("."):
                if not isinstance(value, dict) or part not in value:
                    value = None
                    break
                value = value[part]
            if isinstance(value, str):
                ev["_msg"] = value
        out_lines.append(json.dumps(ev, separators=(",", ":")).encode("utf-8"))
    body = b"\n".join(out_lines) + b"\n"
    qs = urllib.parse.urlencode({"_stream_fields": stream_field})
    req = urllib.request.Request(
        f"{url}/insert/jsonline?{qs}",
        data=body,
        method="POST",
        headers={"Content-Type": "application/stream+json"},
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        if resp.status >= 300:
            raise RuntimeError(f"ingest failed: HTTP {resp.status}: {resp.read()!r}")
    return len(out_lines)


def wait_until_count(url: str, query: str, *, expected: int, timeout: float = 30.0) -> int:
    """Poll the count of matches for `query` until it reaches `expected` or timeout.

    VL ingest is asynchronous — there is a brief window after POSTing where rows
    are not yet queryable. This polls until they are, then returns the final
    count. Returns 0 (without raising) if the count never reaches `expected`.
    """
    deadline = time.monotonic() + timeout
    last = 0
    while time.monotonic() < deadline:
        last = logsql_count(url, query)
        if last >= expected:
            return last
        time.sleep(0.5)
    return last


def logsql_query(url: str, query: str, *, limit: int = 10000) -> list[dict[str, Any]]:
    """Run a LogsQL query and return up to `limit` rows."""
    qs = urllib.parse.urlencode({"query": query, "limit": str(limit)})
    req = urllib.request.Request(f"{url}/select/logsql/query?{qs}", method="GET")
    with urllib.request.urlopen(req, timeout=60) as resp:
        body = resp.read()
    rows: list[dict[str, Any]] = []
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    return rows


def logsql_count(url: str, query: str) -> int:
    """Cheap row count via `<query> | stats count() as n` — avoids hauling rows."""
    counted = f"{query} | stats count() as n"
    qs = urllib.parse.urlencode({"query": counted})
    req = urllib.request.Request(f"{url}/select/logsql/query?{qs}", method="GET")
    with urllib.request.urlopen(req, timeout=60) as resp:
        body = resp.read().strip()
    if not body:
        return 0
    # Response is a single JSON line per result row.
    last = body.splitlines()[-1]
    obj = json.loads(last)
    return int(obj.get("n", 0))
