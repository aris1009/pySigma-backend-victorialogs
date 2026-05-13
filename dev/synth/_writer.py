"""Deterministic NDJSON writer used by the synth fetcher dispatch.

Stable serialisation: ``sort_keys=True``, no ASCII escaping (so unicode
strings encode the same on every machine), comma+colon separators with
no extra whitespace, ``\n`` line terminator. Output bytes are
byte-identical across Python versions for the same input dicts.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from io import BytesIO
from pathlib import Path
from typing import Any


def serialize(events: Iterable[dict[str, Any]]) -> bytes:
    """Serialise events to NDJSON bytes deterministically."""
    buf = BytesIO()
    for ev in events:
        line = json.dumps(
            ev,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        buf.write(line.encode("utf-8"))
        buf.write(b"\n")
    return buf.getvalue()


def write_ndjson(path: Path, events: Iterable[dict[str, Any]]) -> tuple[int, str]:
    """Write events as NDJSON; returns (line_count, sha256-hex)."""
    payload = serialize(events)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    line_count = payload.count(b"\n")
    return line_count, hashlib.sha256(payload).hexdigest()
