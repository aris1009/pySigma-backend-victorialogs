"""Deterministic event timestamping.

Synthetic events use a fixed baseline so the same ``(generator, seed,
count)`` triple produces the same NDJSON bytes — which lets the fetcher
verify sha256 against the manifest.

Tests that need *fresh* timestamps (e.g. the vmalert e2e harness — vmalert
auto-injects ``_time:[-5m]`` from the group interval) must rewrite the
``_time`` field at ingest time, never at generation time.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

# Frozen baseline. Picked far enough in the past that the vmalert e2e
# harness (which expects fresh ``_time``) cannot accidentally match
# unrewritten synthetic data, and far enough in the future that anyone
# searching VL for "real" data won't see it as production traffic.
BASELINE = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)


def stamp(offset_seconds: int) -> str:
    """Return an ISO 8601 ``_time`` string at BASELINE + offset_seconds."""
    return (BASELINE + timedelta(seconds=offset_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
