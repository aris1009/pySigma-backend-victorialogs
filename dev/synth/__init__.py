"""Synthetic event generators for the e2e harness.

The Windows EventLog harness uses public OTRF Security-Datasets dumps
because authentic offensive-tool telemetry is hard to fabricate. The four
non-Windows pipelines (caddy, journald, podman, suricata) cannot use real
homelab logs — see CONTRIBUTING.md gate "No homelab IPs, internal
hostnames, or personal artefacts". Public corpora exist for some sources
(Suricata sample EVE, Caddy fixtures) but not in shapes that satisfy our
expectations contract end-to-end.

This package provides deterministic, privacy-by-construction generators
that emit NDJSON in the *pipeline-target* shape (i.e. the field names
each pipeline maps onto, not the source's pre-pipeline shape). The output
is fed directly to VictoriaLogs via ``/insert/jsonline`` — the per-rule
Sigma queries from each pipeline can then be asserted against it.

Determinism guarantees
----------------------

Same ``(generator, seed, count)`` triple yields byte-identical NDJSON on
every machine, every Python version. Achieved by:

* All randomness routed through a single ``random.Random(seed)`` per run,
  with no implicit clocks or ``random`` module-level state.
* Stable JSON serialisation (``sort_keys=True``, no trailing whitespace,
  ``\n`` line terminator, UTF-8 encoding).
* Event ``_time`` stamps derive from a fixed baseline + per-event offset,
  not the wall clock.

The fetcher (``dev/fetch_datasets.py``) cache-keys synthetic entries on
the sha256 of the materialised NDJSON, so any non-determinism would trip
the tamper check on the next CI run.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

from .caddy import generate as _caddy
from .caddy import generate_benign as _caddy_benign
from .journald import generate as _journald
from .journald import generate_benign as _journald_benign
from .podman import generate as _podman
from .podman import generate_benign as _podman_benign
from .suricata import generate as _suricata
from .suricata import generate_benign as _suricata_benign

Generator = Callable[[int, int], Iterator[dict[str, Any]]]

GENERATORS: dict[str, Generator] = {
    "caddy": _caddy,
    "caddy_benign": _caddy_benign,
    "journald": _journald,
    "journald_benign": _journald_benign,
    "podman": _podman,
    "podman_benign": _podman_benign,
    "suricata": _suricata,
    "suricata_benign": _suricata_benign,
}

__all__ = ["GENERATORS", "Generator"]
