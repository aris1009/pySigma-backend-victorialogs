"""Fixtures for the Windows EventLog e2e harness.

Skips the whole module when:
  - the e2e marker hasn't been opted into (default — see pyproject's addopts), OR
  - e2e/datasets/ does not exist (no `make e2e-fetch`), OR
  - the VL_E2E_URL endpoint is not reachable.

This keeps `pytest` (unit-only) clean even with these files on disk.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.e2e._expectations import (
    DEFAULT_DATASETS_DIR,
    Expectation,
    load_expectations,
)
from tests.e2e._runtime import wait_until_healthy

DEFAULT_VL_URL = "http://localhost:9428"


@pytest.fixture(scope="session")
def vl_url() -> str:
    """Resolve and health-check the VictoriaLogs endpoint for the harness."""
    url = os.environ.get("VL_E2E_URL", DEFAULT_VL_URL)
    timeout = float(os.environ.get("VL_E2E_TIMEOUT", "60"))
    try:
        wait_until_healthy(url, timeout=timeout)
    except TimeoutError as e:
        pytest.skip(f"VictoriaLogs not reachable at {url} — bring up via `make e2e-up`. {e}")
    return url


@pytest.fixture(scope="session")
def datasets_dir() -> Path:
    """The directory `make e2e-fetch` populates with OTRF/EVTX-Samples JSON."""
    p = Path(os.environ.get("E2E_DATASETS_DIR", str(DEFAULT_DATASETS_DIR)))
    if not p.is_dir() or not (any(p.rglob("*.json")) or any(p.rglob("*.ndjson"))):
        pytest.skip(f"No datasets at {p} — run `make e2e-fetch` first.")
    return p


@pytest.fixture(scope="session")
def expectations() -> list[Expectation]:
    return load_expectations()


@pytest.fixture(scope="session")
def ingested_set() -> set[str]:
    """Per-session set of dataset basenames already POSTed — keeps re-runs cheap."""
    return set()
