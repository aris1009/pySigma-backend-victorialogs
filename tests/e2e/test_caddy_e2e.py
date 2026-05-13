"""End-to-end Caddy v2 access-log correctness harness.

Mirrors test_windows_eventlog_e2e.py but for the caddy pipeline:

  1. Convert each rule via victorialogs_caddy().
  2. POST the synthetic NDJSON dataset to /insert/jsonline (idempotent),
     stamping ``_time`` to now, mapping ``request.uri`` onto VL's
     ``_msg`` (so unbound keyword rules match), and tagging each event
     with a ``dataset_label`` so attack/benign datasets can coexist in
     the same VL without leaking into each other's queries.
  3. Query VL with the converted LogsQL, scoped by ``dataset_label``.
  4. Assert hits >= min_hits (positive) or hits == 0 (negative).

Synthetic data is already in the caddy pipeline-target shape, so no
Vector remap is involved — the test posts NDJSON directly.

Gated behind the `e2e` pytest marker.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sigma.collection import SigmaCollection

from sigma.backends.victorialogs import VictoriaLogsBackend
from sigma.pipelines.victorialogs import victorialogs_caddy
from tests.e2e._expectations import (
    REPO_ROOT,
    Expectation,
    load_expectations,
)
from tests.e2e._runtime import (
    ingest_jsonline_stamp_now,
    logsql_count,
    wait_until_count,
)

pytestmark = pytest.mark.e2e

CADDY_EXPECTATIONS_PATH = REPO_ROOT / "e2e" / "expectations_caddy.yml"
# Caddy events carry `logger: "http.log.access"` — combined with
# `dataset_label` it gives every dataset its own VL stream.
CADDY_STREAM_FIELDS = "logger,dataset_label"
# Rules in the caddy corpus contain unbound keyword filters
# (LogsQL `"phrase"` with no field selector); those filter the `_msg`
# field by default. Mapping `request.uri` onto `_msg` lets keyword
# selectors that target URI substrings match.
CADDY_MSG_FIELD = "request.uri"


def _convert(expectation: Expectation) -> str:
    rule_path = expectation.absolute_rule_path()
    if not rule_path.is_file():
        pytest.fail(
            f"{expectation.id}: rule_path {expectation.rule_path} not found under "
            f"SIGMA_CORPUS_PATH ({rule_path.parent}). Clone SigmaHQ/sigma there."
        )
    backend = VictoriaLogsBackend(processing_pipeline=victorialogs_caddy())
    queries = backend.convert(SigmaCollection.from_yaml(rule_path.read_text(encoding="utf-8")))
    if not isinstance(queries, list) or len(queries) != 1:
        pytest.fail(f"{expectation.id}: expected 1 query, got {queries!r}")
    return queries[0]


def _dataset_label(dataset: Path) -> str:
    """Stable label per dataset basename — keeps queries from one dataset
    out of another's hit count when both are loaded into the same VL."""
    return dataset.stem


def _ensure_ingested(vl_url: str, dataset: Path, ingested_set: set[str]) -> None:
    key = str(dataset.resolve())
    if key in ingested_set:
        return
    ingest_jsonline_stamp_now(
        vl_url,
        dataset,
        stream_field=CADDY_STREAM_FIELDS,
        msg_field=CADDY_MSG_FIELD,
        dataset_label=_dataset_label(dataset),
    )
    ingested_set.add(key)


def _scope(query: str, label: str) -> str:
    """Wrap a converted query in a dataset_label scope filter."""
    return f'dataset_label:="{label}" AND ({query})'


def _expectation_id(exp: Expectation) -> str:
    return exp.id


@pytest.mark.parametrize(
    "expectation", load_expectations(path=CADDY_EXPECTATIONS_PATH), ids=_expectation_id
)
def test_caddy_rule_finds_expected_events(
    expectation: Expectation,
    vl_url: str,
    datasets_dir: Path,
    ingested_set: set[str],
) -> None:
    dataset = expectation.absolute_dataset_path(datasets_dir=datasets_dir)
    if not dataset.is_file():
        pytest.skip(f"dataset missing: {dataset} (run `make e2e-fetch`)")

    raw_query = _convert(expectation)
    _ensure_ingested(vl_url, dataset, ingested_set)
    query = _scope(raw_query, _dataset_label(dataset))

    if expectation.kind == "positive":
        hits = wait_until_count(vl_url, query, expected=expectation.min_hits, timeout=30.0)
        assert hits >= expectation.min_hits, (
            f"{expectation.id}: expected >= {expectation.min_hits} hits, got {hits}.\n"
            f"  query: {query}\n"
            f"  rule:  {expectation.rule_path}\n"
            f"  data:  {expectation.dataset_path}\n"
            f"  notes: {expectation.notes or '(none)'}"
        )
    else:  # negative
        hits = logsql_count(vl_url, query)
        assert hits == 0, (
            f"{expectation.id}: expected 0 hits (negative), got {hits}.\n"
            f"  query: {query}\n"
            f"  rule:  {expectation.rule_path}\n"
            f"  data:  {expectation.dataset_path}"
        )
