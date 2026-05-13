"""End-to-end Kubernetes audit (podman pipeline) correctness harness.

Mirrors test_caddy_e2e.py but for the ``victorialogs_podman`` pipeline:

  1. Convert each rule via victorialogs_podman().
  2. POST the synthetic NDJSON dataset to /insert/jsonline (idempotent),
     stamping ``_time`` to now and tagging each event with a
     ``dataset_label`` so attack/benign datasets can coexist in the same
     VL without leaking into each other's queries.
  3. Query VL with the converted LogsQL, scoped by ``dataset_label``.
  4. Assert hits >= min_hits (positive) or hits == 0 (negative).

The k8s-audit rules under test use field-anchored selectors (``verb``,
``objectRef.*``, ``responseStatus.code`` ...) — no unbound keyword
filters — so the harness does not map any source field onto ``_msg``.

Gated behind the `e2e` pytest marker.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sigma.collection import SigmaCollection

from sigma.backends.victorialogs import VictoriaLogsBackend
from sigma.pipelines.victorialogs import victorialogs_podman
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

PODMAN_EXPECTATIONS_PATH = REPO_ROOT / "e2e" / "expectations_podman.yml"
# Audit events carry `kind: "Event"` — combined with `dataset_label` it
# gives every dataset its own VL stream.
PODMAN_STREAM_FIELDS = "kind,dataset_label"


def _convert(expectation: Expectation) -> str:
    rule_path = expectation.absolute_rule_path()
    if not rule_path.is_file():
        pytest.fail(
            f"{expectation.id}: rule_path {expectation.rule_path} not found under "
            f"SIGMA_CORPUS_PATH ({rule_path.parent}). Clone SigmaHQ/sigma there."
        )
    backend = VictoriaLogsBackend(processing_pipeline=victorialogs_podman())
    queries = backend.convert(SigmaCollection.from_yaml(rule_path.read_text(encoding="utf-8")))
    if not isinstance(queries, list) or len(queries) != 1:
        pytest.fail(f"{expectation.id}: expected 1 query, got {queries!r}")
    return queries[0]


def _dataset_label(dataset: Path) -> str:
    return dataset.stem


def _ensure_ingested(vl_url: str, dataset: Path, ingested_set: set[str]) -> None:
    key = str(dataset.resolve())
    if key in ingested_set:
        return
    ingest_jsonline_stamp_now(
        vl_url,
        dataset,
        stream_field=PODMAN_STREAM_FIELDS,
        msg_field=None,
        dataset_label=_dataset_label(dataset),
    )
    ingested_set.add(key)


def _scope(query: str, label: str) -> str:
    return f'dataset_label:="{label}" AND ({query})'


def _expectation_id(exp: Expectation) -> str:
    return exp.id


@pytest.mark.parametrize(
    "expectation", load_expectations(path=PODMAN_EXPECTATIONS_PATH), ids=_expectation_id
)
def test_podman_rule_finds_expected_events(
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
