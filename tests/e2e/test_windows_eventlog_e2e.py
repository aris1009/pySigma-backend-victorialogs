"""End-to-end Windows EventLog correctness harness.

For each entry in e2e/expectations.yml:
  1. Convert the upstream Sigma rule via victorialogs_windows_eventlog().
  2. Wait until Vector has shipped the OTRF dataset into VL. Vector tails
     ``e2e/datasets/otrf/*.json`` continuously when the e2e profile is up
     (see e2e/vector.toml + e2e/docker-compose.yml). Each event is tagged
     with a ``dataset_label`` derived from the source filename so multiple
     datasets can coexist in VL without leaking into each other's queries.
  3. Query VL with the converted LogsQL, scoped by ``dataset_label``.
  4. Assert hits >= min_hits (positive) or hits == 0 (negative).

The harness is gated behind the `e2e` pytest marker — `pytest tests/e2e -m e2e`
or `make e2e-test`. The default unit suite skips it.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sigma.collection import SigmaCollection

from sigma.backends.victorialogs import VictoriaLogsBackend
from sigma.pipelines.victorialogs import victorialogs_windows_eventlog
from tests.e2e._expectations import Expectation, load_expectations
from tests.e2e._runtime import (
    logsql_count,
    wait_until_count,
)

pytestmark = pytest.mark.e2e


def _convert(expectation: Expectation) -> str:
    rule_path = expectation.absolute_rule_path()
    if not rule_path.is_file():
        pytest.fail(
            f"{expectation.id}: rule_path {expectation.rule_path} not found under "
            f"SIGMA_CORPUS_PATH ({rule_path.parent}). Clone SigmaHQ/sigma there."
        )
    backend = VictoriaLogsBackend(processing_pipeline=victorialogs_windows_eventlog())
    queries = backend.convert(SigmaCollection.from_yaml(rule_path.read_text(encoding="utf-8")))
    if not isinstance(queries, list) or len(queries) != 1:
        pytest.fail(f"{expectation.id}: expected 1 query, got {queries!r}")
    return queries[0]


def _dataset_label(dataset: Path) -> str:
    """Stable label per dataset basename — must match Vector's per-file label
    (e2e/vector.toml: parse_otrf transform derives it from the filename)."""
    return dataset.stem


def _wait_until_shipped(vl_url: str, label: str, *, timeout: float = 60.0) -> int:
    """Poll until Vector has shipped any events tagged with ``label`` into VL.

    Vector tails the OTRF dumps continuously, so the first call per-dataset
    blocks until shipping starts; subsequent calls return immediately.
    """
    query = f'dataset_label:="{label}"'
    return wait_until_count(vl_url, query, expected=1, timeout=timeout)


def _scope(query: str, label: str) -> str:
    """Wrap a converted query in a dataset_label scope filter."""
    return f'dataset_label:="{label}" AND ({query})'


def _expectation_id(exp: Expectation) -> str:
    return exp.id


@pytest.mark.parametrize("expectation", load_expectations(), ids=_expectation_id)
def test_rule_finds_expected_events(
    expectation: Expectation,
    vl_url: str,
    datasets_dir: Path,
) -> None:
    dataset = expectation.absolute_dataset_path(datasets_dir=datasets_dir)
    if not dataset.is_file():
        pytest.skip(f"dataset missing: {dataset} (run `make e2e-fetch`)")

    raw_query = _convert(expectation)
    label = _dataset_label(dataset)
    shipped = _wait_until_shipped(vl_url, label)
    if shipped == 0:
        pytest.fail(
            f"{expectation.id}: Vector has not shipped any rows tagged "
            f"dataset_label={label!r} after 60s. Check `podman logs "
            f"internal-vector` for transform/sink errors."
        )
    query = _scope(raw_query, label)

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
