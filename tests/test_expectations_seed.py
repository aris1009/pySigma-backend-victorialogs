"""Static checks on the committed e2e/expectations.yml seed.

These tests run as part of the regular suite (no e2e marker) so a broken
seed gets caught long before anyone tries to run `make e2e`. The actual
"rule fires against dataset" assertions live in the e2e harness
, gated behind the e2e marker.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml

from tests.e2e._expectations import (
    DEFAULT_DATASETS_DIR,
    DEFAULT_EXPECTATIONS,
    Expectation,
    load_expectations,
    sigma_corpus_root,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
DATASETS_MANIFEST = REPO_ROOT / "e2e" / "datasets.yml"


# ---------------------------- schema -----------------------------


def test_seed_parses() -> None:
    expectations = load_expectations()
    assert len(expectations) >= 5, "epic 32x acceptance: at least 5 rule-by-dataset pairs"


def test_seed_covers_required_channels() -> None:
    """The epic explicitly calls out security/sysmon/powershell coverage."""
    expectations = load_expectations()
    rule_paths = [str(e.rule_path) for e in expectations]
    # We approximate channel coverage by rule-tree directory.
    assert any("/process_creation/" in p for p in rule_paths), "missing process_creation"
    assert any("/process_access/" in p for p in rule_paths), "missing process_access"
    assert any("/registry/" in p for p in rule_paths), "missing registry_set"
    assert any("/powershell/" in p for p in rule_paths), "missing powershell channel"


def test_seed_has_at_least_one_negative() -> None:
    """Negatives prove the harness can detect false-positive surface."""
    expectations = load_expectations()
    negatives = [e for e in expectations if e.kind == "negative"]
    assert negatives, "epic 32x acceptance: at least one negative expectation"


def test_seed_dataset_paths_match_manifest_targets() -> None:
    """Every referenced dataset must be a target of the fetcher manifest."""
    expectations = load_expectations()
    manifest = yaml.safe_load(DATASETS_MANIFEST.read_text(encoding="utf-8"))
    targets = {item["target"] for item in manifest["datasets"]}
    referenced = {str(e.dataset_path) for e in expectations}
    missing = referenced - targets
    assert not missing, f"expectations reference datasets not in datasets.yml: {missing}"


# ---------------------------- rule resolution (skip if corpus absent) -----------------------------


def _corpus_available() -> bool:
    return sigma_corpus_root().exists()


@pytest.mark.skipif(
    not _corpus_available(),
    reason=f"SIGMA_CORPUS_PATH ({sigma_corpus_root()}) not present",
)
def test_seed_rule_paths_exist_in_corpus() -> None:
    expectations = load_expectations()
    missing = [str(e.rule_path) for e in expectations if not e.absolute_rule_path().is_file()]
    assert not missing, f"expectations reference rule files missing from corpus: {missing}"


# ---------------------------- loader: error paths -----------------------------


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "expectations.yml"
    p.write_text(body)
    return p


def test_loader_rejects_missing_version(tmp_path: Path) -> None:
    p = _write(tmp_path, "expectations: []\n")
    with pytest.raises(ValueError, match="version: 1"):
        load_expectations(p)


def test_loader_rejects_empty_expectations(tmp_path: Path) -> None:
    p = _write(tmp_path, "version: 1\nexpectations: []\n")
    with pytest.raises(ValueError, match="non-empty"):
        load_expectations(p)


def test_loader_rejects_unknown_kind(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        "version: 1\nexpectations:\n"
        "  - id: x\n    rule_path: r.yml\n    dataset_path: d.json\n"
        "    kind: maybe\n    min_hits: 1\n",
    )
    with pytest.raises(ValueError, match="kind must be"):
        load_expectations(p)


def test_loader_rejects_negative_with_min_hits(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        "version: 1\nexpectations:\n"
        "  - id: x\n    rule_path: r.yml\n    dataset_path: d.json\n"
        "    kind: negative\n    min_hits: 1\n",
    )
    with pytest.raises(ValueError, match="negative must not"):
        load_expectations(p)


def test_loader_rejects_positive_min_hits_zero(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        "version: 1\nexpectations:\n"
        "  - id: x\n    rule_path: r.yml\n    dataset_path: d.json\n"
        "    kind: positive\n    min_hits: 0\n",
    )
    with pytest.raises(ValueError, match="min_hits >= 1"):
        load_expectations(p)


def test_loader_rejects_traversal(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        "version: 1\nexpectations:\n"
        "  - id: x\n    rule_path: ../../etc/passwd\n    dataset_path: d.json\n"
        "    kind: negative\n",
    )
    with pytest.raises(ValueError, match="repo-relative"):
        load_expectations(p)


def test_loader_rejects_duplicate_id(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        "version: 1\nexpectations:\n"
        "  - id: dup\n    rule_path: r1.yml\n    dataset_path: d.json\n"
        "    kind: negative\n"
        "  - id: dup\n    rule_path: r2.yml\n    dataset_path: d.json\n"
        "    kind: negative\n",
    )
    with pytest.raises(ValueError, match="duplicate id"):
        load_expectations(p)


def test_expectation_path_resolution(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        "version: 1\nexpectations:\n"
        "  - id: x\n    rule_path: rules/foo.yml\n    dataset_path: otrf/x.json\n"
        "    kind: positive\n    min_hits: 2\n    notes: hello\n",
    )
    [exp] = load_expectations(p)
    assert exp.id == "x"
    assert exp.min_hits == 2
    assert exp.notes == "hello"
    assert exp.absolute_rule_path(corpus_root=Path("/corp")) == Path("/corp/rules/foo.yml")
    assert exp.absolute_dataset_path(datasets_dir=Path("/data")) == Path("/data/otrf/x.json")


def test_sigma_corpus_root_honours_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SIGMA_CORPUS_PATH", "/somewhere/else")
    assert sigma_corpus_root() == Path("/somewhere/else")
    monkeypatch.delenv("SIGMA_CORPUS_PATH", raising=False)
    assert sigma_corpus_root() == Path("/tmp/sigma-rules")


# Quiet unused-import lint (used for type narrowing only).
_ = (Expectation, DEFAULT_DATASETS_DIR, DEFAULT_EXPECTATIONS, os)
