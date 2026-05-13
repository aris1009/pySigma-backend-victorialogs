"""Loader for e2e/expectations.yml — the rule-by-dataset contract.

Kept as a private module under ``tests/e2e/`` because it is exclusively
consumed by the e2e harness. Schema is described in the
header comment of e2e/expectations.yml.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_EXPECTATIONS = REPO_ROOT / "e2e" / "expectations.yml"
DEFAULT_DATASETS_DIR = REPO_ROOT / "e2e" / "datasets"


def sigma_corpus_root() -> Path:
    """Resolve the SigmaHQ rules root. Defaults to /tmp/sigma-rules per CLAUDE.md."""
    return Path(os.environ.get("SIGMA_CORPUS_PATH", "/tmp/sigma-rules"))


@dataclass(frozen=True)
class Expectation:
    id: str
    rule_path: Path  # relative to SIGMA_CORPUS_PATH
    dataset_path: Path  # relative to e2e/datasets/
    kind: Literal["positive", "negative"]
    min_hits: int  # 0 for negative
    notes: str

    def absolute_rule_path(self, corpus_root: Path | None = None) -> Path:
        return (corpus_root or sigma_corpus_root()) / self.rule_path

    def absolute_dataset_path(self, datasets_dir: Path | None = None) -> Path:
        return (datasets_dir or DEFAULT_DATASETS_DIR) / self.dataset_path


def load_expectations(path: Path | None = None) -> list[Expectation]:
    p = path or DEFAULT_EXPECTATIONS
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("version") != 1:
        raise ValueError(f"{p}: missing or unsupported `version: 1`")
    items = raw.get("expectations")
    if not isinstance(items, list) or not items:
        raise ValueError(f"{p}: `expectations` must be a non-empty list")

    out: list[Expectation] = []
    seen_ids: set[str] = set()
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            raise ValueError(f"{p}: expectations[{i}] is not a mapping")
        try:
            eid = str(item["id"])
            rule_path = Path(item["rule_path"])
            dataset_path = Path(item["dataset_path"])
            kind = str(item["kind"])
        except KeyError as e:
            raise ValueError(f"{p}: expectations[{i}] missing required field {e}") from e
        if eid in seen_ids:
            raise ValueError(f"{p}: duplicate id {eid!r}")
        seen_ids.add(eid)
        if kind not in ("positive", "negative"):
            raise ValueError(f"{p}: {eid}: kind must be positive|negative, got {kind!r}")
        if rule_path.is_absolute() or ".." in rule_path.parts:
            raise ValueError(f"{p}: {eid}: rule_path must be repo-relative, got {rule_path}")
        if dataset_path.is_absolute() or ".." in dataset_path.parts:
            raise ValueError(f"{p}: {eid}: dataset_path must be repo-relative, got {dataset_path}")

        if kind == "positive":
            min_hits = int(item.get("min_hits", 1))
            if min_hits < 1:
                raise ValueError(f"{p}: {eid}: positive requires min_hits >= 1, got {min_hits}")
        else:
            min_hits = 0
            if "min_hits" in item:
                raise ValueError(f"{p}: {eid}: negative must not set min_hits")

        out.append(
            Expectation(
                id=eid,
                rule_path=rule_path,
                dataset_path=dataset_path,
                kind=kind,  # type: ignore[arg-type]
                min_hits=min_hits,
                notes=str(item.get("notes", "")).strip(),
            )
        )
    return out
