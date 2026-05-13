"""
Corpus coverage test against the public SigmaHQ/sigma rule collection.

There is no official cross-backend conformance suite for pySigma backends —
each backend hand-picks tests. The closest community standard is the
SigmaHQ/sigma corpus (~3000 YAML rules). This test:

  1. Walks a curated subset of categories that are realistic targets for a
     log-search backend (Linux, network, web, application, category-level).
  2. Converts every rule.
  3. Records (success | unsupported | error) per rule.
  4. Asserts a minimum success rate so regressions in the modifier handling
     surface immediately.

The test is **skipped** if `SIGMA_CORPUS_PATH` is not set, because we don't
ship the corpus in-repo. To run locally:

    git clone --depth=1 https://github.com/SigmaHQ/sigma /tmp/sigma-rules
    SIGMA_CORPUS_PATH=/tmp/sigma-rules poetry run pytest tests/test_corpus.py -v

A "success" means pySigma converts the rule to one or more LogsQL strings
without raising. An "unsupported" outcome (SigmaFeatureNotSupportedByBackendError
or NotImplementedError on a backend hook) is expected for some rules — we count
them but don't fail. Anything else (TypeError, KeyError, …) is a real bug and
fails the test.
"""

from __future__ import annotations

import os
from collections import Counter
from pathlib import Path

import pytest
import yaml
from sigma.collection import SigmaCollection
from sigma.exceptions import (
    SigmaError,
    SigmaFeatureNotSupportedByBackendError,
)

from sigma.backends.victorialogs import VictoriaLogsBackend

CORPUS_ENV = "SIGMA_CORPUS_PATH"
# Subdirectories under <corpus>/rules to walk. Process-creation Windows rules
# tend to need product-specific pipelines; we exclude them in v1 and revisit
# in Phase 3 when those pipelines exist.
CATEGORIES = [
    "linux",
    "network",
    "web",
    "application",
    "category",
    "macos",
    "windows",
    "cloud",
    "identity",
]
# How many rules to sample per category, to keep the test fast. None = all.
SAMPLE_PER_CATEGORY: int | None = None
# Minimum success rate over the corpus. The current backend converts 100% of
# rules at the syntax layer; we set the floor below 1.0 to leave headroom for
# upstream Sigma-spec changes that introduce modifiers we haven't wired yet.
MIN_SUCCESS_RATE = 0.99


def _corpus_root() -> Path | None:
    raw = os.environ.get(CORPUS_ENV)
    if not raw:
        return None
    p = Path(raw) / "rules"
    return p if p.is_dir() else None


def _load_rules(root: Path) -> list[Path]:
    out: list[Path] = []
    for cat in CATEGORIES:
        cat_root = root / cat
        if not cat_root.is_dir():
            continue
        files = sorted(cat_root.rglob("*.yml"))
        if SAMPLE_PER_CATEGORY:
            files = files[:SAMPLE_PER_CATEGORY]
        out.extend(files)
    return out


def _is_correlation_rule(path: Path) -> bool:
    """Cheap pre-check so we can skip multi-doc correlation files that need a
    referenced rule loaded alongside them — outside this test's scope."""
    try:
        text = path.read_text()
    except OSError:
        return False
    # Multi-doc YAML; correlation rules live in the second document.
    return "\ncorrelation:" in text or text.lstrip().startswith("correlation:")


@pytest.mark.skipif(_corpus_root() is None, reason=f"set {CORPUS_ENV} to run")
def test_corpus_conversion_success_rate():
    root = _corpus_root()
    assert root is not None  # narrows for type checker
    backend = VictoriaLogsBackend()

    rules = _load_rules(root)
    assert rules, f"no .yml files found under {root}"

    counts: Counter[str] = Counter()
    failures: list[tuple[Path, str]] = []

    for path in rules:
        if _is_correlation_rule(path):
            counts["skipped_correlation"] += 1
            continue
        try:
            text = path.read_text()
        except OSError as exc:
            counts["read_error"] += 1
            failures.append((path, f"read: {exc}"))
            continue

        try:
            collection = SigmaCollection.from_yaml(text)
        except (yaml.YAMLError, SigmaError):
            # Malformed-rule problems are not the backend's fault. Count and skip.
            counts["parse_error"] += 1
            continue

        try:
            backend.convert(collection)
        except SigmaFeatureNotSupportedByBackendError:
            counts["unsupported"] += 1
        except NotImplementedError:
            counts["unsupported"] += 1
        except SigmaError:
            counts["sigma_error"] += 1
            failures.append((path, "SigmaError"))
        except Exception as exc:
            counts["bug"] += 1
            failures.append((path, f"{type(exc).__name__}: {exc}"))
        else:
            counts["ok"] += 1

    total_attempted = counts["ok"] + counts["unsupported"] + counts["sigma_error"] + counts["bug"]
    ok = counts["ok"]
    rate = ok / total_attempted if total_attempted else 0.0

    print(
        f"\nCorpus conversion: ok={ok}/{total_attempted} ({rate:.1%})  "
        f"unsupported={counts['unsupported']}  sigma_error={counts['sigma_error']}  "
        f"bug={counts['bug']}  parse_error={counts['parse_error']}  "
        f"skipped_correlation={counts['skipped_correlation']}"
    )

    # Bug-class failures (unexpected exception types) always fail the test.
    if counts["bug"]:
        sample = "\n  ".join(f"{p}: {m}" for p, m in failures[:5])
        pytest.fail(f"{counts['bug']} rule(s) raised unexpected exceptions; first 5:\n  {sample}")

    assert rate >= MIN_SUCCESS_RATE, (
        f"corpus success rate {rate:.1%} below threshold {MIN_SUCCESS_RATE:.1%}"
    )
