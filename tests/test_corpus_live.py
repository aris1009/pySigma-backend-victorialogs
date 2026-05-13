"""Corpus + live-VL integration test.

`test_corpus.py` measures only "did pySigma raise?". It reports 100%
(3132/3132) while live-VL re-validation found 55/3132 actual HTTP 400s
— bugs the test couldn't see (IPv6 CIDR family dispatch, literal `\\*`/`\\?`
escape preservation). This test sends every emitted query to a live VL
instance and asserts each one parses (HTTP 200), with a per-bucket allowlist
for known-acceptable failures.

Skipped unless BOTH `SIGMA_CORPUS_PATH` and `VICTORIALOGS_URL` are set; runs
in ~30s with 12 worker threads against a fast local VL.

To run:

    git clone --depth=1 https://github.com/SigmaHQ/sigma /tmp/sigma-rules
    SIGMA_CORPUS_PATH=/tmp/sigma-rules \\
    VICTORIALOGS_URL=http://localhost:9428 \\
        poetry run pytest tests/test_corpus_live.py -v -s
"""

from __future__ import annotations

import os
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import pytest
import yaml
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError, SigmaFeatureNotSupportedByBackendError

from sigma._dev.wrap import wrap_query
from sigma.backends.victorialogs import VictoriaLogsBackend

CORPUS_ENV = "SIGMA_CORPUS_PATH"
VL_ENV = "VICTORIALOGS_URL"

# Categories under <corpus>/rules to walk. Same set as test_corpus.py.
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

# Allowlist of failure-bucket prefixes. Each entry is matched as a substring of
# the VL error body's first line. Anything not matched fails the test.
#
# `-search.maxQueryLen=...` : 6-7 corpus rules emit huge IOC OR-chains that
# bust the default 16384-byte cap (driver_load IOC blocklists, emoji glyph
# alternations). Out of scope for the backend; see docs/limitations.md.
ALLOWED_BUCKETS: tuple[str, ...] = ("the `query` arg length cannot exceed -search.maxQueryLen",)
# Hard ceiling on allowlisted failures — a regression that doubles the count
# should fail the test even if every individual failure matches the allowlist.
MAX_ALLOWED_FAILURES = 12


def _corpus_root() -> Path | None:
    raw = os.environ.get(CORPUS_ENV)
    if not raw:
        return None
    p = Path(raw) / "rules"
    return p if p.is_dir() else None


def _vl_url() -> str | None:
    raw = os.environ.get(VL_ENV)
    return raw.rstrip("/") if raw else None


def _is_correlation_rule(path: Path) -> bool:
    try:
        text = path.read_text()
    except OSError:
        return False
    return "\ncorrelation:" in text or text.lstrip().startswith("correlation:")


def _check(vl_url: str, query: str, retries: int = 2) -> tuple[bool, str]:
    """HTTP-200 check with one retry on transient failures.

    HTTPError surfaces immediately — those are real "VL rejected this query"
    signals. Connection / timeout errors are retried since they can be noisy
    over flaky networks and would otherwise produce flaky test results.
    """
    url = f"{vl_url}/select/logsql/query?" + urllib.parse.urlencode(
        {"query": wrap_query(query), "limit": "1"}
    )
    last_err = ""
    for _ in range(retries + 1):
        try:
            with urllib.request.urlopen(url, timeout=15) as resp:
                resp.read(512)
                return True, ""
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")
            return False, body.splitlines()[0][:200] if body else f"HTTP {exc.code}"
        except Exception as exc:
            last_err = f"{type(exc).__name__}: {exc}"[:200]
    return False, last_err


def _is_allowed(err: str) -> bool:
    return any(prefix in err for prefix in ALLOWED_BUCKETS)


@pytest.mark.skipif(
    _corpus_root() is None or _vl_url() is None,
    reason=f"set {CORPUS_ENV}=/path/to/sigma and {VL_ENV}=http://host:9428 to run",
)
def test_corpus_live_validation():
    root = _corpus_root()
    vl = _vl_url()
    assert root is not None and vl is not None  # narrows for type checker

    backend = VictoriaLogsBackend()
    rules = sorted(p for cat in CATEGORIES for p in (root / cat).rglob("*.yml"))
    assert rules, f"no .yml files found under {root}"

    queries: list[tuple[Path, str]] = []
    counts: Counter[str] = Counter()

    for path in rules:
        if _is_correlation_rule(path):
            counts["skipped_correlation"] += 1
            continue
        try:
            text = path.read_text()
        except OSError:
            counts["read_error"] += 1
            continue
        try:
            collection = SigmaCollection.from_yaml(text)
        except (yaml.YAMLError, SigmaError):
            counts["parse_error"] += 1
            continue
        try:
            out = backend.convert(collection)
        except (SigmaFeatureNotSupportedByBackendError, NotImplementedError):
            counts["unsupported"] += 1
            continue
        except SigmaError:
            counts["sigma_error"] += 1
            continue
        for q in out:
            queries.append((path, q))

    by_error: defaultdict[str, list[tuple[Path, str]]] = defaultdict(list)
    live_ok = 0
    live_fail = 0

    def task(item: tuple[Path, str]) -> tuple[Path, str, bool, str]:
        path, q = item
        ok, err = _check(vl, q)
        return path, q, ok, err

    with ThreadPoolExecutor(max_workers=12) as pool:
        for fut in as_completed(pool.submit(task, it) for it in queries):
            path, q, ok, err = fut.result()
            if ok:
                live_ok += 1
            else:
                live_fail += 1
                by_error[err].append((path, q))

    print(
        f"\nLive corpus: {live_ok}/{len(queries)} parsed, {live_fail} failed; "
        f"unsupported={counts['unsupported']} parse_error={counts['parse_error']} "
        f"skipped_correlation={counts['skipped_correlation']}"
    )

    unexpected: list[tuple[str, list[tuple[Path, str]]]] = []
    allowed = 0
    for err, items in sorted(by_error.items(), key=lambda kv: -len(kv[1])):
        bucket_label = "ALLOWED" if _is_allowed(err) else "UNEXPECTED"
        print(f"  [{len(items)}] {bucket_label}: {err}")
        if _is_allowed(err):
            allowed += len(items)
        else:
            unexpected.append((err, items))

    if unexpected:
        sample_lines: list[str] = []
        for err, items in unexpected[:3]:
            sample_lines.append(f"\n  {err}")
            for p, q in items[:3]:
                sample_lines.append(f"    - {p.relative_to(root.parent)}: {q[:200]}")
        pytest.fail(
            f"{sum(len(items) for _, items in unexpected)} unexpected live-VL "
            f"failures (not in allowlist):" + "".join(sample_lines)
        )

    assert allowed <= MAX_ALLOWED_FAILURES, (
        f"allowlisted failure count {allowed} exceeded ceiling "
        f"{MAX_ALLOWED_FAILURES} — investigate before raising the cap"
    )
