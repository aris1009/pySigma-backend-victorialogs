"""Unit tests for the e2e dataset fetcher.

Covers manifest parsing, archive extraction, sha256 verification, the
cache-skip path, and the synthetic-source dispatch. The HTTP layer is
patched so these tests are fully offline.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import sys
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "dev"))
sys.path.insert(0, str(REPO_ROOT))

import fetch_datasets as fwd  # noqa: E402

# ---------------------------- helpers -----------------------------


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _zip_with(member: str, payload: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(member, payload)
    return buf.getvalue()


def _write_manifest(path: Path, entries: list[dict]) -> None:
    path.write_text(yaml.safe_dump({"version": 1, "datasets": entries}, sort_keys=False))


# ---------------------------- manifest parsing -----------------------------


def test_load_manifest_round_trip(tmp_path: Path):
    m = tmp_path / "datasets.yml"
    _write_manifest(
        m,
        [
            {
                "name": "a",
                "source": "otrf",
                "url": "https://example.invalid/a.zip",
                "sha256": "deadbeef",
                "archive": "zip",
                "target": "otrf/a.json",
            }
        ],
    )
    raw, entries = fwd._load_manifest(m)
    assert raw["version"] == 1
    assert len(entries) == 1
    assert entries[0].name == "a"
    assert entries[0].sha256 == "deadbeef"
    assert entries[0].target == Path("otrf/a.json")


def test_load_manifest_rejects_unknown_archive(tmp_path: Path):
    m = tmp_path / "datasets.yml"
    _write_manifest(
        m,
        [
            {
                "name": "a",
                "source": "otrf",
                "url": "https://example.invalid/a.bin",
                "sha256": "x",
                "archive": "tar",
                "target": "x/a.json",
            }
        ],
    )
    with pytest.raises(SystemExit, match="not in"):
        fwd._load_manifest(m)


def test_load_manifest_rejects_traversal_target(tmp_path: Path):
    m = tmp_path / "datasets.yml"
    _write_manifest(
        m,
        [
            {
                "name": "a",
                "source": "otrf",
                "url": "https://example.invalid/a.zip",
                "sha256": "x",
                "archive": "zip",
                "target": "../etc/passwd",
            }
        ],
    )
    with pytest.raises(SystemExit, match="parent traversal"):
        fwd._load_manifest(m)


def test_load_manifest_rejects_duplicate_names(tmp_path: Path):
    m = tmp_path / "datasets.yml"
    _write_manifest(
        m,
        [
            {
                "name": "a",
                "source": "otrf",
                "url": "https://example.invalid/a.zip",
                "sha256": "x",
                "archive": "zip",
                "target": "otrf/a.json",
            },
            {
                "name": "a",
                "source": "otrf",
                "url": "https://example.invalid/b.zip",
                "sha256": "y",
                "archive": "zip",
                "target": "otrf/b.json",
            },
        ],
    )
    with pytest.raises(SystemExit, match="duplicate name"):
        fwd._load_manifest(m)


def test_load_manifest_rejects_wrong_version(tmp_path: Path):
    m = tmp_path / "datasets.yml"
    m.write_text(yaml.safe_dump({"version": 2, "datasets": []}))
    with pytest.raises(SystemExit, match="version: 1"):
        fwd._load_manifest(m)


# ---------------------------- live manifest is well-formed -----------------------------


def test_live_manifest_parses():
    """The committed e2e/datasets.yml must always parse cleanly."""
    raw, entries = fwd._load_manifest(REPO_ROOT / "e2e" / "datasets.yml")
    assert raw["version"] == 1
    assert len(entries) >= 5, "epic acceptance: at least 5 seed datasets"
    # Every entry has a sha256 (no committed unpinned entries — CI would fail).
    missing = [e.name for e in entries if not e.sha256]
    assert not missing, f"manifest entries missing sha256: {missing}"
    # Every target lives under a known source subdir.
    for e in entries:
        assert e.target.parts[0] in {"otrf", "evtx-samples", "synth"}, e.target


# ---------------------------- extraction -----------------------------


def test_extract_zip_single_json(tmp_path: Path):
    payload = b'{"hello": "world"}'
    archive = _zip_with("nested/data.json", payload)
    entry = fwd.Entry(
        name="t",
        source="otrf",
        url="https://example.invalid/x.zip",
        sha256=_sha(archive),
        archive="zip",
        target=Path("otrf/x.json"),
        member=None,
        description="",
    )
    out = tmp_path / "x.json"
    fwd._extract(entry, archive, out)
    assert out.read_bytes() == payload


def test_extract_zip_ambiguous_requires_member(tmp_path: Path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.json", b"{}")
        zf.writestr("b.json", b"{}")
    archive = buf.getvalue()
    entry = fwd.Entry(
        name="t",
        source="otrf",
        url="u",
        sha256="x",
        archive="zip",
        target=Path("otrf/x.json"),
        member=None,
        description="",
    )
    with pytest.raises(SystemExit, match="specify `member"):
        fwd._extract(entry, archive, tmp_path / "x.json")


def test_extract_zip_member_selects_explicit(tmp_path: Path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.json", b'{"pick": "me"}')
        zf.writestr("b.json", b'{"not": "this"}')
    archive = buf.getvalue()
    entry = fwd.Entry(
        name="t",
        source="otrf",
        url="u",
        sha256="x",
        archive="zip",
        target=Path("otrf/x.json"),
        member="a.json",
        description="",
    )
    out = tmp_path / "x.json"
    fwd._extract(entry, archive, out)
    assert out.read_bytes() == b'{"pick": "me"}'


def test_extract_gzip(tmp_path: Path):
    payload = b'{"compressed": true}'
    archive = gzip.compress(payload)
    entry = fwd.Entry(
        name="t",
        source="otrf",
        url="u",
        sha256=_sha(archive),
        archive="gzip",
        target=Path("otrf/x.json"),
        member=None,
        description="",
    )
    out = tmp_path / "x.json"
    fwd._extract(entry, archive, out)
    assert out.read_bytes() == payload


def test_extract_raw(tmp_path: Path):
    payload = b'{"raw": "json"}'
    entry = fwd.Entry(
        name="t",
        source="otrf",
        url="u",
        sha256=_sha(payload),
        archive="raw",
        target=Path("otrf/x.json"),
        member=None,
        description="",
    )
    out = tmp_path / "x.json"
    fwd._extract(entry, payload, out)
    assert out.read_bytes() == payload


# ---------------------------- process_entry: sha verification -----------------------------


def test_process_entry_sha_mismatch_aborts(tmp_path: Path):
    archive = _zip_with("data.json", b"{}")
    entry = fwd.Entry(
        name="bad",
        source="otrf",
        url="https://example.invalid/x.zip",
        sha256="0" * 64,
        archive="zip",
        target=Path("otrf/x.json"),
        member=None,
        description="",
    )
    out_dir = tmp_path / "out"
    cache_dir = tmp_path / "cache"
    with (
        patch.object(fwd, "_download", return_value=archive),
        pytest.raises(SystemExit, match="sha256 mismatch"),
    ):
        fwd._process_entry(entry, out_dir=out_dir, cache_dir=cache_dir, force=False, pin=False)


def test_process_entry_unpinned_without_pin_flag_aborts(tmp_path: Path):
    archive = _zip_with("data.json", b"{}")
    entry = fwd.Entry(
        name="needs_pin",
        source="otrf",
        url="https://example.invalid/x.zip",
        sha256=None,
        archive="zip",
        target=Path("otrf/x.json"),
        member=None,
        description="",
    )
    with (
        patch.object(fwd, "_download", return_value=archive),
        pytest.raises(SystemExit, match="--pin"),
    ):
        fwd._process_entry(
            entry,
            out_dir=tmp_path / "out",
            cache_dir=tmp_path / "cache",
            force=False,
            pin=False,
        )


def test_process_entry_pin_records_sha(tmp_path: Path):
    archive = _zip_with("data.json", b'{"k": 1}')
    entry = fwd.Entry(
        name="new",
        source="otrf",
        url="https://example.invalid/x.zip",
        sha256=None,
        archive="zip",
        target=Path("otrf/x.json"),
        member=None,
        description="",
    )
    out_dir = tmp_path / "out"
    cache_dir = tmp_path / "cache"
    with patch.object(fwd, "_download", return_value=archive):
        status, computed = fwd._process_entry(
            entry,
            out_dir=out_dir,
            cache_dir=cache_dir,
            force=False,
            pin=True,
        )
    assert status == "pin"
    assert computed == _sha(archive)
    assert (out_dir / "otrf" / "x.json").read_bytes() == b'{"k": 1}'


def test_process_entry_skips_when_cached_and_target_present(tmp_path: Path):
    archive = _zip_with("data.json", b'{"x": 0}')
    sha = _sha(archive)
    entry = fwd.Entry(
        name="cached",
        source="otrf",
        url="https://example.invalid/x.zip",
        sha256=sha,
        archive="zip",
        target=Path("otrf/x.json"),
        member=None,
        description="",
    )
    out_dir = tmp_path / "out"
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    (cache_dir / "cached__x.zip").write_bytes(archive)
    target = out_dir / "otrf" / "x.json"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"already here")
    with patch.object(fwd, "_download", side_effect=AssertionError("must not download")):
        status, _ = fwd._process_entry(
            entry,
            out_dir=out_dir,
            cache_dir=cache_dir,
            force=False,
            pin=False,
        )
    assert status == "skip"


def test_process_entry_force_redownloads(tmp_path: Path):
    archive = _zip_with("data.json", b'{"x": 0}')
    sha = _sha(archive)
    entry = fwd.Entry(
        name="forced",
        source="otrf",
        url="https://example.invalid/x.zip",
        sha256=sha,
        archive="zip",
        target=Path("otrf/x.json"),
        member=None,
        description="",
    )
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    (cache_dir / "forced__x.zip").write_bytes(b"stale-bytes")
    with patch.object(fwd, "_download", return_value=archive) as dl:
        status, _ = fwd._process_entry(
            entry,
            out_dir=tmp_path / "out",
            cache_dir=cache_dir,
            force=True,
            pin=False,
        )
    assert dl.called
    assert status == "fetch"


# ---------------------------- pin write-back -----------------------------


def test_pin_write_back_preserves_other_entries(tmp_path: Path):
    m = tmp_path / "datasets.yml"
    _write_manifest(
        m,
        [
            {
                "name": "old",
                "source": "otrf",
                "url": "u1",
                "sha256": "abc",
                "archive": "raw",
                "target": "otrf/old.json",
            },
            {
                "name": "new",
                "source": "otrf",
                "url": "u2",
                "sha256": None,
                "archive": "raw",
                "target": "otrf/new.json",
            },
        ],
    )
    raw, _ = fwd._load_manifest(m)
    fwd._write_pinned_manifest(m, raw, {"new": "deadbeef" * 8})
    raw2, _ = fwd._load_manifest(m)
    by_name = {e["name"]: e for e in raw2["datasets"]}
    assert by_name["old"]["sha256"] == "abc"
    assert by_name["new"]["sha256"] == "deadbeef" * 8


def test_pin_write_back_preserves_comments_and_dividers(tmp_path: Path):
    """Regression test: --pin must not destroy header
    comments, section dividers, or literal-block descriptions."""
    m = tmp_path / "datasets.yml"
    original = (
        "# Top header.\n"
        "# Schema notes:\n"
        "#   - field A\n"
        "#   - field B\n"
        "\n"
        "version: 1\n"
        "\n"
        "datasets:\n"
        "  - name: pinned_already\n"
        "    source: otrf\n"
        "    url: https://example.invalid/a.zip\n"
        "    sha256: abc123\n"
        "    archive: zip\n"
        "    target: otrf/a.json\n"
        "    description: |\n"
        "      Multi-line literal block\n"
        "      that must not be reflowed.\n"
        "\n"
        "  # ---- section divider ----\n"
        "\n"
        "  - name: needs_pinning\n"
        "    source: synthetic\n"
        "    generator: caddy\n"
        "    seed: 42\n"
        "    count: 4\n"
        "    sha256:\n"
        "    target: synth/x.ndjson\n"
        "    description: |\n"
        "      Trailing block.\n"
    )
    m.write_text(original, encoding="utf-8")
    raw, _ = fwd._load_manifest(m)
    fwd._write_pinned_manifest(m, raw, {"needs_pinning": "f" * 64})

    written = m.read_text(encoding="utf-8")
    assert "# Top header." in written
    assert "# Schema notes:" in written
    assert "  #   - field A" not in written  # original was top-level
    assert "#   - field A" in written
    assert "# ---- section divider ----" in written
    assert "Multi-line literal block" in written
    assert "that must not be reflowed." in written
    assert "Trailing block." in written
    assert f"    sha256: {'f' * 64}\n" in written
    # Untouched entry's sha256 stays put.
    assert "    sha256: abc123\n" in written
    # Re-parse: pin landed correctly.
    _, entries = fwd._load_manifest(m)
    pinned = {e.name: e.sha256 for e in entries}
    assert pinned["pinned_already"] == "abc123"
    assert pinned["needs_pinning"] == "f" * 64


def test_pin_write_back_errors_when_sha_line_missing(tmp_path: Path):
    """If an entry has no `sha256:` line at all, refuse to guess where to
    insert one — tell the user to add an empty placeholder."""
    m = tmp_path / "datasets.yml"
    m.write_text(
        "version: 1\n"
        "datasets:\n"
        "  - name: no_sha_line\n"
        "    source: synthetic\n"
        "    generator: caddy\n"
        "    seed: 1\n"
        "    count: 1\n"
        "    target: synth/x.ndjson\n",
        encoding="utf-8",
    )
    raw, _ = fwd._load_manifest(m)
    with pytest.raises(SystemExit, match="could not locate a `sha256:` line"):
        fwd._write_pinned_manifest(m, raw, {"no_sha_line": "0" * 64})


def test_pin_write_back_noop_on_empty_pins(tmp_path: Path):
    m = tmp_path / "datasets.yml"
    original = "# do not touch\nversion: 1\ndatasets: []\n"
    m.write_text(original, encoding="utf-8")
    fwd._write_pinned_manifest(m, {"version": 1, "datasets": []}, {})
    assert m.read_text(encoding="utf-8") == original


# ---------------------------- synthetic source dispatch -----------------------------


def _synth_entry(**overrides) -> dict:
    base = {
        "name": "synth1",
        "source": "synthetic",
        "generator": "caddy",
        "seed": 42,
        "count": 5,
        "sha256": None,
        "target": "synth/caddy_test.ndjson",
    }
    base.update(overrides)
    # Drop fields explicitly set to None to mirror manifest absence semantics.
    return {k: v for k, v in base.items() if v is not None or k == "sha256"}


def test_load_manifest_synthetic_round_trip(tmp_path: Path):
    m = tmp_path / "datasets.yml"
    _write_manifest(m, [_synth_entry(sha256="deadbeef" * 8)])
    _, entries = fwd._load_manifest(m)
    assert len(entries) == 1
    e = entries[0]
    assert e.source == "synthetic"
    assert e.generator == "caddy"
    assert e.seed == 42
    assert e.count == 5
    assert e.url is None
    assert e.archive is None


def test_load_manifest_synthetic_requires_generator(tmp_path: Path):
    m = tmp_path / "datasets.yml"
    raw = _synth_entry(sha256="x")
    raw.pop("generator")
    _write_manifest(m, [raw])
    with pytest.raises(SystemExit, match="requires `generator`"):
        fwd._load_manifest(m)


def test_load_manifest_synthetic_requires_seed(tmp_path: Path):
    m = tmp_path / "datasets.yml"
    raw = _synth_entry(sha256="x")
    raw.pop("seed")
    _write_manifest(m, [raw])
    with pytest.raises(SystemExit, match="requires `seed`"):
        fwd._load_manifest(m)


def test_load_manifest_synthetic_rejects_url(tmp_path: Path):
    m = tmp_path / "datasets.yml"
    _write_manifest(m, [_synth_entry(sha256="x", url="https://example.invalid")])
    with pytest.raises(SystemExit, match="must not declare `url`"):
        fwd._load_manifest(m)


def test_load_manifest_synthetic_rejects_zero_count(tmp_path: Path):
    m = tmp_path / "datasets.yml"
    _write_manifest(m, [_synth_entry(sha256="x", count=0)])
    with pytest.raises(SystemExit, match="count must be"):
        fwd._load_manifest(m)


def test_load_manifest_unknown_source(tmp_path: Path):
    m = tmp_path / "datasets.yml"
    _write_manifest(
        m,
        [
            {
                "name": "x",
                "source": "homelab",
                "url": "u",
                "archive": "zip",
                "sha256": "x",
                "target": "otrf/x.json",
            }
        ],
    )
    with pytest.raises(SystemExit, match="not in"):
        fwd._load_manifest(m)


def test_synthesise_runs_generator_deterministically():
    entry = fwd.Entry(
        name="t",
        source="synthetic",
        sha256=None,
        target=Path("synth/x.ndjson"),
        description="",
        generator="caddy",
        seed=7,
        count=3,
    )
    a = fwd._synthesise(entry)
    b = fwd._synthesise(entry)
    assert a == b
    # NDJSON: 3 lines, each ending in \n.
    assert a.count(b"\n") == 3


def test_synthesise_unknown_generator_aborts():
    entry = fwd.Entry(
        name="t",
        source="synthetic",
        sha256=None,
        target=Path("synth/x.ndjson"),
        description="",
        generator="bogus",
        seed=1,
        count=1,
    )
    with pytest.raises(SystemExit, match="unknown generator"):
        fwd._synthesise(entry)


def test_process_synthetic_pin_records_sha(tmp_path: Path):
    entry = fwd.Entry(
        name="t",
        source="synthetic",
        sha256=None,
        target=Path("synth/caddy.ndjson"),
        description="",
        generator="caddy",
        seed=42,
        count=4,
    )
    out_dir = tmp_path / "out"
    status, computed = fwd._process_entry(
        entry, out_dir=out_dir, cache_dir=tmp_path / "cache", force=False, pin=True
    )
    assert status == "pin"
    assert computed and len(computed) == 64
    target = out_dir / "synth" / "caddy.ndjson"
    assert target.exists()
    # Re-running with the recorded sha must verify.
    entry.sha256 = computed
    status2, _ = fwd._process_entry(
        entry, out_dir=out_dir, cache_dir=tmp_path / "cache", force=False, pin=False
    )
    assert status2 == "skip"


def test_process_synthetic_sha_mismatch_aborts(tmp_path: Path):
    entry = fwd.Entry(
        name="t",
        source="synthetic",
        sha256="0" * 64,
        target=Path("synth/caddy.ndjson"),
        description="",
        generator="caddy",
        seed=42,
        count=2,
    )
    with pytest.raises(SystemExit, match="sha256 mismatch"):
        fwd._process_entry(
            entry,
            out_dir=tmp_path / "out",
            cache_dir=tmp_path / "cache",
            force=False,
            pin=False,
        )


def test_process_synthetic_force_rewrites(tmp_path: Path):
    """--force re-runs the generator even when the on-disk sha matches."""
    entry = fwd.Entry(
        name="t",
        source="synthetic",
        sha256=None,
        target=Path("synth/caddy.ndjson"),
        description="",
        generator="caddy",
        seed=42,
        count=2,
    )
    out_dir = tmp_path / "out"
    # Pin first.
    _, sha = fwd._process_entry(
        entry, out_dir=out_dir, cache_dir=tmp_path / "cache", force=False, pin=True
    )
    entry.sha256 = sha
    # With --force, status is fetch (not skip) even though sha matches.
    status, _ = fwd._process_entry(
        entry, out_dir=out_dir, cache_dir=tmp_path / "cache", force=True, pin=False
    )
    assert status == "fetch"
