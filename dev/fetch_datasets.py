#!/usr/bin/env python3
"""Fetch / synthesise / verify e2e datasets.

Reads the manifest at ``e2e/datasets.yml`` and dispatches each entry by
``source``:

* ``source: otrf`` — download a remote archive to a cache directory,
  sha256-verify against the manifest, extract the JSON member into
  ``e2e/datasets/<target>``. The cache key is the URL's last path
  segment so a URL bump invalidates without colliding.
* ``source: synthetic`` — run the named generator from ``dev.synth``
  with the declared ``(seed, count)``, sha256-verify the output bytes
  against the manifest, write to ``e2e/datasets/<target>``. No network.

Both paths fail closed on sha256 mismatch (treated as tamper / corrupt
download / non-deterministic generator). The ``--pin`` flag computes
and writes back missing sha256 fields so a freshly-added manifest entry
can be locked in one round-trip.

This script is the implementation behind ``make e2e-fetch``. CI caches
``e2e/datasets/`` keyed on hash(e2e/datasets.yml) so the heavy
downloads only run on manifest change; synthetic entries materialise
in milliseconds and are re-run on every cache miss.

Exit codes:
    0 on success or no-op
    1 on sha256 mismatch (tamper / corrupt download / non-determinism)
    2 on manifest schema or argument errors
    3 on network failure
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import re
import shutil
import sys
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = REPO_ROOT / "e2e" / "datasets.yml"
DEFAULT_OUT_DIR = REPO_ROOT / "e2e" / "datasets"
DEFAULT_CACHE_DIR = REPO_ROOT / "e2e" / ".cache"

ALLOWED_ARCHIVE_TYPES = frozenset({"raw", "zip", "gzip"})
ALLOWED_SOURCE_TYPES = frozenset({"otrf", "evtx-samples", "synthetic"})


@dataclass
class Entry:
    name: str
    source: str
    sha256: str | None
    target: Path
    description: str
    # Download-source fields (otrf, evtx-samples).
    url: str | None = None
    archive: str | None = None
    member: str | None = None
    # Synthetic-source fields.
    generator: str | None = None
    seed: int | None = None
    count: int | None = None


def _load_manifest(path: Path) -> tuple[dict[str, Any], list[Entry]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("version") != 1:
        raise SystemExit(f"manifest {path}: missing or unsupported `version: 1`")
    datasets = raw.get("datasets")
    if not isinstance(datasets, list):
        raise SystemExit(f"manifest {path}: `datasets` must be a list")
    entries: list[Entry] = []
    seen_names: set[str] = set()
    for i, item in enumerate(datasets):
        if not isinstance(item, dict):
            raise SystemExit(f"manifest {path}: datasets[{i}] is not a mapping")
        try:
            name = str(item["name"])
            source = str(item["source"])
            target = Path(item["target"])
        except KeyError as e:
            raise SystemExit(f"manifest {path}: datasets[{i}] missing required field {e}") from e
        if name in seen_names:
            raise SystemExit(f"manifest {path}: duplicate name {name!r}")
        seen_names.add(name)
        if source not in ALLOWED_SOURCE_TYPES:
            raise SystemExit(
                f"manifest {path}: {name}: source {source!r} not in {sorted(ALLOWED_SOURCE_TYPES)}"
            )
        if target.is_absolute() or ".." in target.parts:
            raise SystemExit(
                f"manifest {path}: {name}: target must be a repo-relative path with no parent traversal"
            )
        sha = item.get("sha256")
        sha_str = str(sha).strip() if sha else None
        if sha_str == "":
            sha_str = None

        entry = Entry(
            name=name,
            source=source,
            sha256=sha_str,
            target=target,
            description=str(item.get("description", "")),
        )

        if source == "synthetic":
            for required in ("generator", "seed", "count"):
                if required not in item:
                    raise SystemExit(
                        f"manifest {path}: {name}: synthetic source requires `{required}`"
                    )
            entry.generator = str(item["generator"])
            try:
                entry.seed = int(item["seed"])
                entry.count = int(item["count"])
            except (TypeError, ValueError) as e:
                raise SystemExit(
                    f"manifest {path}: {name}: seed/count must be integers ({e})"
                ) from e
            if entry.count < 1:
                raise SystemExit(f"manifest {path}: {name}: count must be >= 1, got {entry.count}")
            # Synthetic entries reject download-only fields to keep the
            # manifest schema explicit and grep-able.
            for forbidden in ("url", "archive", "member"):
                if forbidden in item:
                    raise SystemExit(
                        f"manifest {path}: {name}: synthetic source must not declare `{forbidden}`"
                    )
        else:
            for required in ("url", "archive"):
                if required not in item:
                    raise SystemExit(
                        f"manifest {path}: {name}: {source} source requires `{required}`"
                    )
            entry.url = str(item["url"])
            entry.archive = str(item["archive"])
            entry.member = str(item["member"]) if item.get("member") else None
            if entry.archive not in ALLOWED_ARCHIVE_TYPES:
                raise SystemExit(
                    f"manifest {path}: {name}: archive {entry.archive!r} "
                    f"not in {sorted(ALLOWED_ARCHIVE_TYPES)}"
                )

        entries.append(entry)
    return raw, entries


def _sha256_of(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def _download(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "internal-fetcher/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return resp.read()
    except urllib.error.URLError as e:
        raise SystemExit(f"download failed for {url}: {e}") from e


def _extract(entry: Entry, archive_bytes: bytes, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if entry.archive == "raw":
        dest.write_bytes(archive_bytes)
        return
    if entry.archive == "gzip":
        dest.write_bytes(gzip.decompress(archive_bytes))
        return
    if entry.archive == "zip":
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zf:
            members = [n for n in zf.namelist() if not n.endswith("/")]
            if entry.member:
                if entry.member not in members:
                    raise SystemExit(
                        f"{entry.name}: declared member {entry.member!r} not in archive (have: {members})"
                    )
                pick = entry.member
            else:
                json_members = [n for n in members if n.endswith(".json")]
                if len(json_members) != 1:
                    raise SystemExit(
                        f"{entry.name}: archive has {len(json_members)} json members; "
                        f"specify `member:` in the manifest. Members: {members}"
                    )
                pick = json_members[0]
            with zf.open(pick) as src, dest.open("wb") as out:
                shutil.copyfileobj(src, out)
        return
    raise AssertionError(f"unhandled archive type {entry.archive!r}")  # pragma: no cover


def _cache_path(cache_dir: Path, entry: Entry) -> Path:
    # Cache by name + the last URL segment so a URL bump invalidates the cache
    # entry without colliding with the previous version's bytes on disk.
    assert entry.url is not None  # only called for download sources
    suffix = Path(entry.url.split("?")[0]).name
    return cache_dir / f"{entry.name}__{suffix}"


def _synthesise(entry: Entry) -> bytes:
    """Run the declared generator and return the NDJSON bytes."""
    # Imported lazily so download-only callers don't pay the import cost.
    from dev.synth import GENERATORS
    from dev.synth._writer import serialize

    assert entry.generator is not None and entry.seed is not None and entry.count is not None
    if entry.generator not in GENERATORS:
        raise SystemExit(
            f"{entry.name}: unknown generator {entry.generator!r}; available: {sorted(GENERATORS)}"
        )
    gen = GENERATORS[entry.generator]
    return serialize(gen(entry.seed, entry.count))


def _process_synthetic(
    entry: Entry, *, out_dir: Path, force: bool, pin: bool
) -> tuple[str, str | None]:
    """Materialise a synthetic entry. Returns (status, computed_sha256_if_pin)."""
    target_path = out_dir / entry.target

    # Fast-path skip: if the on-disk bytes already match the manifest sha,
    # don't re-run the generator (cheap, but spammy at scale).
    if not force and target_path.exists() and entry.sha256:
        existing = target_path.read_bytes()
        if _sha256_of(existing) == entry.sha256:
            return "skip", None

    payload = _synthesise(entry)
    actual_sha = _sha256_of(payload)
    if pin and not entry.sha256:
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_bytes(payload)
        return "pin", actual_sha
    if entry.sha256 and actual_sha != entry.sha256:
        raise SystemExit(
            f"sha256 mismatch for {entry.name} (synthetic): manifest says {entry.sha256}, "
            f"got {actual_sha}.\n  This means the generator output changed since the pin "
            f"was computed — either a generator bug, or an intentional update that needs "
            f"a fresh `--pin` run + commit."
        )
    if not entry.sha256:
        raise SystemExit(
            f"{entry.name}: no sha256 in manifest. Run with --pin to record the current bytes."
        )
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_bytes(payload)
    return "fetch", None


def _process_download(
    entry: Entry, *, out_dir: Path, cache_dir: Path, force: bool, pin: bool
) -> tuple[str, str | None]:
    """Returns (status, computed_sha256_if_pin_else_None)."""
    target_path = out_dir / entry.target
    cache_path = _cache_path(cache_dir, entry)
    cache_dir.mkdir(parents=True, exist_ok=True)

    if not force and target_path.exists() and entry.sha256 and cache_path.exists():
        cached = cache_path.read_bytes()
        if _sha256_of(cached) == entry.sha256:
            return "skip", None

    if not force and cache_path.exists():
        archive_bytes = cache_path.read_bytes()
    else:
        assert entry.url is not None
        archive_bytes = _download(entry.url)
        cache_path.write_bytes(archive_bytes)

    actual_sha = _sha256_of(archive_bytes)
    if pin and not entry.sha256:
        # Defer write-back to the caller — we mutate the manifest once at the
        # end so partial failures don't leave half-pinned manifests.
        _extract(entry, archive_bytes, target_path)
        return "pin", actual_sha
    if entry.sha256 and actual_sha != entry.sha256:
        raise SystemExit(
            f"sha256 mismatch for {entry.name}: manifest says {entry.sha256}, got {actual_sha}.\n"
            f"  Download saved at {cache_path} for inspection.\n"
            f"  If the upstream URL legitimately changed, bump the URL pin and re-run with --pin."
        )
    if not entry.sha256:
        raise SystemExit(
            f"{entry.name}: no sha256 in manifest. Run with --pin to record the current bytes."
        )
    _extract(entry, archive_bytes, target_path)
    return "fetch", None


def _process_entry(
    entry: Entry, *, out_dir: Path, cache_dir: Path, force: bool, pin: bool
) -> tuple[str, str | None]:
    if entry.source == "synthetic":
        return _process_synthetic(entry, out_dir=out_dir, force=force, pin=pin)
    return _process_download(entry, out_dir=out_dir, cache_dir=cache_dir, force=force, pin=pin)


# Targeted line-edit regexes for `_write_pinned_manifest`. PyYAML's safe_dump
# round-trip strips comments, section dividers, and literal-block descriptions,
# so we instead locate each entry's `sha256:` line by name and rewrite that line
# only — leaving every other byte verbatim.
_NAME_LINE_RE = re.compile(r"^(?P<indent>\s*)-\s+name:\s*(?P<name>\S+?)\s*$")
_SHA_LINE_RE = re.compile(r"^(?P<indent>\s*)sha256:.*$")


def _write_pinned_manifest(
    manifest_path: Path, raw_manifest: dict[str, Any], pins: dict[str, str]
) -> None:
    """Write back computed sha256 pins without disturbing the rest of the manifest.

    Walks the file line-by-line, locates the `- name: <pinned>` line for each
    entry to pin, then replaces the first deeper-indented `sha256:` line in that
    block. Every other line — comments, section dividers, literal-block
    descriptions, field ordering — is preserved verbatim.

    The convention documented in `e2e/datasets.yml` is that newly added entries
    include an empty `sha256:` line; if that line is absent for a pinned entry
    we error out rather than guessing where to insert it.
    """
    if not pins:
        return

    lines = manifest_path.read_text(encoding="utf-8").splitlines(keepends=True)
    current_name: str | None = None
    current_indent_len = -1
    pinned: set[str] = set()
    out: list[str] = []

    for line in lines:
        nm = _NAME_LINE_RE.match(line)
        if nm:
            current_name = nm.group("name").strip("'\"")
            current_indent_len = len(nm.group("indent"))
            out.append(line)
            continue

        if current_name in pins and current_name not in pinned:
            sm = _SHA_LINE_RE.match(line)
            if sm and len(sm.group("indent")) > current_indent_len:
                out.append(f"{sm.group('indent')}sha256: {pins[current_name]}\n")
                pinned.add(current_name)
                continue

        out.append(line)

    missing = set(pins) - pinned
    if missing:
        raise SystemExit(
            f"pin write-back failed in {manifest_path}: could not locate a `sha256:` "
            f"line for {sorted(missing)}. Add an empty `sha256:` field to each "
            f"affected entry and re-run --pin."
        )

    manifest_path.write_text("".join(out), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    parser.add_argument(
        "--pin",
        action="store_true",
        help="Compute and write back sha256 for entries that don't have one.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-download / re-synthesise every entry even if a verified copy is on disk.",
    )
    parser.add_argument(
        "--only",
        action="append",
        default=[],
        metavar="NAME",
        help="Restrict to specific entries by name (may be passed multiple times).",
    )
    args = parser.parse_args(argv)

    if not args.manifest.exists():
        print(f"manifest not found: {args.manifest}", file=sys.stderr)
        return 2

    raw_manifest, entries = _load_manifest(args.manifest)
    if args.only:
        wanted = set(args.only)
        unknown = wanted - {e.name for e in entries}
        if unknown:
            print(f"unknown entries: {sorted(unknown)}", file=sys.stderr)
            return 2
        entries = [e for e in entries if e.name in wanted]

    pins: dict[str, str] = {}
    counts = {"skip": 0, "fetch": 0, "pin": 0}
    for entry in entries:
        status, computed = _process_entry(
            entry,
            out_dir=args.out_dir,
            cache_dir=args.cache_dir,
            force=args.force,
            pin=args.pin,
        )
        counts[status] += 1
        if status == "pin" and computed:
            pins[entry.name] = computed
        sha_display = entry.sha256 or computed or "<unknown>"
        print(f"  [{status:5s}] {entry.name}  sha256={sha_display[:12]}…  -> {entry.target}")

    if pins:
        _write_pinned_manifest(args.manifest, raw_manifest, pins)
        print(f"\nWrote {len(pins)} sha256 pin(s) back to {args.manifest}.")

    print(
        f"\ndone: {counts['fetch']} fetched, {counts['skip']} cached, "
        f"{counts['pin']} pinned, total={len(entries)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
