"""Synth CLI: ``python -m dev.synth <generator> --seed N --count N --out path``.

Used standalone to materialise a single dataset, and re-used by the
fetcher (``dev/fetch_datasets.py``) when an entry in ``e2e/datasets.yml``
declares ``source: synthetic``.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import GENERATORS
from ._writer import write_ndjson


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m dev.synth", description=__doc__)
    parser.add_argument("generator", choices=sorted(GENERATORS), help="Generator name.")
    parser.add_argument("--seed", type=int, required=True, help="Deterministic seed.")
    parser.add_argument("--count", type=int, required=True, help="Number of events.")
    parser.add_argument(
        "--out",
        type=Path,
        required=True,
        help="Output NDJSON path (parent dirs are created).",
    )
    args = parser.parse_args(argv)

    if args.count < 1:
        print(f"--count must be >= 1, got {args.count}", file=sys.stderr)
        return 2

    gen = GENERATORS[args.generator]
    lines, sha = write_ndjson(args.out, gen(args.seed, args.count))
    print(f"wrote {lines} events to {args.out}  sha256={sha}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
