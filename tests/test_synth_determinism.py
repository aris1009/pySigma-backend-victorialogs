"""Determinism gate for the synthetic dataset generator framework.

Each generator with ``seed=42`` must produce byte-identical output across
two consecutive runs. Catches accidental nondeterminism that would imply
an unpinned source of values — i.e. a generator reaching outside the
trust-root vocab module (``dev/synth/_vocab.py``) for an identifier.

This is one half of the leak guarantee for ``dev/synth/``: the other half
is owner review of the vocab module itself, gated by ``.github/CODEOWNERS``.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from dev.synth import GENERATORS  # noqa: E402
from dev.synth._writer import serialize  # noqa: E402

_SEED = 42
_COUNT = 200


@pytest.mark.parametrize("name", sorted(GENERATORS))
def test_generator_byte_identical_across_runs(name: str):
    gen = GENERATORS[name]
    a = serialize(gen(_SEED, _COUNT))
    b = serialize(gen(_SEED, _COUNT))
    assert a == b, (
        f"{name}: serialized output differs across two seed=42 runs — "
        "a generator is reading from an unpinned source (env var, wall "
        "clock, file outside dev/synth/, or third-party faker)."
    )


@pytest.mark.parametrize("name", sorted(GENERATORS))
def test_generator_seed_actually_varies_output(name: str):
    """Sanity: different seeds must yield different bytes, otherwise the
    'determinism on seed=42' test is trivially satisfied by a constant
    generator."""
    gen = GENERATORS[name]
    a = serialize(gen(_SEED, _COUNT))
    c = serialize(gen(_SEED + 1, _COUNT))
    assert a != c, f"{name}: output is independent of seed"
