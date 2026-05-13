"""
Entry-point smoke test.

pySigma discovers backends via the `sigma.backends` entry-point group
(declared in `pyproject.toml` as `[tool.poetry.plugins."sigma.backends"]`).
If the group, name, or target class drifts, downstream tooling — including
the `sigma` CLI and the SigmaHQ plugin directory — silently stops finding
the backend. This test pins all three and round-trips a trivial rule
through the entry-point-loaded class so a packaging regression fails CI
before it ships.
"""

from __future__ import annotations

from importlib.metadata import entry_points

from sigma.collection import SigmaCollection

from sigma.backends.victorialogs import VictoriaLogsBackend

ENTRY_POINT_GROUP = "sigma.backends"
ENTRY_POINT_NAME = "victorialogs"
ENTRY_POINT_TARGET = "sigma.backends.victorialogs:VictoriaLogsBackend"


def _victorialogs_entry_point():
    eps = entry_points(group=ENTRY_POINT_GROUP)
    matches = [e for e in eps if e.name == ENTRY_POINT_NAME]
    assert matches, (
        f"no `{ENTRY_POINT_NAME}` entry point found in group "
        f"`{ENTRY_POINT_GROUP}` — is the package installed (poetry install)?"
    )
    assert len(matches) == 1, f"duplicate entry points: {matches!r}"
    return matches[0]


def test_entry_point_registered():
    ep = _victorialogs_entry_point()
    assert ep.value == ENTRY_POINT_TARGET, (
        f"entry-point target drifted: expected {ENTRY_POINT_TARGET!r}, got {ep.value!r}"
    )


def test_entry_point_loads_to_backend_class():
    ep = _victorialogs_entry_point()
    cls = ep.load()
    assert cls is VictoriaLogsBackend, (
        "entry point resolved to a different class than the one imported "
        "via `from sigma.backends.victorialogs import VictoriaLogsBackend`"
    )


def test_entry_point_instantiates_and_converts():
    ep = _victorialogs_entry_point()
    backend = ep.load()()
    out = backend.convert(
        SigmaCollection.from_yaml(
            """
title: T
status: test
logsource:
    category: test
detection:
    sel:
        fieldA: valueA
    condition: sel
"""
        )
    )
    assert out == ['fieldA:="valueA"'], f"unexpected output via entry point: {out!r}"
