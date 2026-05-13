"""
Unit tests for the Caddy access-log pipeline.

The pipeline targets Caddy v2 JSON access-log shape (request.* sub-paths,
top-level status/size). Each test pins the **exact** LogsQL query so
field-mapping regressions surface explicitly.
"""

from __future__ import annotations

import pytest
from sigma.collection import SigmaCollection

from sigma.backends.victorialogs import VictoriaLogsBackend
from sigma.pipelines.victorialogs import pipelines, victorialogs_caddy
from sigma.pipelines.victorialogs.caddy import _CADDY_FIELD_MAPPING

# ---------------------------- pipeline metadata -----------------------------


def test_pipeline_metadata():
    p = victorialogs_caddy()
    assert p.name == "VictoriaLogs Caddy (v2 JSON access-log shape)"
    assert p.priority == 20
    assert p.allowed_backends == frozenset({"victorialogs"})
    assert len(p.items) > 0


def test_registered_in_pipelines_dict():
    assert pipelines["victorialogs_caddy"] is victorialogs_caddy


def test_registered_via_entry_point():
    from importlib.metadata import entry_points

    target = next(
        e for e in entry_points(group="sigma.pipelines") if e.name == "victorialogs"
    ).load()
    assert "victorialogs_caddy" in target


# ---------------------------- helpers -----------------------------


def _backend() -> VictoriaLogsBackend:
    return VictoriaLogsBackend(processing_pipeline=victorialogs_caddy())


def _convert(yaml: str) -> str:
    out = _backend().convert(SigmaCollection.from_yaml(yaml))
    assert isinstance(out, list) and len(out) == 1
    return out[0]


# ---------------------------- method / URI / host --------------------------


def test_method_and_uri():
    q = _convert(
        """
title: T
status: test
logsource:
    category: webserver
detection:
    sel:
        cs-method: POST
        cs-uri-stem: /login
    condition: sel
"""
    )
    assert q == 'request.method:="POST" AND request.uri:="/login"'


def test_uri_query_collapses_to_request_uri():
    q = _convert(
        """
title: T
status: test
logsource:
    category: webserver
detection:
    sel:
        cs-uri-query|contains: 'union select'
    condition: sel
"""
    )
    assert q == 'request.uri:"union select"'


def test_status_code_numeric():
    q = _convert(
        """
title: T
status: test
logsource:
    category: webserver
detection:
    sel:
        sc-status: 401
    condition: sel
"""
    )
    assert q == "status:=401"


def test_user_agent_under_request_headers():
    q = _convert(
        """
title: T
status: test
logsource:
    category: webserver
detection:
    sel:
        cs-user-agent|contains: sqlmap
    condition: sel
"""
    )
    assert q == '"request.headers.User-Agent":"sqlmap"'


def test_referer_and_cookie():
    q = _convert(
        """
title: T
status: test
logsource:
    category: webserver
detection:
    sel:
        Referer|contains: evil.com
        Cookie|contains: session=
    condition: sel
"""
    )
    assert q == 'request.headers.Referer:"evil.com" AND request.headers.Cookie:"session="'


def test_client_ip_mapping():
    q = _convert(
        """
title: T
status: test
logsource:
    category: webserver
detection:
    sel:
        c-ip: 192.0.2.5
    condition: sel
"""
    )
    assert q == 'request.remote_ip:="192.0.2.5"'


# ---------------------------- gating ---------------------------------------


def test_non_webserver_rule_unaffected():
    """Rules outside category=webserver must NOT pick up Caddy renames."""
    q = _convert(
        """
title: T
status: test
logsource:
    product: linux
    category: process_creation
detection:
    sel:
        cs-method: GET
    condition: sel
"""
    )
    assert q == '"cs-method":="GET"'
    assert "request.method" not in q


# ---------------------------- mapping invariants ---------------------------


def test_all_targets_under_request_or_top_level():
    """Every Caddy target is either `request.*` or one of the top-level
    response keys (`status`, `size`)."""
    allowed_top = {"status", "size"}
    for sigma_field, target in _CADDY_FIELD_MAPPING.items():
        assert isinstance(target, str)
        assert target.startswith("request.") or target in allowed_top, (
            f"{sigma_field} -> {target!r}: not a Caddy v2 field path"
        )


@pytest.mark.parametrize(
    "alias",
    ["cs-uri", "cs-uri-stem", "cs-uri-query", "c-uri", "c-uri-query", "uri", "url"],
)
def test_uri_aliases_all_collapse(alias: str):
    assert _CADDY_FIELD_MAPPING[alias] == "request.uri"


@pytest.mark.parametrize("alias", ["cs-method", "c-method", "method", "Method"])
def test_method_aliases_all_collapse(alias: str):
    assert _CADDY_FIELD_MAPPING[alias] == "request.method"
