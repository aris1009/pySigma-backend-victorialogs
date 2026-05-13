"""
Caddy access-log pipeline for the VictoriaLogs backend.

Caddy v2 emits structured JSON access logs whose field shape differs from
the W3C / IIS-style identifiers Sigma's ``webserver`` category uses
(``cs-method``, ``cs-uri-query``, ``c-ip`` …). This pipeline maps those
neutral identifiers onto the Caddy JSON paths that land in VictoriaLogs
when the ``json`` access-log encoder writes directly to a VL
ingestion endpoint (or via a Vector / fluent-bit JSON pass-through).

Scope
-----

* Applies to rules with ``logsource.category == "webserver"`` *and* to
  ``product`` values that share the same neutral taxonomy
  (``apache``, ``nginx``, ``iis``, ``caddy``). Other web stacks already
  use these field names by convention.
* Only renames fields that have a documented Caddy JSON counterpart;
  unknown identifiers pass through so operators can spot unmapped fields
  directly in the emitted query.

Reference: Caddy v2 access log format
(https://caddyserver.com/docs/logging) — request metadata sits under
``request.*`` and response metadata at the top level.
"""

from __future__ import annotations

from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation

_CADDY_FIELD_MAPPING: dict[str | None, str | list[str]] = {
    # HTTP method.
    "cs-method": "request.method",
    "c-method": "request.method",
    "method": "request.method",
    "Method": "request.method",
    # URL components. Caddy stores the full URI on `request.uri`; Sigma's
    # `cs-uri-stem` / `cs-uri-query` distinction does not survive the JSON
    # encoder, so both collapse onto `request.uri`.
    "cs-uri": "request.uri",
    "cs-uri-stem": "request.uri",
    "cs-uri-query": "request.uri",
    "c-uri": "request.uri",
    "c-uri-query": "request.uri",
    "c-uri-extension": "request.uri",
    "r-uri": "request.uri",
    "uri": "request.uri",
    "url": "request.uri",
    # Host / virtual host.
    "cs-host": "request.host",
    "c-host": "request.host",
    "host": "request.host",
    "Host": "request.host",
    # Client identity.
    "c-ip": "request.remote_ip",
    "src_ip": "request.remote_ip",
    "ClientIP": "request.remote_ip",
    # Request headers Caddy nests under `request.headers.<Header-Name>`
    # (header values are arrays in the JSON encoder, but LogsQL field
    # selectors match values inside arrays the same way they match scalars).
    "cs-user-agent": "request.headers.User-Agent",
    "c-useragent": "request.headers.User-Agent",
    "useragent": "request.headers.User-Agent",
    "UserAgent": "request.headers.User-Agent",
    "User-Agent": "request.headers.User-Agent",
    "cs-referer": "request.headers.Referer",
    "Referer": "request.headers.Referer",
    "referer": "request.headers.Referer",
    "cs-cookie": "request.headers.Cookie",
    "Cookie": "request.headers.Cookie",
    # Protocol.
    "cs-version": "request.proto",
    "c-version": "request.proto",
    "proto": "request.proto",
    # Response.
    "sc-status": "status",
    "status_code": "status",
    "StatusCode": "status",
    "sc-bytes": "size",
    "ResponseSize": "size",
}

_FIELD_MAPPING_ID = "victorialogs_caddy_field_mapping"


def victorialogs_caddy() -> ProcessingPipeline:
    """Sigma webserver/web rules -> Caddy v2 JSON access-log shape."""
    return ProcessingPipeline(
        name="VictoriaLogs Caddy (v2 JSON access-log shape)",
        priority=20,
        allowed_backends=frozenset({"victorialogs"}),
        items=[
            ProcessingItem(
                identifier=_FIELD_MAPPING_ID,
                transformation=FieldMappingTransformation(dict(_CADDY_FIELD_MAPPING)),
                rule_conditions=[LogsourceCondition(category="webserver")],
            ),
        ],
    )
