"""
Suricata EVE pipeline for the VictoriaLogs backend.

Suricata's EVE JSON output is the canonical structured representation of
IDS / network telemetry on most Linux deployments. Most of Sigma's
``network`` taxonomy already aligns with EVE field names (``src_ip``,
``src_port``, ``proto`` …) — the only field-naming gap is the
destination-side aliases:

* Sigma rules write ``dst_ip`` / ``dst_port`` / ``DestinationIp`` /
  ``DestinationPort``;
* EVE writes ``dest_ip`` / ``dest_port``.

This pipeline closes that gap and adds the small set of EVE sub-document
remaps for HTTP / DNS / TLS that Sigma's ``proxy`` and ``dns`` categories
reach into.

Scope
-----

* Applies to rules with ``logsource.category in {network, dns, firewall,
  proxy}`` *or* ``logsource.product in {zeek, suricata}``.
* Renames only fields with a clear EVE counterpart. Anything not on the
  list (e.g. Sigma's ``Initiated`` boolean) passes through unchanged so
  the gap is visible in the emitted query.

Reference: Suricata EVE schema
(https://docs.suricata.io/en/latest/output/eve/eve-json-format.html).
"""

from __future__ import annotations

from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation

_SURICATA_FIELD_MAPPING: dict[str | None, str | list[str]] = {
    # Destination tuple — Sigma writes `dst_*`, EVE writes `dest_*`.
    "dst_ip": "dest_ip",
    "DestinationIp": "dest_ip",
    "DestinationHostname": "dest_ip",
    "dst_port": "dest_port",
    "DestinationPort": "dest_port",
    # Source tuple — names already match, but cover the title-cased
    # variants Sigma occasionally uses.
    "SourceIp": "src_ip",
    "SourceHostname": "src_ip",
    "SourcePort": "src_port",
    # HTTP — Sigma `proxy` category fields land under `http.*` in EVE.
    "cs-host": "http.hostname",
    "host": "http.hostname",
    "cs-uri": "http.url",
    "cs-uri-stem": "http.url",
    "cs-uri-query": "http.url",
    "c-uri": "http.url",
    "uri": "http.url",
    "cs-method": "http.http_method",
    "method": "http.http_method",
    "cs-user-agent": "http.http_user_agent",
    "useragent": "http.http_user_agent",
    "UserAgent": "http.http_user_agent",
    "User-Agent": "http.http_user_agent",
    "sc-status": "http.status",
    "status_code": "http.status",
    # DNS — Sigma `dns` rules query against the queried name.
    "QueryName": "dns.rrname",
    "query": "dns.rrname",
    "QueryType": "dns.rrtype",
    "Answer": "dns.answers.rdata",
    # TLS — used by some `proxy` and threat-hunting rules.
    "TlsServerName": "tls.sni",
    "ServerName": "tls.sni",
    "Subject": "tls.subject",
    "Issuer": "tls.issuerdn",
}

_FIELD_MAPPING_ID = "victorialogs_suricata_field_mapping"


def victorialogs_suricata() -> ProcessingPipeline:
    """Sigma network/dns/proxy rules -> Suricata EVE JSON shape."""
    return ProcessingPipeline(
        name="VictoriaLogs Suricata EVE (network/dns/proxy/firewall)",
        priority=20,
        allowed_backends=frozenset({"victorialogs"}),
        items=[
            ProcessingItem(
                identifier=_FIELD_MAPPING_ID,
                transformation=FieldMappingTransformation(dict(_SURICATA_FIELD_MAPPING)),
                rule_conditions=[
                    LogsourceCondition(category="network"),
                    LogsourceCondition(category="dns"),
                    LogsourceCondition(category="firewall"),
                    LogsourceCondition(category="proxy"),
                    LogsourceCondition(product="zeek"),
                    LogsourceCondition(product="suricata"),
                ],
                rule_condition_linking=any,
            ),
        ],
    )
