"""
Unit tests for the Suricata EVE pipeline.
"""

from __future__ import annotations

import pytest
from sigma.collection import SigmaCollection

from sigma.backends.victorialogs import VictoriaLogsBackend
from sigma.pipelines.victorialogs import pipelines, victorialogs_suricata
from sigma.pipelines.victorialogs.suricata import _SURICATA_FIELD_MAPPING

# ---------------------------- pipeline metadata -----------------------------


def test_pipeline_metadata():
    p = victorialogs_suricata()
    assert p.name == "VictoriaLogs Suricata EVE (network/dns/proxy/firewall)"
    assert p.priority == 20
    assert p.allowed_backends == frozenset({"victorialogs"})


def test_registered_in_pipelines_dict():
    assert pipelines["victorialogs_suricata"] is victorialogs_suricata


def test_registered_via_entry_point():
    from importlib.metadata import entry_points

    target = next(
        e for e in entry_points(group="sigma.pipelines") if e.name == "victorialogs"
    ).load()
    assert "victorialogs_suricata" in target


# ---------------------------- helpers -----------------------------


def _backend() -> VictoriaLogsBackend:
    return VictoriaLogsBackend(processing_pipeline=victorialogs_suricata())


def _convert(yaml: str) -> str:
    out = _backend().convert(SigmaCollection.from_yaml(yaml))
    assert isinstance(out, list) and len(out) == 1
    return out[0]


# ---------------------------- network: dst_ip / dst_port -------------------


def test_network_dst_renames():
    q = _convert(
        """
title: T
status: test
logsource:
    category: network
detection:
    sel:
        dst_ip: 10.0.0.1
        dst_port: 4444
    condition: sel
"""
    )
    assert q == 'dest_ip:="10.0.0.1" AND dest_port:=4444'


def test_network_titlecased_destination_renames():
    q = _convert(
        """
title: T
status: test
logsource:
    category: network
detection:
    sel:
        DestinationIp: 10.0.0.1
        DestinationPort: 22
    condition: sel
"""
    )
    assert q == 'dest_ip:="10.0.0.1" AND dest_port:=22'


def test_source_aliases():
    q = _convert(
        """
title: T
status: test
logsource:
    category: network
detection:
    sel:
        SourceIp: 192.0.2.1
        SourcePort: 443
    condition: sel
"""
    )
    assert q == 'src_ip:="192.0.2.1" AND src_port:=443'


# ---------------------------- DNS / proxy / TLS ---------------------------


def test_dns_query_rename():
    q = _convert(
        """
title: T
status: test
logsource:
    category: dns
detection:
    sel:
        QueryName|endswith: .onion
    condition: sel
"""
    )
    assert q == 'dns.rrname:~"\\\\.onion$"'


def test_proxy_http_url_and_method():
    q = _convert(
        """
title: T
status: test
logsource:
    category: proxy
detection:
    sel:
        cs-method: GET
        cs-uri|contains: /admin
        cs-user-agent|contains: curl
    condition: sel
"""
    )
    assert q == ('http.http_method:="GET" AND http.url:"/admin" AND http.http_user_agent:"curl"')


def test_tls_sni_rename():
    q = _convert(
        """
title: T
status: test
logsource:
    category: network
    product: zeek
detection:
    sel:
        TlsServerName|endswith: .badtld
    condition: sel
"""
    )
    assert q == 'tls.sni:~"\\\\.badtld$"'


# ---------------------------- gating --------------------------------------


def test_non_network_rule_unaffected():
    """Linux process_creation rules should not pick up EVE renames even if
    a field name happens to overlap (e.g. `host`)."""
    q = _convert(
        """
title: T
status: test
logsource:
    product: linux
    category: process_creation
detection:
    sel:
        host: web01
    condition: sel
"""
    )
    assert q == 'host:="web01"'


def test_firewall_category_routed():
    q = _convert(
        """
title: T
status: test
logsource:
    category: firewall
detection:
    sel:
        dst_port: 22
    condition: sel
"""
    )
    assert q == "dest_port:=22"


def test_zeek_product_routed():
    q = _convert(
        """
title: T
status: test
logsource:
    product: zeek
detection:
    sel:
        dst_port: 443
    condition: sel
"""
    )
    assert q == "dest_port:=443"


# ---------------------------- mapping invariants --------------------------


@pytest.mark.parametrize(
    "sigma_field,target",
    [
        ("dst_ip", "dest_ip"),
        ("DestinationIp", "dest_ip"),
        ("dst_port", "dest_port"),
        ("DestinationPort", "dest_port"),
        ("QueryName", "dns.rrname"),
        ("TlsServerName", "tls.sni"),
        ("cs-method", "http.http_method"),
        ("cs-user-agent", "http.http_user_agent"),
    ],
)
def test_mapping_table_pinned(sigma_field: str, target: str):
    assert _SURICATA_FIELD_MAPPING[sigma_field] == target
