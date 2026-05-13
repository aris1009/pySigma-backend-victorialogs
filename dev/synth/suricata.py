"""Synthetic Suricata EVE event generators.

Two generators are exposed:

* ``generate`` (registered as ``suricata``) — mixed traffic, ~60% benign
  flows/dns/http/tls/alert events and ~40% attack-shaped events that
  plant verbatim payloads public SigmaHQ ``logsource: { category: dns
  | proxy }`` rules look for.
* ``generate_benign`` (registered as ``suricata_benign``) — benign-only
  traffic. Used for negative expectations: rules that fire on the attack
  dataset MUST NOT fire here.

Output shape: top-level Suricata EVE JSON, one event per line. Fields
match what the ``victorialogs_suricata`` pipeline targets — top-level
``src_ip`` / ``dest_ip`` / ``dest_port``, nested ``http.*`` / ``dns.*``
/ ``tls.*``.

Event types covered: ``flow``, ``http``, ``dns``, ``tls``, ``alert``.

A public PCAP-derived EVE sample was considered as a second source.
Because Suricata's upstream test corpora ship under a mix of GPLv2 / BSD
licences that aren't always clear at the file level, this module ships
synthetic only.

All identifying values come from ``_vocab``; no real domains, IPs, or
SIDs are emitted — every value is from RFC-reserved or documentation
ranges.
"""

from __future__ import annotations

import random
import string
from collections.abc import Iterator
from typing import Any

from . import _vocab
from ._time import stamp

_ALERT_SIGS = (
    {
        "signature_id": 2_010_935,
        "signature": "ET SCAN Possible Nmap User-Agent Observed",
        "category": "Web Application Attack",
        "severity": 2,
    },
    {
        "signature_id": 2_023_883,
        "signature": "ET POLICY Possible Kali Linux hostname in DHCP Request Packet",
        "category": "Potential Corporate Privacy Violation",
        "severity": 2,
    },
    {
        "signature_id": 2_021_595,
        "signature": "ET TROJAN Possible Malicious Macro DL EXE Aug 23 2015",
        "category": "A Network Trojan was detected",
        "severity": 1,
    },
)

_TLS_VERSIONS = ("TLS 1.2", "TLS 1.3")

# ---------------------- attack payload pools (verbatim selectors) -----------
#
# Each branch's payload contains a substring the named SigmaHQ rule's
# selector looks for. Branch -> covered rule:
#
#   dns_telegram        -> rules/network/dns/net_dns_susp_telegram_api.yml
#   dns_b64_exfil       -> rules/network/dns/net_dns_susp_b64_queries.yml
#   dns_cobalt          -> rules/network/dns/net_dns_mal_cobaltstrike.yml
#   dns_xmr_mining      -> rules/network/dns/net_dns_pua_cryptocoin_mining_xmr.yml
#   dns_wannacry        -> rules/network/dns/net_dns_wannacry_killswitch_domain.yml
#   dns_oast            -> rules/network/dns/net_dns_external_service_interaction_domains.yml
#   http_pwndrop        -> rules/web/proxy_generic/proxy_pwndrop.yml
#   http_babyshark      -> rules/web/proxy_generic/proxy_hktl_baby_shark_default_agent_url.yml

_TELEGRAM_QUERY = "api.telegram.org"

_COBALT_QUERIES = (
    "aaa.stage.example.com",
    "post.1.example.org",
    "host.stage.123456.example.test",
)

_XMR_QUERIES = (
    "pool.minexmr.com",
    "fr.minexmr.com",
    "xmr-eu1.nanopool.org",
    "xmr.2miners.com",
)

_WANNACRY_QUERIES = (
    "ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com",
    "ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.test",
    "ayylmaotjhsstasdfasdfasdfasdfasdfasdfasdf.com",
)

_OAST_SUFFIXES = (
    ".burpcollaborator.net",
    ".oast.fun",
    ".oast.live",
    ".interact.sh",
    ".dnslog.cn",
)

_PWNDROP_PATHS = (
    "/pwndrop/share/abc",
    "/pwndrop/login",
    "/pwndrop/api/file",
)

_BABYSHARK_PATHS = (
    "/?momyshark?key=AAAA",
    "/index.php?momyshark?key=BBBB",
    "/cgi-bin/redir?momyshark?key=CCCC",
)


def _b64_exfil_query(rng: random.Random) -> str:
    label = "".join(rng.choices(string.ascii_letters + string.digits, k=44)) + "=="
    return f"{label}.{_vocab.EXFIL_DOMAIN_SUFFIX}"


def _flow(rng: random.Random, offset: int) -> dict[str, Any]:
    return {
        "_time": stamp(offset),
        "event_type": "flow",
        "src_ip": _vocab.random_rfc5737_v4(rng),
        "src_port": rng.randint(1024, 65_535),
        "dest_ip": _vocab.random_rfc5737_v4(rng),
        "dest_port": rng.choice((80, 443, 8080, 8443, 53)),
        "proto": rng.choice(("TCP", "UDP")),
        "flow": {
            "pkts_toserver": rng.randint(1, 100),
            "pkts_toclient": rng.randint(1, 100),
            "bytes_toserver": rng.randint(64, 100_000),
            "bytes_toclient": rng.randint(64, 100_000),
            "state": "established",
        },
    }


def _http_benign(rng: random.Random, offset: int) -> dict[str, Any]:
    return {
        "_time": stamp(offset),
        "event_type": "http",
        "src_ip": _vocab.random_rfc5737_v4(rng),
        "src_port": rng.randint(1024, 65_535),
        "dest_ip": _vocab.random_rfc5737_v4(rng),
        "dest_port": rng.choice((80, 8080)),
        "proto": "TCP",
        "http": {
            "hostname": rng.choice(_vocab.BENIGN_DOMAINS),
            "url": rng.choice(("/", "/index.html", "/api/v1/users", "/login")),
            "http_user_agent": _vocab.random_user_agent(rng, suspicious=False),
            "http_method": rng.choice(("GET", "POST")),
            "protocol": "HTTP/1.1",
            "status": rng.choice((200, 200, 200, 301, 404, 500)),
            "length": rng.randint(100, 50_000),
        },
    }


def _http_attack(rng: random.Random, offset: int, *, branch: str) -> dict[str, Any]:
    url = rng.choice(_PWNDROP_PATHS) if branch == "http_pwndrop" else rng.choice(_BABYSHARK_PATHS)
    return {
        "_time": stamp(offset),
        "event_type": "http",
        "src_ip": _vocab.random_rfc5737_v4(rng),
        "src_port": rng.randint(1024, 65_535),
        "dest_ip": _vocab.random_rfc5737_v4(rng),
        "dest_port": rng.choice((80, 8080)),
        "proto": "TCP",
        "http": {
            "hostname": rng.choice(_vocab.BENIGN_DOMAINS),
            "url": url,
            "http_user_agent": _vocab.random_user_agent(rng, suspicious=False),
            "http_method": "GET",
            "protocol": "HTTP/1.1",
            "status": rng.choice((200, 302, 404)),
            "length": rng.randint(100, 50_000),
        },
    }


def _dns_benign(rng: random.Random, offset: int) -> dict[str, Any]:
    return {
        "_time": stamp(offset),
        "event_type": "dns",
        "src_ip": _vocab.random_rfc5737_v4(rng),
        "src_port": rng.randint(1024, 65_535),
        "dest_ip": _vocab.random_rfc5737_v4(rng),
        "dest_port": 53,
        "proto": "UDP",
        "dns": {
            "type": rng.choice(("query", "answer")),
            "id": rng.randint(0, 65_535),
            "rrname": rng.choice(_vocab.BENIGN_DOMAINS),
            "rrtype": rng.choice(("A", "AAAA", "TXT", "CNAME")),
        },
    }


def _dns_attack(rng: random.Random, offset: int, *, branch: str) -> dict[str, Any]:
    if branch == "dns_telegram":
        rrname = _TELEGRAM_QUERY
    elif branch == "dns_b64_exfil":
        rrname = _b64_exfil_query(rng)
    elif branch == "dns_cobalt":
        rrname = rng.choice(_COBALT_QUERIES)
    elif branch == "dns_xmr_mining":
        rrname = rng.choice(_XMR_QUERIES)
    elif branch == "dns_wannacry":
        rrname = rng.choice(_WANNACRY_QUERIES)
    else:  # dns_oast
        rrname = "".join(rng.choices(string.ascii_lowercase, k=10)) + rng.choice(_OAST_SUFFIXES)
    return {
        "_time": stamp(offset),
        "event_type": "dns",
        "src_ip": _vocab.random_rfc5737_v4(rng),
        "src_port": rng.randint(1024, 65_535),
        "dest_ip": _vocab.random_rfc5737_v4(rng),
        "dest_port": 53,
        "proto": "UDP",
        "dns": {
            "type": "query",
            "id": rng.randint(0, 65_535),
            "rrname": rrname,
            "rrtype": "A",
        },
    }


def _tls(rng: random.Random, offset: int) -> dict[str, Any]:
    sni = rng.choice(_vocab.BENIGN_DOMAINS)
    return {
        "_time": stamp(offset),
        "event_type": "tls",
        "src_ip": _vocab.random_rfc5737_v4(rng),
        "src_port": rng.randint(1024, 65_535),
        "dest_ip": _vocab.random_rfc5737_v4(rng),
        "dest_port": 443,
        "proto": "TCP",
        "tls": {
            "sni": sni,
            "subject": f"CN={sni}",
            "issuerdn": "CN=Example CA, O=Example, C=XX",
            "version": rng.choice(_TLS_VERSIONS),
            "ja3": {"hash": "0" * 32},
        },
    }


def _alert(rng: random.Random, offset: int) -> dict[str, Any]:
    sig = rng.choice(_ALERT_SIGS)
    return {
        "_time": stamp(offset),
        "event_type": "alert",
        "src_ip": _vocab.random_rfc5737_v4(rng),
        "src_port": rng.randint(1024, 65_535),
        "dest_ip": _vocab.random_rfc5737_v4(rng),
        "dest_port": rng.choice((80, 443)),
        "proto": "TCP",
        "alert": dict(sig),
    }


_DNS_ATTACK_BRANCHES = (
    "dns_telegram",
    "dns_b64_exfil",
    "dns_cobalt",
    "dns_xmr_mining",
    "dns_wannacry",
    "dns_oast",
)
_HTTP_ATTACK_BRANCHES = ("http_pwndrop", "http_babyshark")


def _benign_event(rng: random.Random, offset: int) -> dict[str, Any]:
    roll = rng.random()
    if roll < 0.35:
        return _flow(rng, offset)
    elif roll < 0.60:
        return _http_benign(rng, offset)
    elif roll < 0.80:
        return _dns_benign(rng, offset)
    elif roll < 0.92:
        return _tls(rng, offset)
    else:
        return _alert(rng, offset)


def _attack_event(rng: random.Random, offset: int) -> dict[str, Any]:
    if rng.random() < 0.7:
        branch = rng.choice(_DNS_ATTACK_BRANCHES)
        return _dns_attack(rng, offset, branch=branch)
    branch = rng.choice(_HTTP_ATTACK_BRANCHES)
    return _http_attack(rng, offset, branch=branch)


def generate(seed: int, count: int) -> Iterator[dict[str, Any]]:
    """Yield ``count`` synthetic Suricata EVE events seeded by ``seed``.

    ~40% of events are attack-shaped, distributed across the DNS/HTTP
    branches above so a 5000-event run plants ample positives for each
    rule under test.
    """
    rng = random.Random(seed)
    for i in range(count):
        attack = rng.random() < 0.40
        yield _attack_event(rng, i) if attack else _benign_event(rng, i)


def generate_benign(seed: int, count: int) -> Iterator[dict[str, Any]]:
    """Yield ``count`` benign-only Suricata EVE events.

    Used for negative e2e expectations — network/dns/proxy Sigma rules
    that fire on the attack-mix dataset MUST NOT fire here.
    """
    rng = random.Random(seed)
    for i in range(count):
        yield _benign_event(rng, i)
