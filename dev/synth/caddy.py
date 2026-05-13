"""Synthetic Caddy v2 access-log generators.

Two generators are exposed:

* ``generate`` (registered as ``caddy``) — mixed traffic, ~60% benign and
  ~40% attack. Each attack branch plants verbatim payloads that public
  SigmaHQ ``logsource: webserver`` rules look for, so the e2e harness has
  reliable positive expectations to assert against.
* ``generate_benign`` (registered as ``caddy_benign``) — benign-only
  traffic. Used for negative expectations: rules that fire on the attack
  dataset MUST NOT fire here.

Output shape matches the ``victorialogs_caddy`` pipeline mapping
(``request.method`` / ``request.uri`` / ``request.headers.User-Agent`` /
``request.remote_ip`` / ``status`` / ``size`` / ``logger``) so converted
Sigma rules query this NDJSON directly via ``/insert/jsonline`` — no
Vector remap.

All values come from ``_vocab`` (RFC 5737 client IPs, ``.example/.test``
hostnames). No real public IPs, hosts, or contributor identifiers.
"""

from __future__ import annotations

import random
from collections.abc import Iterator
from typing import Any

from . import _vocab
from ._time import stamp

_BENIGN_PATHS = (
    "/",
    "/index.html",
    "/login",
    "/api/v1/health",
    "/api/v1/users",
    "/static/app.js",
    "/static/css/app.css",
    "/favicon.ico",
)

_BENIGN_METHODS = ("GET", "POST", "PUT", "DELETE", "OPTIONS")
_STATUSES_OK = (200, 200, 200, 200, 301, 302, 304, 401, 403, 404)
_STATUSES_ERR = (500, 502, 503, 504)

# ----- attack payload pools (each plants a verbatim Sigma rule selector) -----

_PATH_TRAVERSAL_URIS = (
    "/../../../../etc/passwd",
    "/index.php?file=../../../etc/passwd",
    "/cgi-bin/x?p=../../../../windows/win.ini",
    "/img?src=..%252f..%252f..%252fetc%252fpasswd",
)

_SOURCE_DISCLOSURE_URIS = (
    "/.git/config",
    "/.git/HEAD",
    "/.env",
    "/.aws/credentials",
)

_JNDI_URIS = (
    "/?x=/Basic/Command/Base64/Y3VybCBhdHRhY2tlcg==",
    "/?p=/Basic/ReverseShell/198.51.100.5/4444",
    "/?j=/TomcatBypass/Command/cmd",
    "/?j=/Deserialization/URLDNS/dnslog",
)

_WIN_PATH_URIS = (
    "/?file==C:/Users/admin/secret.txt",
    "/?p==C:/Windows/System32/config/SAM",
    "/?path==C:/Program%20Files/notes.txt",
    "/?f==C%3A%5CUsers%5Cadmin%5Csecret",
)

_XSS_URIS = (
    "/search?q==<script>alert(1)</script>",
    "/?q==%3Cscript%3Ealert(1)%3C/script%3E",
    "/?q=<svg onload=alert(1)>",
    "/?q=javascript:alert(1)",
)

_SQLI_URIS = (
    "/?id=1 UNION SELECT 1,2,3",
    "/?id=1%20UNION%20SELECT%201",
    "/?id=1 or 1=1#",
    "/?q=select database()",
)

_SSTI_URIS = (
    "/render?tpl={{7*7}}",
    "/r?t==%7B%7B7%2A7%7D%7D",
    "/render?tpl=${7*7}",
    "/render?tpl=<%=7*7%>",
)

_WIN_WEBSHELL_URIS = (
    "/cgi-bin/x?cmd=whoami",
    "/cgi-bin/x?cmd=cmd%20/c%20dir",
    "/cgi-bin/x?cmd=powershell%20-c%20Get-Process",
    "/cgi-bin/x?cmd=tasklist%20/v",
    "/cgi-bin/x?cmd=ipconfig",
)

_IIS_SHORTNAME_URIS = (
    "/old~1files/dataa.aspx",
    "/legacy~1content/indexa.aspx",
    "/archive~1/reporta.aspx",
)

_F5_BASH_URIS = (
    "/mgmt/tm/util/bash",
    "/api/mgmt/tm/util/bash",
)

# Each attack branch is a tuple of (method, uri-pool, status-pool). status
# is constrained so the rule's filter clauses (e.g. NOT 404) still match.
_ATTACK_BRANCHES: tuple[tuple[str, str, tuple[str, ...], tuple[int, ...]], ...] = (
    ("path_traversal", "GET", _PATH_TRAVERSAL_URIS, (200, 403, 404)),
    ("source_disclosure", "GET", _SOURCE_DISCLOSURE_URIS, (200, 403, 404)),
    ("jndi", "GET", _JNDI_URIS, (200, 403)),
    ("win_path", "GET", _WIN_PATH_URIS, (200, 500)),
    ("xss", "GET", _XSS_URIS, (200, 500)),
    ("sqli", "GET", _SQLI_URIS, (200, 500)),
    ("ssti", "GET", _SSTI_URIS, (200, 500)),
    ("win_webshell", "GET", _WIN_WEBSHELL_URIS, (200, 500)),
    ("iis_shortname", "GET", _IIS_SHORTNAME_URIS, (200, 301)),
    ("f5_bash", "POST", _F5_BASH_URIS, (200, 401)),
    ("recon_ua", "GET", _BENIGN_PATHS, _STATUSES_OK),
)


def _benign_request(rng: random.Random) -> dict[str, Any]:
    return {
        "method": rng.choice(_BENIGN_METHODS),
        "uri": rng.choice(_BENIGN_PATHS),
        "host": _vocab.random_hostname(rng, prefix="www"),
        "proto": "HTTP/2.0" if rng.random() < 0.7 else "HTTP/1.1",
        "remote_ip": _vocab.random_rfc5737_v4(rng),
        "headers": {
            "User-Agent": [_vocab.random_user_agent(rng, suspicious=False)],
            "Accept": ["*/*"],
        },
    }


def _attack_request(rng: random.Random) -> tuple[dict[str, Any], int]:
    name, method, uris, statuses = rng.choice(_ATTACK_BRANCHES)
    if name == "recon_ua":
        ua = rng.choice(_vocab.RECON_USER_AGENTS)
    else:
        ua = _vocab.random_user_agent(rng, suspicious=False)
    request = {
        "method": method,
        "uri": rng.choice(uris),
        "host": _vocab.random_hostname(rng, prefix="www"),
        "proto": "HTTP/1.1",
        "remote_ip": _vocab.random_rfc5737_v4(rng),
        "headers": {
            "User-Agent": [ua],
            "Accept": ["*/*"],
        },
    }
    return request, rng.choice(statuses)


def _event(rng: random.Random, offset: int, *, attack: bool) -> dict[str, Any]:
    if attack:
        request, status = _attack_request(rng)
    else:
        request = _benign_request(rng)
        status = rng.choice(_STATUSES_ERR) if rng.random() < 0.05 else rng.choice(_STATUSES_OK)
    return {
        "_time": stamp(offset),
        "request": request,
        "status": status,
        "size": rng.randint(200, 50_000),
        "duration": round(rng.uniform(0.001, 1.5), 6),
        "logger": "http.log.access",
    }


def generate(seed: int, count: int) -> Iterator[dict[str, Any]]:
    """Yield ``count`` Caddy v2 access-log events seeded by ``seed``.

    ~40% of events are attack-shaped, distributed across the branches in
    ``_ATTACK_BRANCHES`` so a 5000-event run plants ~180 of each pattern.
    """
    rng = random.Random(seed)
    for i in range(count):
        attack = rng.random() < 0.40
        yield _event(rng, i, attack=attack)


def generate_benign(seed: int, count: int) -> Iterator[dict[str, Any]]:
    """Yield ``count`` benign-only Caddy v2 access-log events.

    Used for negative e2e expectations — webserver Sigma rules that fire
    on the attack-mix dataset MUST NOT fire here.
    """
    rng = random.Random(seed)
    for i in range(count):
        yield _event(rng, i, attack=False)
