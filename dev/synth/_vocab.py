"""Trust-root vocabulary module for synthetic event generation.

Every identifying value (IP, hostname, domain, username, container name,
container image, user-agent string) emitted by any ``dev/synth/<gen>.py``
generator must originate here and only here. Generators are deterministic
functions of ``(vocab, seed)``; the leak guarantee is "review this file
once, trust the generator math" rather than scanning generator output on
every PR.

Enforcement:

* ``.github/CODEOWNERS`` requires owner review for any change under
  ``dev/synth/``, including this file.
* ``tests/test_synth_determinism.py`` asserts each generator with
  ``seed=42`` produces byte-identical output across two consecutive runs;
  any nondeterminism implies an unpinned source of values (something
  outside this module).

Generators MUST NOT:

* Read environment variables for vocabulary.
* Read files outside ``dev/synth/``.
* Import third-party faker libraries that auto-generate identifying
  values without going through this vocab as the override source.

Current vocab is RFC-clean — every IP comes from RFC 5737/1918, every
hostname from RFC 2606 reserved TLDs, every username from the standard
cryptography "alphabet alice" set. If realism demands more variety
(realistic-looking attacker domains for IOC realism, hand-picked public
IPs that are demonstrably not homelab addresses), add them here under
explicit owner review — not by reaching outside this module.

References:

* RFC 5737 — IPv4 documentation prefixes (TEST-NET-1/2/3).
* RFC 3849 — IPv6 documentation prefix (2001:db8::/32).
* RFC 1918 — IPv4 private ranges (used sparingly, only when the rule needs
  a "private network" shape; never as the public-facing client IP).
* RFC 2606 — reserved TLDs (.example/.test/.invalid) and reserved domain
  names (example.com / .net / .org).
* RFC 6761 — additional reserved names (localhost, .local under mDNS).
"""

from __future__ import annotations

import ipaddress
import random

# IPv4 documentation pools — RFC 5737.
_RFC5737_BLOCKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)

# IPv4 private ranges — RFC 1918. Used only for "internal" client shapes
# where the rule explicitly wants RFC1918, never for the public client IP.
_RFC1918_BLOCKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)

# IPv6 documentation prefix — RFC 3849.
_RFC3849_BLOCK = ipaddress.ip_network("2001:db8::/32")

# RFC 2606 reserved TLDs + sample domains. Synthetic hostnames use these.
RESERVED_TLDS = ("example", "test", "invalid")
RESERVED_DOMAINS = ("example.com", "example.net", "example.org")

# Hostnames the suricata generator plants as benign DNS / TLS / HTTP
# `Host:` values. All under reserved TLDs per RFC 2606.
BENIGN_DOMAINS = (
    "www.example.com",
    "api.example.org",
    "static.example.net",
    "telemetry.example.test",
    "registry.example.invalid",
)

# Suffix for synthetic DNS-exfil-shaped queries — the generator prefixes
# a random label, so the full name lands as ``<random>.exfil.example.invalid``.
EXFIL_DOMAIN_SUFFIX = "exfil.example.invalid"

# Cryptography alphabet — universally understood as fictional.
USERNAMES = (
    "alice",
    "bob",
    "carol",
    "dave",
    "eve",
    "frank",
    "grace",
    "heidi",
    "ivan",
    "judy",
    "mallory",
    "oscar",
    "peggy",
    "trent",
    "victor",
    "walter",
)

# Container image names — point at a documentation registry that does not
# resolve to a real public registry.
CONTAINER_IMAGES = (
    "registry.example.invalid/team/web:1.0.0",
    "registry.example.invalid/team/api:2.3.1",
    "registry.example.invalid/team/worker:0.9.4",
    "registry.example.invalid/team/cron:1.4.2",
)

CONTAINER_NAMES = (
    "web-1",
    "web-2",
    "api-1",
    "api-2",
    "worker-1",
    "worker-2",
    "cron-1",
    "cron-2",
)

USER_AGENTS = (
    # Versions are kept to two-component (major.minor) form so they cannot
    # be mis-parsed as IPv4 addresses by privacy-gate scanners.
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537 (KHTML, like Gecko) Chrome/120 Safari/537",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X) AppleWebKit/605 (KHTML, like Gecko) Version/17 Safari/605",
    "curl/8",
    "python-requests/2",
    "Mozilla/5.0 (Windows NT 10; Win64; x64) AppleWebKit/537 (KHTML, like Gecko) Edge/120",
)

# Suspicious user agents used by the synthetic suricata generator's
# "rule-matching" subset — strings public Sigma rules look for.
SUSPICIOUS_USER_AGENTS = (
    "sqlmap/1-dev",
    "nmap/7",
    "Nikto/2",
    "Mozilla/5 (Nikto/2) (Evasions:None) (Test:Var)",
)

# Recon/scanner user agents that the SigmaHQ webserver rule
# `web_susp_useragents.yml` flags. Distinct from the general suspicious
# pool above so the caddy generator can plant verbatim matches.
RECON_USER_AGENTS = (
    "Wfuzz/2",
    "WPScan v3",
    "Recon-ng/v5",
    "GIS - AppSec Team - Project Vision",
)


def random_rfc5737_v4(rng: random.Random) -> str:
    """Pick a random IPv4 from the documentation blocks (RFC 5737)."""
    block = rng.choice(_RFC5737_BLOCKS)
    return str(ipaddress.IPv4Address(int(block.network_address) + rng.randint(1, 254)))


def random_rfc1918_v4(rng: random.Random) -> str:
    """Pick a random IPv4 from the private blocks (RFC 1918)."""
    block = rng.choice(_RFC1918_BLOCKS)
    # Stay well within block bounds — pick one of the first 65k addresses.
    offset = rng.randint(1, 65_534)
    return str(ipaddress.IPv4Address(int(block.network_address) + offset))


def random_rfc3849_v6(rng: random.Random) -> str:
    """Pick a random IPv6 from the documentation prefix (RFC 3849)."""
    base = int(_RFC3849_BLOCK.network_address)
    # Offset within the documented /32. Cap at /48 worth to keep the
    # address visually short.
    offset = rng.randint(0, 2**80 - 1)
    return str(ipaddress.IPv6Address(base + offset))


def random_hostname(rng: random.Random, *, prefix: str = "host") -> str:
    """Build a hostname using a reserved TLD."""
    tld = rng.choice(RESERVED_TLDS)
    n = rng.randint(1, 99)
    return f"{prefix}-{n:02d}.{tld}"


def random_username(rng: random.Random) -> str:
    return rng.choice(USERNAMES)


def random_user_agent(rng: random.Random, *, suspicious: bool = False) -> str:
    if suspicious:
        return rng.choice(SUSPICIOUS_USER_AGENTS)
    return rng.choice(USER_AGENTS)
