"""Unit tests for the synthetic dataset generator framework.

Covers:

* Vocab helpers round-trip through the trust-root module.
* Per-generator count and valid-NDJSON shape.
* CLI surface: ``python -m dev.synth`` end-to-end.
* Pipeline-target shape: each generator emits the field names the
  corresponding ``victorialogs_<pipeline>`` mapping points at.

Determinism (byte-identical output for ``seed=42``) is enforced
separately in ``tests/test_synth_determinism.py``. Privacy-by-construction
is enforced by reviewing ``dev/synth/_vocab.py`` (CODEOWNERS-gated), not
by scanning generator output on every PR.
"""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from dev.synth import GENERATORS  # noqa: E402
from dev.synth._vocab import (  # noqa: E402
    random_hostname,
    random_rfc1918_v4,
    random_rfc3849_v6,
    random_rfc5737_v4,
    random_user_agent,
    random_username,
)
from dev.synth._writer import serialize, write_ndjson  # noqa: E402

_RFC5737 = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]
_RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]
_RFC3849 = ipaddress.ip_network("2001:db8::/32")
_RESERVED_TLDS_RE = re.compile(r"\.(example|test|invalid)$")


def _is_safe_ipv4(s: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(s)
    except ValueError:
        return False
    return any(addr in net for net in _RFC5737 + _RFC1918) or addr.is_loopback


def _is_safe_ipv6(s: str) -> bool:
    try:
        addr = ipaddress.IPv6Address(s)
    except ValueError:
        return False
    return addr in _RFC3849 or addr.is_loopback


# ---------------------------- vocab helpers -----------------------------


def test_vocab_helpers_round_trip():
    import random

    rng = random.Random(0)
    assert _is_safe_ipv4(random_rfc5737_v4(rng))
    assert _is_safe_ipv4(random_rfc1918_v4(rng))
    assert _is_safe_ipv6(random_rfc3849_v6(rng))
    host = random_hostname(rng)
    assert _RESERVED_TLDS_RE.search(host), host
    assert random_username(rng)
    assert random_user_agent(rng)
    assert random_user_agent(rng, suspicious=True)


# ---------------------------- count / shape -----------------------------


@pytest.mark.parametrize("name", sorted(GENERATORS))
def test_generator_count_matches(name: str):
    gen = GENERATORS[name]
    payload = serialize(gen(0, 17))
    assert payload.count(b"\n") == 17


@pytest.mark.parametrize("name", sorted(GENERATORS))
def test_generator_emits_valid_ndjson(name: str):
    gen = GENERATORS[name]
    payload = serialize(gen(0, 10))
    for line in payload.splitlines():
        json.loads(line)  # raises if invalid


# ---------------------------- shape: pipeline targets -----------------------------


def test_caddy_emits_request_method():
    payload = serialize(GENERATORS["caddy"](42, 30))
    assert any("request" in json.loads(line) for line in payload.splitlines())
    one = json.loads(payload.splitlines()[0])
    assert "method" in one["request"]
    assert "uri" in one["request"]
    assert "remote_ip" in one["request"]
    assert "User-Agent" in one["request"]["headers"]
    assert "status" in one


def test_journald_emits_trusted_fields():
    payload = serialize(GENERATORS["journald"](42, 30))
    one = json.loads(payload.splitlines()[0])
    assert "_EXE" in one
    assert "_CMDLINE" in one
    assert "_HOSTNAME" in one
    assert "MESSAGE" in one
    assert "PRIORITY" in one


def test_podman_emits_k8s_audit_shape():
    """The podman generator emits Kubernetes audit events — the only public
    Sigma corpus that exercises the ``victorialogs_podman`` pipeline."""
    payload = serialize(GENERATORS["podman"](42, 30))
    events = [json.loads(line) for line in payload.splitlines()]
    assert all(ev.get("kind") == "Event" for ev in events)
    assert all(ev.get("apiVersion") == "audit.k8s.io/v1" for ev in events)
    assert all("verb" in ev for ev in events)
    assert all("objectRef" in ev for ev in events)


def test_suricata_emits_eve_shape():
    payload = serialize(GENERATORS["suricata"](42, 100))
    types = {json.loads(line)["event_type"] for line in payload.splitlines()}
    assert types <= {"flow", "http", "dns", "tls", "alert"}
    one = json.loads(payload.splitlines()[0])
    assert "src_ip" in one
    assert "dest_ip" in one
    assert "dest_port" in one


# ---------------------------- writer -----------------------------


def test_write_ndjson_returns_count_and_sha(tmp_path: Path):
    out = tmp_path / "x.ndjson"
    n, sha = write_ndjson(out, ({"a": i} for i in range(3)))
    assert n == 3
    assert len(sha) == 64
    text = out.read_text(encoding="utf-8")
    assert text.count("\n") == 3
    assert text.startswith('{"a":0}\n')


# ---------------------------- CLI -----------------------------


def test_cli_writes_ndjson(tmp_path: Path):
    out = tmp_path / "caddy.ndjson"
    rc = subprocess.call(
        [
            sys.executable,
            "-m",
            "dev.synth",
            "caddy",
            "--seed=99",
            "--count=4",
            f"--out={out}",
        ],
        cwd=REPO_ROOT,
    )
    assert rc == 0
    assert out.exists()
    assert out.read_bytes().count(b"\n") == 4


def test_cli_rejects_zero_count(tmp_path: Path):
    rc = subprocess.call(
        [
            sys.executable,
            "-m",
            "dev.synth",
            "caddy",
            "--seed=1",
            "--count=0",
            f"--out={tmp_path / 'x.ndjson'}",
        ],
        cwd=REPO_ROOT,
    )
    assert rc == 2
