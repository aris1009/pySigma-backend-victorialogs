"""
Unit tests for the generic journald pipeline.

The pipeline targets systemd-journal's native field convention (uppercase,
leading underscore for trusted fields). Each test asserts the **exact**
LogsQL query produced for a given Sigma rule; field-mapping regressions
should change deliberately, not silently.
"""

from __future__ import annotations

import pytest
from sigma.collection import SigmaCollection

from sigma.backends.victorialogs import VictoriaLogsBackend
from sigma.pipelines.victorialogs import (
    pipelines,
    victorialogs_journald,
)
from sigma.pipelines.victorialogs.journald import _JOURNALD_FIELD_MAPPING

# ---------------------------- pipeline metadata -----------------------------


def test_pipeline_metadata():
    pipeline = victorialogs_journald()
    assert pipeline.name == "VictoriaLogs journald (systemd-journal native fields)"
    assert pipeline.priority == 20
    assert pipeline.allowed_backends == frozenset({"victorialogs"})
    assert len(pipeline.items) > 0


def test_pipeline_registered_in_pipelines_dict():
    assert "victorialogs_journald" in pipelines
    assert pipelines["victorialogs_journald"] is victorialogs_journald


def test_pipeline_registered_via_entry_point():
    """pySigma plugin discovery — see pyproject.toml [tool.poetry.plugins.\"sigma.pipelines\"]."""
    from importlib.metadata import entry_points

    eps = list(entry_points(group="sigma.pipelines"))
    matches = [e for e in eps if e.name == "victorialogs"]
    assert matches, "no `victorialogs` entry point in group `sigma.pipelines`"
    target = matches[0].load()
    assert "victorialogs_journald" in target


# ---------------------------- helpers -----------------------------


def _backend() -> VictoriaLogsBackend:
    return VictoriaLogsBackend(processing_pipeline=victorialogs_journald())


def _convert(yaml: str) -> str:
    out = _backend().convert(SigmaCollection.from_yaml(yaml))
    assert isinstance(out, list) and len(out) == 1, f"expected 1 query, got {out!r}"
    return out[0]


# ---------------------------- process_creation ------------------------------


def test_process_creation_image_and_commandline():
    q = _convert(
        """
title: T
status: test
logsource:
    product: linux
    category: process_creation
detection:
    sel:
        Image: /usr/bin/curl
        CommandLine|contains: example.com
    condition: sel
"""
    )
    assert q == '_EXE:="/usr/bin/curl" AND _CMDLINE:"example.com"'


def test_process_creation_processname_endswith():
    q = _convert(
        """
title: T
status: test
logsource:
    product: linux
    category: process_creation
detection:
    sel:
        ProcessName|endswith: bash
    condition: sel
"""
    )
    assert q == '_COMM:~"bash$"'


def test_process_id_numeric_unquoted():
    """ProcessId should pass through as a numeric LogsQL value."""
    q = _convert(
        """
title: T
status: test
logsource:
    product: linux
    category: process_creation
detection:
    sel:
        ProcessId: 1337
    condition: sel
"""
    )
    assert q == "_PID:=1337"


# ---------------------------- syslog / auth ---------------------------------


def test_syslog_program_alias_maps_to_syslog_identifier():
    """`program` and `Program` and `SyslogTag` all collapse onto SYSLOG_IDENTIFIER."""
    for sigma_field in ("program", "Program", "SyslogTag"):
        q = _convert(
            f"""
title: T
status: test
logsource:
    product: linux
    service: syslog
detection:
    sel:
        {sigma_field}: sshd
    condition: sel
"""
        )
        assert q == 'SYSLOG_IDENTIFIER:="sshd"', f"{sigma_field} mapping wrong: {q!r}"


def test_auth_message_substring_search():
    """Classic ssh-bruteforce-style rule: substring against the journal MESSAGE body."""
    q = _convert(
        """
title: T
status: test
logsource:
    product: linux
    service: auth
detection:
    sel:
        Message|contains: 'Failed password for'
    condition: sel
"""
    )
    assert q == 'MESSAGE:"Failed password for"'


def test_priority_and_facility_mapping():
    q = _convert(
        """
title: T
status: test
logsource:
    product: linux
    service: syslog
detection:
    sel:
        Priority: 3
        Facility: 4
    condition: sel
"""
    )
    assert q == "PRIORITY:=3 AND SYSLOG_FACILITY:=4"


def test_unit_and_hostname_mapping():
    q = _convert(
        """
title: T
status: test
logsource:
    product: linux
    service: syslog
detection:
    sel:
        Unit: sshd.service
        Hostname: web01
    condition: sel
"""
    )
    assert q == '_SYSTEMD_UNIT:="sshd.service" AND _HOSTNAME:="web01"'


# ---------------------------- unmapped fields -------------------------------


def test_unmapped_field_left_alone():
    """ParentImage has no native journald counterpart; it must NOT be silently
    renamed or prefixed. Leaving it raw makes the auditd/sysmon-for-linux gap
    visible to the operator instead of producing a query that quietly matches
    nothing under a fabricated path."""
    q = _convert(
        """
title: T
status: test
logsource:
    product: linux
    category: process_creation
detection:
    sel:
        ParentImage: /usr/bin/sshd
    condition: sel
"""
    )
    assert q == 'ParentImage:="/usr/bin/sshd"'


def test_user_field_left_alone():
    """`User` is a textual username in Sigma; journald carries `_UID` (numeric)
    and `_AUDIT_LOGINUID`. The mapping is lossy/ambiguous so we deliberately
    don't rename it — operators add their own pipeline if they need it."""
    q = _convert(
        """
title: T
status: test
logsource:
    product: linux
    category: process_creation
detection:
    sel:
        User: root
    condition: sel
"""
    )
    assert q == 'User:="root"'


# ---------------------------- non-Linux isolation ---------------------------


def test_windows_rule_unaffected():
    """Windows rules must not pick up journald renames."""
    q = _convert(
        """
title: T
status: test
logsource:
    product: windows
    category: process_creation
detection:
    sel:
        Image: C:\\Windows\\System32\\cmd.exe
        CommandLine|contains: /c
    condition: sel
"""
    )
    assert "_EXE" not in q
    assert "_CMDLINE" not in q
    assert q == 'Image:="C:\\\\Windows\\\\System32\\\\cmd.exe" AND CommandLine:"/c"'


def test_macos_rule_unaffected():
    q = _convert(
        """
title: T
status: test
logsource:
    product: macos
    category: process_creation
detection:
    sel:
        Image: /usr/bin/curl
    condition: sel
"""
    )
    assert q == 'Image:="/usr/bin/curl"'
    assert "_EXE" not in q


# ---------------------------- mapping invariants ----------------------------


@pytest.mark.parametrize(
    "sigma_field,journald_field",
    [
        ("Image", "_EXE"),
        ("ProcessName", "_COMM"),
        ("CommandLine", "_CMDLINE"),
        ("ProcessId", "_PID"),
        ("Computer", "_HOSTNAME"),
        ("Hostname", "_HOSTNAME"),
        ("Unit", "_SYSTEMD_UNIT"),
        ("SyslogTag", "SYSLOG_IDENTIFIER"),
        ("Program", "SYSLOG_IDENTIFIER"),
        ("program", "SYSLOG_IDENTIFIER"),
        ("Facility", "SYSLOG_FACILITY"),
        ("SyslogFacility", "SYSLOG_FACILITY"),
        ("Priority", "PRIORITY"),
        ("Severity", "PRIORITY"),
        ("Message", "MESSAGE"),
        ("msg", "MESSAGE"),
    ],
)
def test_mapping_table_matches_module_constant(sigma_field: str, journald_field: str):
    """Test contract: every row above must match _JOURNALD_FIELD_MAPPING.

    If the constant changes, this test fails loudly so a reviewer can
    confirm the rename was intentional."""
    assert _JOURNALD_FIELD_MAPPING[sigma_field] == journald_field


def test_mapping_targets_are_journald_shape():
    """All mapped journald targets are either trusted (`_FOO`) or syslog
    pass-through (`SYSLOG_*`, `MESSAGE`, `PRIORITY`). No lowercase / dotted
    paths, which would indicate a typo."""
    for sigma_field, target in _JOURNALD_FIELD_MAPPING.items():
        assert isinstance(target, str), f"{sigma_field}: target is {target!r}"
        assert target.isupper() or target.startswith("_"), (
            f"{sigma_field} -> {target!r}: not a journald-shaped field name"
        )
        assert "." not in target, f"{sigma_field} -> {target!r}: dotted target"


# ---------------------------- realistic combined rule -----------------------


def test_realistic_ssh_bruteforce_rule():
    """End-to-end shape check on a representative auth/journald rule."""
    q = _convert(
        """
title: SSH bruteforce
status: test
logsource:
    product: linux
    service: auth
detection:
    sel:
        program: sshd
        Message|contains: 'Failed password'
    condition: sel
"""
    )
    assert q == 'SYSLOG_IDENTIFIER:="sshd" AND MESSAGE:"Failed password"'
