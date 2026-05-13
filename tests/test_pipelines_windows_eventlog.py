"""
Unit tests for the generic Windows EventLog pipeline.

The pipeline targets the Winlogbeat / Vector ECS layout (winlog.* + winlog.event_data.*).
Each test asserts the **exact** LogsQL query produced for a given Sigma rule;
field-mapping or selector regressions are surface-level differences and these
expectations should change deliberately, not silently.
"""

from __future__ import annotations

import pytest
from sigma.collection import SigmaCollection

from sigma.backends.victorialogs import VictoriaLogsBackend
from sigma.pipelines.victorialogs import (
    pipelines,
    victorialogs_windows_eventlog,
)
from sigma.pipelines.victorialogs.windows_eventlog import (
    _WINLOG_TOPLEVEL_FIELD_MAPPING,
)

# ---------------------------- pipeline metadata -----------------------------


def test_pipeline_metadata():
    pipeline = victorialogs_windows_eventlog()
    assert pipeline.name == "VictoriaLogs Windows EventLog (Winlogbeat/Vector ECS layout)"
    assert pipeline.priority == 20
    assert pipeline.allowed_backends == frozenset({"victorialogs"})
    assert len(pipeline.items) > 0


def test_pipeline_registered_in_pipelines_dict():
    assert "victorialogs_windows_eventlog" in pipelines
    assert pipelines["victorialogs_windows_eventlog"] is victorialogs_windows_eventlog


def test_pipeline_registered_via_entry_point():
    """pySigma plugin discovery — see pyproject.toml [tool.poetry.plugins.\"sigma.pipelines\"]."""
    from importlib.metadata import entry_points

    eps = list(entry_points(group="sigma.pipelines"))
    matches = [e for e in eps if e.name == "victorialogs"]
    assert matches, "no `victorialogs` entry point in group `sigma.pipelines`"
    target = matches[0].load()
    assert "victorialogs_windows_eventlog" in target


# ---------------------------- helpers -----------------------------


def _backend() -> VictoriaLogsBackend:
    return VictoriaLogsBackend(processing_pipeline=victorialogs_windows_eventlog())


def _convert(yaml: str) -> str:
    out = _backend().convert(SigmaCollection.from_yaml(yaml))
    assert isinstance(out, list) and len(out) == 1, f"expected 1 query, got {out!r}"
    return out[0]


# ---------------------------- channel selector ------------------------------


def test_security_channel_selector():
    q = _convert(
        """
title: T
status: test
logsource:
    product: windows
    service: security
detection:
    sel:
        EventID: 4624
    condition: sel
"""
    )
    assert q == 'winlog.channel:="Security" AND winlog.event_id:=4624'


def test_sysmon_channel_selector():
    q = _convert(
        """
title: T
status: test
logsource:
    product: windows
    service: sysmon
detection:
    sel:
        EventID: 1
    condition: sel
"""
    )
    assert q == ('winlog.channel:="Microsoft-Windows-Sysmon/Operational" AND winlog.event_id:=1')


def test_powershell_channel_selector_or_list():
    """`powershell` service maps to two channels — should produce an OR list."""
    q = _convert(
        """
title: T
status: test
logsource:
    product: windows
    service: powershell
detection:
    sel:
        EventID: 4104
    condition: sel
"""
    )
    assert q == (
        '(winlog.channel:in("Microsoft-Windows-PowerShell/Operational", '
        '"PowerShellCore/Operational")) AND winlog.event_id:=4104'
    )


# ---------------------------- top-level field mapping ------------------------


def test_top_level_field_mapping_eventid_and_computer():
    q = _convert(
        """
title: T
status: test
logsource:
    product: windows
    service: security
detection:
    sel:
        EventID: 4625
        Computer: dc01.example.com
    condition: sel
"""
    )
    assert q == (
        'winlog.channel:="Security" AND winlog.event_id:=4625 AND '
        'winlog.computer_name:="dc01.example.com"'
    )


def test_top_level_field_mapping_provider_alias():
    """Both `Provider_Name` and `ProviderName` should map to winlog.provider_name."""
    q = _convert(
        """
title: T
status: test
logsource:
    product: windows
    service: security
detection:
    sel:
        Provider_Name: Microsoft-Windows-Security-Auditing
    condition: sel
"""
    )
    assert q == (
        'winlog.channel:="Security" AND winlog.provider_name:="Microsoft-Windows-Security-Auditing"'
    )


def test_top_level_field_mapping_covers_winlog_fields():
    """Every documented top-level field maps to a `winlog.` ECS path."""
    for sigma_field, target in _WINLOG_TOPLEVEL_FIELD_MAPPING.items():
        assert target.startswith("winlog."), (
            f"{sigma_field}: top-level mapping {target!r} should be under winlog.*"
        )


# ---------------------------- event_data prefix ------------------------------


def test_event_data_prefix_for_unmapped_field():
    q = _convert(
        """
title: T
status: test
logsource:
    product: windows
    category: process_creation
detection:
    sel:
        Image|endswith: \\powershell.exe
        CommandLine|contains: -EncodedCommand
    condition: sel
"""
    )
    assert q == (
        'winlog.event_data.Image:~"\\\\\\\\powershell\\\\.exe$" AND '
        'winlog.event_data.CommandLine:"-EncodedCommand"'
    )


def test_event_data_prefix_skips_mapped_field():
    """Fields hit by the top-level mapping must not get the event_data prefix."""
    q = _convert(
        """
title: T
status: test
logsource:
    product: windows
    service: security
detection:
    sel:
        EventID: 4720
        TargetUserName: alice
    condition: sel
"""
    )
    assert "winlog.event_data.winlog" not in q
    assert "winlog.event_data.EventID" not in q
    assert q == (
        'winlog.channel:="Security" AND winlog.event_id:=4720 AND '
        'winlog.event_data.TargetUserName:="alice"'
    )


def test_event_data_prefix_skips_already_dotted_field():
    """Fields that already contain a `.` (e.g. nested path from the rule author)
    must not get an extra prefix."""
    q = _convert(
        """
title: T
status: test
logsource:
    product: windows
    service: sysmon
detection:
    sel:
        'winlog.event_data.Image': C:\\Windows\\System32\\cmd.exe
    condition: sel
"""
    )
    assert q == (
        'winlog.channel:="Microsoft-Windows-Sysmon/Operational" AND '
        'winlog.event_data.Image:="C:\\\\Windows\\\\System32\\\\cmd.exe"'
    )


# ---------------------------- non-Windows isolation --------------------------


def test_non_windows_rule_unaffected():
    """Linux/macOS rules must not pick up winlog.* prefixing or channel filters."""
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
    condition: sel
"""
    )
    assert q == 'Image:="/usr/bin/curl"'
    assert "winlog" not in q


# ---------------------------- combined real-world rule ----------------------


def test_realistic_sysmon_process_creation_rule():
    q = _convert(
        """
title: Suspicious cmd.exe spawn
status: test
logsource:
    product: windows
    category: process_creation
detection:
    sel:
        EventID: 1
        Image|endswith: \\cmd.exe
        ParentImage|endswith: \\winword.exe
    condition: sel
"""
    )
    assert q == (
        "winlog.event_id:=1 AND "
        'winlog.event_data.Image:~"\\\\\\\\cmd\\\\.exe$" AND '
        'winlog.event_data.ParentImage:~"\\\\\\\\winword\\\\.exe$"'
    )


# ---------------------------- defensive ----------------------------


@pytest.mark.parametrize("service", ["security", "sysmon", "system", "application"])
def test_each_core_service_emits_channel_filter(service: str):
    q = _convert(
        f"""
title: T
status: test
logsource:
    product: windows
    service: {service}
detection:
    sel:
        EventID: 1
    condition: sel
"""
    )
    assert "winlog.channel:" in q
    assert "winlog.event_id:=1" in q
