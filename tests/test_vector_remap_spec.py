"""Spec for the e2e/vector.toml remap, expressed as a Python mirror.

Vector's remap engine (VRL) cannot be invoked without the Rust binary, so
this test asserts the *contract* the remap is meant to satisfy: for a
representative mordor-shape OTRF event, the produced shape must match
what the victorialogs_windows_eventlog() pipeline queries against.

If you change the VRL in e2e/vector.toml, update _python_remap() below to
mirror it. The e2e harness is the only place where the
two are cross-validated against a live Vector — this file is the static
contract every developer can run in CI.
"""

from __future__ import annotations

from typing import Any

import pytest

# Fields the VRL strips so they don't bloat event_data.
_NOISE_FIELDS = {
    "host",
    "source_type",
    "file",
    "@version",
    "tags",
    "EventType",
    "EventTime",
    "OpcodeValue",
    "ThreadID",
    "Message",
}

# top-level mordor field -> winlog.* destination (keys to consume from input).
_TOPLEVEL_MAP: dict[str, str] = {
    "Channel": "channel",
    "EventID": "event_id",
    "ProviderGuid": "provider_guid",
    "EventRecordID": "record_id",
    "Task": "task",
    "Opcode": "opcode",
    "Keywords": "keywords",
    "Level": "level",
    "Version": "version",
}


def _python_remap(event: dict[str, Any]) -> dict[str, Any]:
    """Pure-Python mirror of e2e/vector.toml's `to_winlog` VRL transform."""
    e = dict(event)  # work on a copy
    ts = e.pop("@timestamp", None)
    for k in _NOISE_FIELDS:
        e.pop(k, None)

    winlog: dict[str, Any] = {}
    for src, dst in _TOPLEVEL_MAP.items():
        if src in e:
            winlog[dst] = e.pop(src)

    # computer_name: Computer or fall back to Hostname.
    computer = e.pop("Computer", None)
    hostname = e.pop("Hostname", None)
    if computer is not None:
        winlog["computer_name"] = computer
    elif hostname is not None:
        winlog["computer_name"] = hostname

    # provider_name: Provider_Name or fall back to SourceName.
    provider = e.pop("Provider_Name", None)
    source_name = e.pop("SourceName", None)
    if provider is not None:
        winlog["provider_name"] = provider
    elif source_name is not None:
        winlog["provider_name"] = source_name

    # Everything left becomes event_data — the path AddFieldnamePrefixTransformation
    # ("winlog.event_data.") in our pipeline targets.
    if e:
        winlog["event_data"] = e

    out: dict[str, Any] = {"winlog": winlog}
    if ts is not None:
        out["_time"] = ts
    return out


# ---------------------------- minimal mordor fixtures -----------------------------


SYSMON_EID10_LSASS_ACCESS = {
    "@timestamp": "2020-08-07T14:32:25.358Z",
    "@version": "1",
    "tags": ["mordorDataset"],
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "EventID": 10,
    "Hostname": "MORDORDC.theshire.local",
    "SourceName": "Microsoft-Windows-Sysmon",
    "EventRecordID": 12345,
    "Task": 10,
    "OpcodeValue": 0,
    "Message": "Process accessed:\nRuleName: -...",
    "EventType": "INFO",
    "EventTime": "2020-08-07 10:32:22",
    "ThreadID": 4208,
    "Version": 3,
    "TargetImage": "C:\\windows\\system32\\lsass.exe",
    "TargetProcessGUID": "{9f85ce58-5a6a-5f2b-a900-000000000400}",
    "SourceImage": "C:\\windows\\system32\\svchost.exe",
    "GrantedAccess": "0x1000",
    "CallTrace": "C:\\windows\\SYSTEM32\\ntdll.dll+9fc24|...",
}

POWERSHELL_EID4103_EMPIRE = {
    "@timestamp": "2020-08-07T14:32:27.000Z",
    "Channel": "Microsoft-Windows-PowerShell/Operational",
    "EventID": 4103,
    "Computer": "WORKSTATION5.theshire.local",
    "Provider_Name": "Microsoft-Windows-PowerShell",
    "ContextInfo": "Severity = Informational\nHost Name = ConsoleHost\nHost Application = powershell.exe -noP -sta -w 1 -enc SQBmAC...",
    "Payload": "CommandInvocation(Start-Sleep): ...",
}

REGISTRY_EID13_FAX_IMAGEPATH = {
    "@timestamp": "2020-09-01T08:00:00Z",
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "EventID": 13,
    "Hostname": "VICTIM.local",
    "TargetObject": "HKLM\\System\\CurrentControlSet\\Services\\Fax\\ImagePath",
    "Details": "C:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe -noexit -c 'whoami'",
    "EventType": "SetValue",
}


# ---------------------------- pipeline-target invariants -----------------------------


def test_remap_lifts_channel_to_winlog_channel():
    out = _python_remap(SYSMON_EID10_LSASS_ACCESS)
    assert out["winlog"]["channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert "Channel" not in out, "Channel must not survive at top level"


def test_remap_lifts_event_id_to_winlog_event_id():
    out = _python_remap(SYSMON_EID10_LSASS_ACCESS)
    assert out["winlog"]["event_id"] == 10
    assert "EventID" not in out


def test_remap_promotes_timestamp_to_underscore_time():
    out = _python_remap(SYSMON_EID10_LSASS_ACCESS)
    assert out["_time"] == "2020-08-07T14:32:25.358Z"


def test_remap_pushes_payload_under_event_data():
    out = _python_remap(SYSMON_EID10_LSASS_ACCESS)
    ed = out["winlog"]["event_data"]
    # These are the fields a Sigma rule would address as e.g. TargetImage|endswith
    # The pipeline prefixes them to winlog.event_data.<name>.
    assert ed["TargetImage"] == "C:\\windows\\system32\\lsass.exe"
    assert ed["GrantedAccess"] == "0x1000"
    assert "CallTrace" in ed


def test_remap_uses_hostname_when_computer_absent():
    out = _python_remap(SYSMON_EID10_LSASS_ACCESS)
    assert out["winlog"]["computer_name"] == "MORDORDC.theshire.local"


def test_remap_prefers_computer_when_both_present():
    e = dict(SYSMON_EID10_LSASS_ACCESS, Computer="ELDER.local")
    out = _python_remap(e)
    assert out["winlog"]["computer_name"] == "ELDER.local"


def test_remap_provider_name_preference():
    out = _python_remap(POWERSHELL_EID4103_EMPIRE)
    # Provider_Name takes precedence over SourceName.
    assert out["winlog"]["provider_name"] == "Microsoft-Windows-PowerShell"


def test_remap_strips_noise_fields():
    out = _python_remap(SYSMON_EID10_LSASS_ACCESS)
    flat: list[str] = []

    def _flatten(prefix: str, obj: object) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                _flatten(f"{prefix}.{k}" if prefix else k, v)
        else:
            flat.append(prefix)

    _flatten("", out)
    for noise in (
        "Message",
        "EventType",
        "EventTime",
        "OpcodeValue",
        "ThreadID",
        "tags",
        "@version",
    ):
        assert not any(p.endswith(noise) for p in flat), f"{noise!r} leaked into output"


def test_remap_registry_event_routes_event_data():
    """The registry-set rule queries winlog.event_data.{TargetObject,Details}."""
    out = _python_remap(REGISTRY_EID13_FAX_IMAGEPATH)
    ed = out["winlog"]["event_data"]
    assert ed["TargetObject"].endswith("\\ImagePath")
    assert "powershell.exe" in ed["Details"]


def test_remap_powershell_module_event_routes_context_info():
    """posh_pm_susp_invocation_specific.yml selects on ContextInfo."""
    out = _python_remap(POWERSHELL_EID4103_EMPIRE)
    ed = out["winlog"]["event_data"]
    assert "ContextInfo" in ed
    assert "-noP -sta -w 1 -enc" in ed["ContextInfo"]


# ---------------------------- vector.toml is a valid TOML doc -----------------------------


def test_vector_toml_parses():
    try:
        import tomllib
    except ImportError:  # pragma: no cover - Python <3.11
        import tomli as tomllib  # type: ignore[import-not-found,no-redef]
    from pathlib import Path

    repo = Path(__file__).resolve().parent.parent
    cfg = tomllib.loads((repo / "e2e" / "vector.toml").read_text(encoding="utf-8"))
    # Required components.
    assert "otrf" in cfg["sources"]
    assert "to_winlog" in cfg["transforms"]
    assert "victorialogs" in cfg["sinks"]
    # Sink targets the JSON-line ingest endpoint with stream-field hint.
    sink = cfg["sinks"]["victorialogs"]
    assert sink["uri"].endswith("/insert/jsonline?_stream_fields=winlog.channel")
    assert sink["compression"] == "none"
    assert sink["encoding"]["codec"] == "json"


@pytest.mark.parametrize(
    "fixture",
    [SYSMON_EID10_LSASS_ACCESS, POWERSHELL_EID4103_EMPIRE, REGISTRY_EID13_FAX_IMAGEPATH],
)
def test_remap_always_produces_channel_and_event_id(fixture: dict[str, Any]) -> None:
    out = _python_remap(fixture)
    assert "channel" in out["winlog"]
    assert "event_id" in out["winlog"]
