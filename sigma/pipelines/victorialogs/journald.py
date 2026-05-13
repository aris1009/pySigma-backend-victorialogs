"""
Generic systemd-journal pipeline for the VictoriaLogs backend.

systemd-journald is the dominant Linux log transport that lands in
VictoriaLogs — either via Vector's `journald` source, fluent-bit's `systemd`
input, or VL agents that read ``/var/log/journal`` directly. All three
preserve the journal's native field convention (uppercase names, leading
underscore for trusted fields the kernel/PID 1 stamped on the entry), so
rule conversion needs to translate Sigma's neutral Linux taxonomy
(``Image``, ``CommandLine``, …) into the journald convention
(``_EXE``, ``_CMDLINE``, …).

Scope
-----

* Applies only to rules with ``logsource: { product: linux }``.
* Renames the well-known equivalents listed in
  ``_JOURNALD_FIELD_MAPPING`` below.
* Fields without a meaningful journald counterpart (``ParentImage``,
  ``ParentCommandLine``, ``LogonId``, the textual ``User`` form, …) are
  left untouched. They originate from auditd / sysmon-for-linux, NOT raw
  journald — rules that depend on them will not match plain journald data
  by design. Run those rules through a dedicated auditd /
  sysmon-for-linux pipeline instead (out of scope here).

The pipeline does not prefix unmapped fields the way the Windows EventLog
pipeline does: there is no journald equivalent of ``winlog.event_data.*``,
and silently moving every Sigma field under a made-up namespace would hide
the auditd/journald gap rather than expose it.
"""

from __future__ import annotations

from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation

# Sigma neutral field name -> journald field name (as written by the journal).
# Typed as the union pySigma's FieldMappingTransformation accepts so it can
# be passed through ``dict(...)`` without a ``# type: ignore``.
_JOURNALD_FIELD_MAPPING: dict[str | None, str | list[str]] = {
    # Process metadata captured natively by journald (trusted fields).
    "Image": "_EXE",
    "ProcessName": "_COMM",
    "CommandLine": "_CMDLINE",
    "ProcessId": "_PID",
    # Host / unit metadata.
    "Computer": "_HOSTNAME",
    "Hostname": "_HOSTNAME",
    "Unit": "_SYSTEMD_UNIT",
    # Syslog-shape metadata journald carries through for forwarded entries.
    "SyslogTag": "SYSLOG_IDENTIFIER",
    "Program": "SYSLOG_IDENTIFIER",
    "program": "SYSLOG_IDENTIFIER",
    "Facility": "SYSLOG_FACILITY",
    "SyslogFacility": "SYSLOG_FACILITY",
    "Priority": "PRIORITY",
    "Severity": "PRIORITY",
    # Free-form log line.
    "Message": "MESSAGE",
    "msg": "MESSAGE",
}

_FIELD_MAPPING_ID = "victorialogs_journald_field_mapping"


def victorialogs_journald() -> ProcessingPipeline:
    """Generic journald -> VictoriaLogs (native systemd-journal field names)."""
    return ProcessingPipeline(
        name="VictoriaLogs journald (systemd-journal native fields)",
        priority=20,
        allowed_backends=frozenset({"victorialogs"}),
        items=[
            ProcessingItem(
                identifier=_FIELD_MAPPING_ID,
                transformation=FieldMappingTransformation(dict(_JOURNALD_FIELD_MAPPING)),
                rule_conditions=[LogsourceCondition(product="linux")],
            ),
        ],
    )
