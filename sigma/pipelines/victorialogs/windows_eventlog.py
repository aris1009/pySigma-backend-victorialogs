"""
Generic Windows EventLog pipeline for the VictoriaLogs backend.

Targets the Winlogbeat / Vector ECS layout — the de-facto standard for
shipping Windows Event Log data into VictoriaLogs:

* Each Sigma `logsource: { product: windows, service: <s> }` rule gets a
  `winlog.channel:=<channel>` selector derived from the SigmaHQ
  service→channel mapping (sigma.pipelines.common.windows_logsource_mapping).
* Top-level event metadata (EventID, Channel, Provider, Computer, etc.) is
  remapped to the `winlog.*` ECS fields written by Winlogbeat ≥ 7.
* Every other Sigma field on a Windows rule (Image, CommandLine, TargetObject,
  …) is prefixed with `winlog.event_data.` to match where Winlogbeat / Vector
  place EventData payload fields.

This is intentionally a *minimal* generic pipeline — it does not flatten into
ECS process/file/network fields. Use a dedicated ECS pipeline downstream if
that level of normalisation is required.
"""

from __future__ import annotations

from sigma.pipelines.common import generate_windows_logsource_items
from sigma.processing.conditions import (
    FieldNameProcessingItemAppliedCondition,
    IncludeFieldCondition,
    LogsourceCondition,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    AddFieldnamePrefixTransformation,
    FieldMappingTransformation,
)

# Top-level winlog.* fields (written by Winlogbeat / Vector outside event_data).
# Sources: Winlogbeat ECS reference, Vector `windows_event_log` source.
# Typed as the union pySigma's FieldMappingTransformation accepts so we can
# pass it through `dict(...)` without a `# type: ignore`.
_WINLOG_TOPLEVEL_FIELD_MAPPING: dict[str | None, str | list[str]] = {
    "EventID": "winlog.event_id",
    "Channel": "winlog.channel",
    "Provider_Name": "winlog.provider_name",
    "ProviderName": "winlog.provider_name",
    "ProviderGuid": "winlog.provider_guid",
    "Computer": "winlog.computer_name",
    "ComputerName": "winlog.computer_name",
    "EventRecordID": "winlog.record_id",
    "Task": "winlog.task",
    "Opcode": "winlog.opcode",
    "Keywords": "winlog.keywords",
    "Level": "winlog.level",
    "Version": "winlog.version",
}

_FIELD_MAPPING_ID = "victorialogs_windows_eventlog_field_mapping"
_EVENTDATA_PREFIX_ID = "victorialogs_windows_eventlog_eventdata_prefix"


def victorialogs_windows_eventlog() -> ProcessingPipeline:
    """Generic Windows EventLog → VictoriaLogs (Winlogbeat/Vector layout)."""
    return ProcessingPipeline(
        name="VictoriaLogs Windows EventLog (Winlogbeat/Vector ECS layout)",
        priority=20,
        allowed_backends=frozenset({"victorialogs"}),
        items=[
            *generate_windows_logsource_items("winlog.channel", "{source}"),
            ProcessingItem(
                identifier=_FIELD_MAPPING_ID,
                transformation=FieldMappingTransformation(dict(_WINLOG_TOPLEVEL_FIELD_MAPPING)),
                rule_conditions=[LogsourceCondition(product="windows")],
            ),
            ProcessingItem(
                identifier=_EVENTDATA_PREFIX_ID,
                transformation=AddFieldnamePrefixTransformation("winlog.event_data."),
                rule_conditions=[LogsourceCondition(product="windows")],
                field_name_conditions=[
                    FieldNameProcessingItemAppliedCondition(_FIELD_MAPPING_ID),
                    IncludeFieldCondition(fields=[r"\w+\."], mode="re"),
                ],
                field_name_condition_negation=True,
                field_name_condition_linking=any,
            ),
        ],
    )
