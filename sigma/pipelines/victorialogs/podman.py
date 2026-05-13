"""
Podman / container pipeline for the VictoriaLogs backend.

When podman / docker / containerd ship container stdout to journald (the
default on most Linux hosts), each entry carries the container metadata
under the ``CONTAINER_*`` journald fields. When the same logs are shipped
through Vector's / fluent-bit's ``container_logs`` source, the metadata
lands on VL ``_stream`` labels (``container_name``, ``image_name``,
``namespace``).

This pipeline maps Sigma's container-related field names onto whichever
shape applies. By default it targets the journald form (most common);
operators using a stream-label shipper can layer a second pipeline of
their own on top.

Scope
-----

* Applies to rules whose ``logsource`` mentions a container product
  (``docker``, ``podman``, ``kubernetes``) or a generic
  ``category: container``.
* Renames only fields with a clear container-runtime counterpart. Sigma
  has no rich container taxonomy — the mapping below is intentionally
  small.

Reference: ``man systemd.journal-fields`` (CONTAINER_NAME, CONTAINER_ID,
CONTAINER_TAG, IMAGE_NAME).
"""

from __future__ import annotations

from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation

_PODMAN_FIELD_MAPPING: dict[str | None, str | list[str]] = {
    # Container identity — journald CONTAINER_* convention.
    "ContainerName": "CONTAINER_NAME",
    "container_name": "CONTAINER_NAME",
    "ContainerId": "CONTAINER_ID",
    "ContainerID": "CONTAINER_ID",
    "container_id": "CONTAINER_ID",
    "ContainerTag": "CONTAINER_TAG",
    "container_tag": "CONTAINER_TAG",
    # Image — both `Image` (rare for containers, common for processes)
    # and the explicit `ImageName` get routed to IMAGE_NAME so container
    # rules don't accidentally inherit the Linux process_creation
    # `Image -> _EXE` mapping.
    "ImageName": "IMAGE_NAME",
    "image_name": "IMAGE_NAME",
    "container_image": "IMAGE_NAME",
}

_FIELD_MAPPING_ID = "victorialogs_podman_field_mapping"


def victorialogs_podman() -> ProcessingPipeline:
    """Sigma container rules -> podman/docker journald CONTAINER_* shape."""
    return ProcessingPipeline(
        name="VictoriaLogs podman/docker (journald CONTAINER_* shape)",
        priority=20,
        allowed_backends=frozenset({"victorialogs"}),
        items=[
            ProcessingItem(
                identifier=_FIELD_MAPPING_ID,
                transformation=FieldMappingTransformation(dict(_PODMAN_FIELD_MAPPING)),
                rule_conditions=[
                    LogsourceCondition(category="container"),
                    LogsourceCondition(product="docker"),
                    LogsourceCondition(product="podman"),
                    LogsourceCondition(product="kubernetes"),
                ],
                rule_condition_linking=any,
            ),
        ],
    )
