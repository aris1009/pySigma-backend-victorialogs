"""
Unit tests for the podman/docker pipeline.
"""

from __future__ import annotations

from sigma.collection import SigmaCollection

from sigma.backends.victorialogs import VictoriaLogsBackend
from sigma.pipelines.victorialogs import pipelines, victorialogs_podman
from sigma.pipelines.victorialogs.podman import _PODMAN_FIELD_MAPPING

# ---------------------------- pipeline metadata -----------------------------


def test_pipeline_metadata():
    p = victorialogs_podman()
    assert p.name == "VictoriaLogs podman/docker (journald CONTAINER_* shape)"
    assert p.priority == 20
    assert p.allowed_backends == frozenset({"victorialogs"})


def test_registered_in_pipelines_dict():
    assert pipelines["victorialogs_podman"] is victorialogs_podman


def test_registered_via_entry_point():
    from importlib.metadata import entry_points

    target = next(
        e for e in entry_points(group="sigma.pipelines") if e.name == "victorialogs"
    ).load()
    assert "victorialogs_podman" in target


# ---------------------------- helpers -----------------------------


def _backend() -> VictoriaLogsBackend:
    return VictoriaLogsBackend(processing_pipeline=victorialogs_podman())


def _convert(yaml: str) -> str:
    out = _backend().convert(SigmaCollection.from_yaml(yaml))
    assert isinstance(out, list) and len(out) == 1
    return out[0]


# ---------------------------- mappings --------------------------------------


def test_container_name_and_id():
    q = _convert(
        """
title: T
status: test
logsource:
    category: container
detection:
    sel:
        ContainerName: alpine
        ContainerID: abc123
    condition: sel
"""
    )
    assert q == 'CONTAINER_NAME:="alpine" AND CONTAINER_ID:="abc123"'


def test_image_name_routes_to_image_name_not_exe():
    """Critical: the journald pipeline maps `Image` to `_EXE` (process exec).
    For container rules we must route ImageName to IMAGE_NAME, not allow it
    to be interpreted as a process executable path."""
    q = _convert(
        """
title: T
status: test
logsource:
    category: container
detection:
    sel:
        ImageName: docker.io/library/alpine:3.20
    condition: sel
"""
    )
    assert q == 'IMAGE_NAME:="docker.io/library/alpine:3.20"'
    assert "_EXE" not in q


def test_docker_product_routed():
    q = _convert(
        """
title: T
status: test
logsource:
    product: docker
detection:
    sel:
        ContainerName: web
    condition: sel
"""
    )
    assert q == 'CONTAINER_NAME:="web"'


def test_kubernetes_product_routed():
    q = _convert(
        """
title: T
status: test
logsource:
    product: kubernetes
detection:
    sel:
        container_name: nginx
    condition: sel
"""
    )
    assert q == 'CONTAINER_NAME:="nginx"'


# ---------------------------- gating ---------------------------------------


def test_non_container_rule_unaffected():
    """A normal Linux process_creation rule must not pick up CONTAINER_*
    renames — its `Image` should remain untouched (the journald pipeline,
    when stacked, will rename it to `_EXE`)."""
    q = _convert(
        """
title: T
status: test
logsource:
    product: linux
    category: process_creation
detection:
    sel:
        ImageName: /usr/bin/curl
    condition: sel
"""
    )
    assert q == 'ImageName:="/usr/bin/curl"'
    assert "IMAGE_NAME" not in q


# ---------------------------- mapping invariants ---------------------------


def test_all_targets_are_journald_container_fields():
    """Every podman target must be one of the documented journald
    CONTAINER_* fields or IMAGE_NAME."""
    allowed = {"CONTAINER_NAME", "CONTAINER_ID", "CONTAINER_TAG", "IMAGE_NAME"}
    for sigma_field, target in _PODMAN_FIELD_MAPPING.items():
        assert isinstance(target, str)
        assert target in allowed, f"{sigma_field} -> {target!r}: unexpected target"
