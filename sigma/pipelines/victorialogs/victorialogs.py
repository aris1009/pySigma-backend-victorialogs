"""
Processing pipelines for the VictoriaLogs backend.

Phase 1 ships only an empty placeholder; concrete log-source pipelines
(journald, Caddy, Suricata EVE, podman) land in Phase 3.
"""

from sigma.processing.pipeline import ProcessingPipeline


def victorialogs_pipeline() -> ProcessingPipeline:
    """No-op placeholder pipeline. Returns an empty ProcessingPipeline."""
    return ProcessingPipeline(
        name="VictoriaLogs placeholder pipeline",
        priority=20,
        items=[],
    )
