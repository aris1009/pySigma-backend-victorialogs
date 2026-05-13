"""Processing pipelines for the VictoriaLogs backend."""

from .caddy import victorialogs_caddy
from .journald import victorialogs_journald
from .podman import victorialogs_podman
from .suricata import victorialogs_suricata
from .victorialogs import victorialogs_pipeline
from .windows_eventlog import victorialogs_windows_eventlog

__all__ = [
    "victorialogs_caddy",
    "victorialogs_journald",
    "victorialogs_pipeline",
    "victorialogs_podman",
    "victorialogs_suricata",
    "victorialogs_windows_eventlog",
]

pipelines = {
    "victorialogs": victorialogs_pipeline,
    "victorialogs_caddy": victorialogs_caddy,
    "victorialogs_journald": victorialogs_journald,
    "victorialogs_podman": victorialogs_podman,
    "victorialogs_suricata": victorialogs_suricata,
    "victorialogs_windows_eventlog": victorialogs_windows_eventlog,
}
