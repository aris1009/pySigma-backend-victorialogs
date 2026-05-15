"""End-to-end Grafana provisioning load test for the ``grafana_alerting`` format.

This is the **structural contract test** for the format: it spins up a real
Grafana container, mounts a generated alert-rule YAML at
``/etc/grafana/provisioning/alerting/``, and asserts that Grafana's
provisioning loader accepts the file at boot.

Why containers and not unit tests
---------------------------------

Grafana has no published JSON schema for its provisioning format; the
authoritative validator is the loader code in ``grafana/grafana``. Running
the loader itself is the only way to catch breakage from a missing required
field, a misnamed enum, or a Grafana-version-specific schema drift.

What this test does NOT cover
-----------------------------

* The VictoriaLogs datasource plugin's acceptance of our ``model.queryType``
  and ``expr`` shape. Grafana accepts the rule structurally before any query
  ever evaluates — plugin-level validation is exercised by the manual e2e
  runbook in ``tests/e2e/grafana_alerting/README.md``, not here.
* Actual alert evaluation. That requires a full VL + plugin stack and lives
  in the same manual runbook.

Operationally
-------------

Skipped automatically when ``docker`` is not on PATH or not usable, so the
unit-test job stays green on machines without Docker. Wire to a dedicated CI
job (e.g. ``e2e-grafana-provisioning``) that runs on PRs touching the
backend.
"""

from __future__ import annotations

import shutil
import subprocess
import time
import uuid
from pathlib import Path

import pytest
from sigma.collection import SigmaCollection

from sigma.backends.victorialogs import VictoriaLogsBackend

pytestmark = pytest.mark.grafana_provisioning

# Grafana versions to validate against. 10.4 is the floor declared by the
# victoriametrics-logs-datasource plugin; ``latest`` catches forward drift.
GRAFANA_IMAGES = ["grafana/grafana:10.4.0", "grafana/grafana:latest"]

# Boot budget per image. Grafana cold-starts in ~10-15s on a warm host; the
# generous timeout absorbs first-pull latency on a cold CI agent.
BOOT_TIMEOUT = 90.0
POLL_INTERVAL = 1.0

SAMPLE_RULE = """
title: Provisioning smoke rule
id: 99999999-9999-4999-8999-999999999999
status: experimental
description: Drives the Grafana provisioning structural test.
references:
  - https://example.com/ref
level: high
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\cmd.exe'
    CommandLine|contains: 'powershell'
  condition: selection
"""


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        subprocess.run(
            ["docker", "info"],
            check=True,
            capture_output=True,
            timeout=10,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return False
    return True


@pytest.fixture(scope="module")
def provisioning_yaml(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Generate the alert YAML once for all parametrized boots."""
    backend = VictoriaLogsBackend(grafana_datasource_uid="vl-test")
    yaml_text = backend.convert(
        SigmaCollection.from_yaml(SAMPLE_RULE),
        output_format="grafana_alerting",
    )
    assert isinstance(yaml_text, str)
    provisioning_dir = tmp_path_factory.mktemp("grafana-alerting")
    target = provisioning_dir / "sigma.yaml"
    target.write_text(yaml_text, encoding="utf-8")
    return target


def _container_name() -> str:
    return f"sigma-grafana-provisioning-{uuid.uuid4().hex[:8]}"


def _docker_logs(name: str) -> str:
    out = subprocess.run(
        ["docker", "logs", name],
        check=False,
        capture_output=True,
        timeout=10,
    )
    # Grafana writes both info and errors to stderr.
    return (out.stdout + out.stderr).decode("utf-8", errors="replace")


def _wait_for_provisioning(name: str, timeout: float) -> tuple[bool, str]:
    """Tail container logs until provisioning completes or a hard error appears.

    Returns ``(ok, logs)`` where ``ok`` is true if the loader logged success
    for our rule group without an error. The poll is line-based on the full
    log buffer rather than a streaming follower because Grafana writes one
    structured log line per provisioning action.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        logs = _docker_logs(name)
        lower = logs.lower()
        # Grafana logs an "error" level event with msg containing
        # "could not provision" or "failed to provision" on bad YAML.
        for marker in (
            "could not provision",
            "failed to provision",
            "error parsing",
            "invalid alert rule",
        ):
            if marker in lower:
                return False, logs
        # Success markers vary across versions but all contain "alerting"
        # alongside "provisioned" / "applied". The HTTP server line ("HTTP
        # Server Listen") is the latest signal that provisioning finished
        # without aborting boot.
        if "http server listen" in lower:
            return True, logs
        time.sleep(POLL_INTERVAL)
    return False, _docker_logs(name)


@pytest.mark.parametrize("image", GRAFANA_IMAGES)
def test_grafana_loads_provisioning_yaml(image: str, provisioning_yaml: Path) -> None:
    """Grafana boots cleanly with our generated alert-rule YAML provisioned."""
    if not _docker_available():
        pytest.skip("docker not available on this host")

    name = _container_name()
    host_dir = provisioning_yaml.parent.resolve()
    try:
        subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--rm",
                "--name",
                name,
                "-v",
                f"{host_dir}:/etc/grafana/provisioning/alerting:ro",
                "-e",
                "GF_LOG_LEVEL=info",
                "-e",
                "GF_PATHS_PROVISIONING=/etc/grafana/provisioning",
                image,
            ],
            check=True,
            capture_output=True,
            timeout=60,
        )
        ok, logs = _wait_for_provisioning(name, timeout=BOOT_TIMEOUT)
        if not ok:
            # Truncate to last ~3 KB so failure output stays scannable.
            tail = logs[-3000:] if len(logs) > 3000 else logs
            pytest.fail(
                f"Grafana {image} did not accept provisioning YAML.\n--- last log lines ---\n{tail}"
            )
    finally:
        subprocess.run(
            ["docker", "rm", "-f", name],
            check=False,
            capture_output=True,
            timeout=15,
        )
