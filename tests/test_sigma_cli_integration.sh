#!/usr/bin/env bash
# End-to-end packaging round-trip via the `sigma` CLI.
#
# Builds a wheel, installs it into a throwaway venv together with sigma-cli,
# and asserts that:
#   1. `sigma list backends` discovers `victorialogs` via the entry point
#   2. `sigma convert -t victorialogs <fixture>` produces the expected LogsQL
#
# Catches packaging regressions the pure-Python unit suite misses
# (missing files in the wheel, broken entry-point declarations, dropped
# `py.typed` markers, etc.).
#
# Usage:
#   tests/test_sigma_cli_integration.sh
#
# Requires: python3 (>=3.10), pip, internet access to install sigma-cli.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="$(mktemp -d -t sigma-cli-itest.XXXXXX)"
trap 'rm -rf "${VENV_DIR}"' EXIT

echo "==> building venv at ${VENV_DIR}"
python3 -m venv "${VENV_DIR}"
# shellcheck disable=SC1091
. "${VENV_DIR}/bin/activate"

echo "==> upgrading pip + build"
pip install --quiet --upgrade pip build

echo "==> building wheel from ${REPO_ROOT}"
WHEEL_DIR="${VENV_DIR}/wheel"
mkdir -p "${WHEEL_DIR}"
python -m build --wheel --outdir "${WHEEL_DIR}" "${REPO_ROOT}" >/dev/null

echo "==> installing wheel + sigma-cli"
pip install --quiet "${WHEEL_DIR}"/*.whl sigma-cli

# sigma-cli derives the convert target identifier from the backend class
# name (VictoriaLogsBackend -> "victoria_logs"), which is *not* the same
# as the pyproject entry-point name ("victorialogs"). Both must show up
# in `sigma list targets` for the CLI integration to work end-to-end.
TARGET_ID="victoria_logs"
PLUGIN_NAME="victorialogs"

echo "==> sigma list targets"
LIST_OUT="$(sigma list targets)"
echo "${LIST_OUT}"
if ! grep -qw "${TARGET_ID}" <<<"${LIST_OUT}"; then
    echo "FAIL: sigma did not list target identifier ${TARGET_ID}" >&2
    exit 1
fi
if ! grep -qw "${PLUGIN_NAME}" <<<"${LIST_OUT}"; then
    echo "FAIL: sigma did not list plugin ${PLUGIN_NAME}" >&2
    exit 1
fi

FIXTURE="${VENV_DIR}/rule.yml"
cat >"${FIXTURE}" <<'YAML'
title: itest-fixture
status: test
logsource:
    category: test
detection:
    sel:
        fieldA: valueA
    condition: sel
YAML

echo "==> sigma convert -t ${TARGET_ID} ${FIXTURE}"
CONVERT_OUT="$(sigma convert -t "${TARGET_ID}" "${FIXTURE}")"
echo "${CONVERT_OUT}"
EXPECTED='fieldA:="valueA"'
if [[ "${CONVERT_OUT}" != *"${EXPECTED}"* ]]; then
    echo "FAIL: expected output to contain ${EXPECTED}, got: ${CONVERT_OUT}" >&2
    exit 1
fi

echo "==> sigma convert -t ${TARGET_ID} -f vmalert ${FIXTURE}"
VMALERT_OUT="$(sigma convert -t "${TARGET_ID}" -f vmalert "${FIXTURE}")"
echo "${VMALERT_OUT}"
for needle in 'type: vlogs' 'alert: itest_fixture' '| stats count() as matches'; do
    if [[ "${VMALERT_OUT}" != *"${needle}"* ]]; then
        echo "FAIL: vmalert output missing '${needle}': ${VMALERT_OUT}" >&2
        exit 1
    fi
done

echo "==> OK"
