"""Convert a few hand-picked rules from the SigmaHQ corpus and print the
resulting LogsQL. Pure diagnostic — used to spot-check that the backend
output is recognizable to a human, not just syntactically valid.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from textwrap import indent

from sigma.collection import SigmaCollection

from sigma.backends.victorialogs import VictoriaLogsBackend

SAMPLES = [
    "linux/auditd/lnx_auditd_susp_cmds.yml",
    "linux/builtin/sshd/lnx_sshd_failed_logon_user_does_not_exist.yml",
    "network/proxy/proxy_ua_susp_base64.yml",
    "web/webserver_generic/web_path_traversal_exploitation_attempt.yml",
    "windows/process_creation/proc_creation_win_powershell_iex_pattern.yml",
    "category/database/db_oracle_alter_user.yml",
    "macos/process_creation/proc_creation_macos_susp_curl_security_download.yml",
    "cloud/aws/cloudtrail/aws_console_root_login.yml",
]


def main() -> int:
    root = os.environ.get("SIGMA_CORPUS_PATH")
    if not root:
        print("set SIGMA_CORPUS_PATH=/path/to/sigma", file=sys.stderr)
        return 2
    rules_root = Path(root) / "rules"
    backend = VictoriaLogsBackend()

    for rel in SAMPLES:
        path = rules_root / rel
        if not path.exists():
            print(f"## {rel}\n  (file not found, skipping)\n")
            continue
        try:
            queries = backend.convert(SigmaCollection.from_yaml(path.read_text()))
        except Exception as exc:
            print(f"## {rel}\n  EXCEPTION: {type(exc).__name__}: {exc}\n")
            continue
        print(f"## {rel}")
        for q in queries:
            print(indent(q, "  "))
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
