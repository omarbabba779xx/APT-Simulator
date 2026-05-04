"""T1057 — Process Discovery.

Read-only enumeration of running processes. Equivalent telemetry to
`tasklist` / `ps -ef`. Returns counts and a small sample. Does not touch
process memory.
"""
from __future__ import annotations

import platform
import subprocess
import time
from typing import Any

from ..base import TTP, TTPResult, registry


class T1057ProcessDiscovery(TTP):
    attack_id = "T1057"
    name = "Process Discovery"
    description = "List running processes (read-only)"
    tactic = "discovery"

    def run(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        argv = ["tasklist"] if platform.system().lower() == "windows" else ["ps", "-eo", "pid,comm"]
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=int(params.get("timeout_seconds", 60)),
                shell=False,
                check=False,
            )
            lines = proc.stdout.splitlines()
            return TTPResult(
                ok=proc.returncode == 0,
                output=f"enumerated {len(lines)} process rows",
                error=(proc.stderr[:1000] or None) if proc.returncode != 0 else None,
                started_at=started,
                finished_at=time.time(),
                extra={"argv": argv, "row_count": len(lines), "sample": lines[:20]},
            )
        except subprocess.TimeoutExpired:
            return TTPResult(ok=False, error="timeout", started_at=started, finished_at=time.time())
        except FileNotFoundError as exc:
            return TTPResult(ok=False, error=f"binary not found: {exc}", started_at=started, finished_at=time.time())

    def sigma_rule(self) -> dict[str, Any]:
        return {
            "title": "Process Listing Enumeration (APT Simulator T1057)",
            "id": "a1057000-0000-0000-0000-000000001057",
            "status": "experimental",
            "description": "Detects tasklist/ps execution as part of recon.",
            "references": ["https://attack.mitre.org/techniques/T1057"],
            "tags": ["attack.discovery", "attack.t1057"],
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection_win": {
                    "Image|endswith": ["\\tasklist.exe", "\\qprocess.exe"],
                },
                "selection_posix": {
                    "CommandLine|contains": ["ps -e", "ps -A", "ps aux"],
                },
                "condition": "1 of selection_*",
            },
            "falsepositives": ["Diagnostic scripts"],
            "level": "low",
        }

    def synthetic_events(self, params, result=None):  # type: ignore[override]
        return [
            {"category": "process_creation", "Image": "C:\\Windows\\System32\\tasklist.exe", "CommandLine": "tasklist"},
            {"category": "process_creation", "Image": "/bin/ps", "CommandLine": "ps -e"},
        ]


registry.register(T1057ProcessDiscovery())
