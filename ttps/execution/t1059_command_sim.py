"""T1059 — Command and Scripting Interpreter (simulation).

SAFE. Executes a *fixed allowlist* of benign commands only (whoami, hostname,
ipconfig/ifconfig, ps -ef/tasklist). The user-supplied `command` field is mapped
to one of these, never passed to a shell.

Real adversary T1059 invocations look the same to a SIEM — the goal is to
generate the telemetry, not run arbitrary code.
"""
from __future__ import annotations

import platform
import subprocess
import time
from typing import Any

from ..base import TTP, TTPResult, registry


# Fixed mapping of intent -> (windows_argv, posix_argv).
ALLOWED: dict[str, tuple[list[str], list[str]]] = {
    "whoami": (["whoami"], ["whoami"]),
    "hostname": (["hostname"], ["hostname"]),
    "ifconfig": (["ipconfig"], ["ifconfig", "-a"]),
    "ps": (["tasklist"], ["ps", "-ef"]),
    "netstat": (["netstat", "-an"], ["netstat", "-an"]),
}


class T1059CommandSim(TTP):
    attack_id = "T1059"
    name = "Command and Scripting Interpreter (sim)"
    description = "Run benign command from fixed allowlist; arbitrary commands rejected"
    tactic = "execution"

    def run(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        intent = str(params.get("command", "whoami")).strip().lower()
        if intent not in ALLOWED:
            return TTPResult(
                ok=False,
                error=f"command '{intent}' not in allowlist {sorted(ALLOWED)}",
                started_at=started,
                finished_at=time.time(),
            )
        win_argv, posix_argv = ALLOWED[intent]
        argv = win_argv if platform.system().lower() == "windows" else posix_argv
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=int(params.get("timeout_seconds", 15)),
                shell=False,
                check=False,
            )
            return TTPResult(
                ok=proc.returncode == 0,
                output=proc.stdout[:4000],
                error=(proc.stderr[:2000] or None) if proc.returncode != 0 else None,
                started_at=started,
                finished_at=time.time(),
                extra={"argv": argv, "returncode": proc.returncode},
            )
        except subprocess.TimeoutExpired:
            return TTPResult(
                ok=False, error="timeout", started_at=started, finished_at=time.time()
            )
        except FileNotFoundError as exc:
            return TTPResult(
                ok=False, error=f"binary not found: {exc}", started_at=started, finished_at=time.time()
            )


    def sigma_rule(self) -> dict[str, Any]:
        return {
            "title": "Recon Command Execution Burst (APT Simulator T1059)",
            "id": "a1059000-0000-0000-0000-000000001059",
            "status": "experimental",
            "description": "Detects sequential whoami/hostname/ipconfig/tasklist/netstat from same parent process within a short window.",
            "references": ["https://attack.mitre.org/techniques/T1059"],
            "tags": ["attack.execution", "attack.t1059"],
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "selection": {
                    "Image|endswith": [
                        "\\whoami.exe",
                        "\\hostname.exe",
                        "\\ipconfig.exe",
                        "\\tasklist.exe",
                        "\\netstat.exe",
                    ],
                },
                "condition": "selection",
            },
            "falsepositives": ["IT diagnostic scripts"],
            "level": "medium",
        }

    def synthetic_events(self, params, result=None):  # type: ignore[override]
        intent = str(params.get("command", "whoami")).lower()
        binary_map = {
            "whoami": "C:\\Windows\\System32\\whoami.exe",
            "hostname": "C:\\Windows\\System32\\hostname.exe",
            "ifconfig": "C:\\Windows\\System32\\ipconfig.exe",
            "ps": "C:\\Windows\\System32\\tasklist.exe",
            "netstat": "C:\\Windows\\System32\\netstat.exe",
        }
        image = binary_map.get(intent, "C:\\Windows\\System32\\whoami.exe")
        return [{"category": "process_creation", "Image": image, "CommandLine": intent}]


registry.register(T1059CommandSim())
