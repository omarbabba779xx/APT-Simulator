"""T1049 — System Network Connections Discovery.

Read-only. Captures active network connections and listening ports via netstat.
Mirrors what an adversary runs to understand the network posture of a compromised
host: existing C2 channels, exposed services, lateral movement targets.
"""
from __future__ import annotations

import platform
import subprocess
import time
from typing import Any

from ..base import TTP, TTPResult, registry


class T1049NetworkConnectionsDiscovery(TTP):
    attack_id = "T1049"
    name = "System Network Connections Discovery"
    description = "Enumerate active network connections and listening ports (netstat)"
    tactic = "discovery"
    supported_platforms = ("windows", "linux", "darwin")

    def run(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        timeout = int(params.get("timeout_seconds", 30))
        plat = platform.system().lower()

        if plat == "windows":
            argv = ["netstat", "-ano"]
        else:
            argv = ["netstat", "-tulpn"] if plat == "linux" else ["netstat", "-an"]

        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,
                check=False,
            )
            lines = proc.stdout.splitlines()
            listening = sum(1 for ln in lines if "LISTEN" in ln.upper())
            established = sum(1 for ln in lines if "ESTABLISHED" in ln.upper())
            return TTPResult(
                ok=proc.returncode == 0,
                output=f"found {len(lines)} connections ({listening} listening, {established} established)",
                error=(proc.stderr[:1000] or None) if proc.returncode != 0 else None,
                started_at=started,
                finished_at=time.time(),
                extra={"argv": argv, "total_rows": len(lines), "listening": listening, "established": established,
                       "sample": lines[:20]},
            )
        except subprocess.TimeoutExpired:
            return TTPResult(ok=False, error="timeout", started_at=started, finished_at=time.time())
        except FileNotFoundError as exc:
            return TTPResult(ok=False, error=f"binary not found: {exc}", started_at=started, finished_at=time.time())

    def sigma_rule(self) -> dict[str, Any]:
        return {
            "title": "Network Connections Enumeration (APT Simulator T1049)",
            "id": "a1049000-0000-0000-0000-000000001049",
            "status": "experimental",
            "description": "Detects use of netstat to enumerate active connections — commonly used to identify C2 channels and pivot targets.",
            "references": ["https://attack.mitre.org/techniques/T1049"],
            "tags": ["attack.discovery", "attack.t1049"],
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection_win": {
                    "Image|endswith": ["\\netstat.exe"],
                },
                "selection_posix": {
                    "CommandLine|contains": ["netstat"],
                },
                "condition": "1 of selection_*",
            },
            "falsepositives": ["Monitoring agents", "IT diagnostic scripts"],
            "level": "low",
        }

    def synthetic_events(self, params: dict[str, Any], result: Any = None) -> list[dict[str, Any]]:
        return [
            {"category": "process_creation", "Image": "C:\\Windows\\System32\\netstat.exe", "CommandLine": "netstat -ano"},
            {"category": "process_creation", "CommandLine": "netstat -tulpn"},
        ]


registry.register(T1049NetworkConnectionsDiscovery())
