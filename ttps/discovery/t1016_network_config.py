"""T1016 — System Network Configuration Discovery.

Read-only. Captures network interface configuration (ipconfig /all on Windows,
ip addr show / ifconfig on POSIX). Mirrors what an adversary enumerates to map
available networks before pivoting or establishing C2.
"""
from __future__ import annotations

import platform
import subprocess
import time
from typing import Any

from ..base import TTP, TTPResult, registry


class T1016NetworkConfigDiscovery(TTP):
    attack_id = "T1016"
    name = "System Network Configuration Discovery"
    description = "Enumerate network interface config (ipconfig /all / ip addr show / ifconfig)"
    tactic = "discovery"
    supported_platforms = ("windows", "linux", "darwin")

    def run(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        timeout = int(params.get("timeout_seconds", 30))
        plat = platform.system().lower()

        if plat == "windows":
            candidates = [["ipconfig", "/all"]]
        elif plat == "darwin":
            candidates = [["ifconfig"]]
        else:
            candidates = [["ip", "addr", "show"], ["ifconfig"]]

        for argv in candidates:
            try:
                proc = subprocess.run(
                    argv,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    shell=False,
                    check=False,
                )
                return TTPResult(
                    ok=proc.returncode == 0,
                    output=proc.stdout[:4000] or "(empty output)",
                    error=(proc.stderr[:1000] or None) if proc.returncode != 0 else None,
                    started_at=started,
                    finished_at=time.time(),
                    extra={"argv": argv, "platform": plat},
                )
            except subprocess.TimeoutExpired:
                return TTPResult(ok=False, error="timeout", started_at=started, finished_at=time.time())
            except FileNotFoundError:
                continue  # try next candidate

        return TTPResult(
            ok=False,
            error="no suitable network config binary found",
            started_at=started,
            finished_at=time.time(),
        )

    def sigma_rule(self) -> dict[str, Any]:
        return {
            "title": "Network Interface Configuration Discovery (APT Simulator T1016)",
            "id": "a1016000-0000-0000-0000-000000001016",
            "status": "experimental",
            "description": "Detects enumeration of network interface configuration — a common APT recon step before lateral movement.",
            "references": ["https://attack.mitre.org/techniques/T1016"],
            "tags": ["attack.discovery", "attack.t1016"],
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection_win": {
                    "Image|endswith": ["\\ipconfig.exe"],
                },
                "selection_posix": {
                    "CommandLine|contains": ["ifconfig", "ip addr"],
                },
                "condition": "1 of selection_*",
            },
            "falsepositives": ["IT inventory scripts", "DHCP diagnostic tools", "monitoring agents"],
            "level": "low",
        }

    def synthetic_events(self, params: dict[str, Any], result: Any = None) -> list[dict[str, Any]]:
        return [
            {"category": "process_creation", "Image": "C:\\Windows\\System32\\ipconfig.exe", "CommandLine": "ipconfig /all"},
            {"category": "process_creation", "CommandLine": "ifconfig"},
        ]


registry.register(T1016NetworkConfigDiscovery())
