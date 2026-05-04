"""T1069.001 — Permission Groups Discovery: Local Groups.

Read-only. Enumerates local security groups and their membership.
Adversaries use this to identify high-value groups (Administrators,
Domain Admins, sudoers) before privilege escalation or lateral movement.

Windows: `net localgroup`
Linux/macOS: `getent group` (preferred) or `/etc/group` direct read
"""
from __future__ import annotations

import platform
import subprocess
import time
from pathlib import Path
from typing import Any

from ..base import TTP, TTPResult, registry


class T1069LocalGroupsDiscovery(TTP):
    attack_id = "T1069.001"
    name = "Permission Groups Discovery: Local Groups"
    description = "Enumerate local security groups and high-privilege membership"
    tactic = "discovery"
    supported_platforms = ("windows", "linux", "darwin")

    def run(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        timeout = int(params.get("timeout_seconds", 30))
        plat = platform.system().lower()

        if plat == "windows":
            argv = ["net", "localgroup"]
        elif plat == "darwin":
            argv = ["dscl", ".", "-list", "/Groups"]
        else:
            # Linux: prefer getent, fall back to reading /etc/group
            argv = ["getent", "group"]

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
            if not proc.stdout and plat == "linux":
                # Fallback: read /etc/group directly
                try:
                    lines = Path("/etc/group").read_text(encoding="utf-8").splitlines()
                except OSError as exc:
                    return TTPResult(ok=False, error=str(exc), started_at=started, finished_at=time.time())

            # Count groups that look privileged
            priv_keywords = {"admin", "sudo", "wheel", "root", "domain admins", "administrators"}
            priv_groups = [ln for ln in lines if any(k in ln.lower() for k in priv_keywords)]
            return TTPResult(
                ok=proc.returncode == 0 or bool(lines),
                output=f"found {len(lines)} groups, {len(priv_groups)} privileged",
                started_at=started,
                finished_at=time.time(),
                extra={"total_groups": len(lines), "privileged_groups": priv_groups[:10],
                       "argv": argv, "platform": plat},
            )
        except subprocess.TimeoutExpired:
            return TTPResult(ok=False, error="timeout", started_at=started, finished_at=time.time())
        except FileNotFoundError as exc:
            return TTPResult(ok=False, error=f"binary not found: {exc}", started_at=started, finished_at=time.time())

    def sigma_rule(self) -> dict[str, Any]:
        return {
            "title": "Local Group Enumeration (APT Simulator T1069.001)",
            "id": "a1069001-0000-0000-0000-000000001069",
            "status": "experimental",
            "description": (
                "Detects enumeration of local security groups — a common post-exploitation "
                "step to identify privileged accounts before lateral movement."
            ),
            "references": ["https://attack.mitre.org/techniques/T1069/001"],
            "tags": ["attack.discovery", "attack.t1069.001"],
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection_win": {
                    "Image|endswith": ["\\net.exe", "\\net1.exe"],
                    "CommandLine|contains": ["localgroup"],
                },
                "selection_posix": {
                    "CommandLine|contains": ["getent group", "dscl . -list /Groups"],
                },
                "condition": "1 of selection_*",
            },
            "falsepositives": ["IT admin scripts", "configuration management tools"],
            "level": "low",
        }

    def synthetic_events(self, params: dict[str, Any], result: Any = None) -> list[dict[str, Any]]:
        return [
            {"category": "process_creation",
             "Image": "C:\\Windows\\System32\\net.exe",
             "CommandLine": "net localgroup"},
            {"category": "process_creation",
             "CommandLine": "getent group"},
        ]


registry.register(T1069LocalGroupsDiscovery())
