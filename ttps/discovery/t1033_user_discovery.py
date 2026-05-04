"""T1033 — System Owner/User Discovery.

Read-only. Captures current username + domain context, equivalent to `whoami` /
`id`. Generates the artifact a real adversary would query.
"""
from __future__ import annotations

import getpass
import os
import platform
import socket
import time
from typing import Any

from ..base import TTP, TTPResult, registry


class T1033UserDiscovery(TTP):
    attack_id = "T1033"
    name = "System Owner/User Discovery"
    description = "Enumerate current user, hostname, domain"
    tactic = "discovery"
    supported_platforms = ("windows", "linux", "darwin")

    def run(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        try:
            user = getpass.getuser()
            host = socket.gethostname()
            plat = platform.platform()
            domain = os.environ.get("USERDOMAIN") or os.environ.get("HOSTNAME", "")
            output = f"user={user} host={host} domain={domain} platform={plat}"
            return TTPResult(
                ok=True,
                output=output,
                started_at=started,
                finished_at=time.time(),
                extra={"user": user, "host": host, "domain": domain, "platform": plat},
            )
        except Exception as exc:  # pragma: no cover
            return TTPResult(
                ok=False,
                error=str(exc),
                started_at=started,
                finished_at=time.time(),
            )

    def sigma_rule(self) -> dict[str, Any]:
        return {
            "title": "User and System Owner Discovery (APT Simulator T1033)",
            "id": "a1033000-0000-0000-0000-000000001033",
            "status": "experimental",
            "description": "Detects enumeration of current user/host context (whoami, hostname).",
            "references": ["https://attack.mitre.org/techniques/T1033"],
            "tags": ["attack.discovery", "attack.t1033"],
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "selection": {
                    "Image|endswith": ["\\whoami.exe", "\\hostname.exe"],
                },
                "condition": "selection",
            },
            "falsepositives": ["Legitimate admin scripts"],
            "level": "low",
        }

    def synthetic_events(self, params, result=None):  # type: ignore[override]
        return [
            {"category": "process_creation", "Image": "C:\\Windows\\System32\\whoami.exe", "CommandLine": "whoami"},
        ]


registry.register(T1033UserDiscovery())
