"""T1082 — System Information Discovery.

Read-only. Collects OS version, hostname, architecture, CPU, memory,
uptime, and environment snapshot — the exact recon an adversary runs
immediately after initial access to fingerprint the victim environment
and decide the next pivot.

No subprocess used; pure Python platform/psutil introspection so it
works on every platform without additional tools.
"""
from __future__ import annotations

import os
import platform
import socket
import sys
import time
from typing import Any

from ..base import TTP, TTPResult, registry


def _collect() -> dict[str, Any]:
    info: dict[str, Any] = {}
    u = platform.uname()
    info["hostname"] = u.node
    info["os"] = u.system
    info["os_release"] = u.release
    info["os_version"] = u.version
    info["machine"] = u.machine
    info["processor"] = u.processor or "unknown"
    info["python_version"] = sys.version.split()[0]
    info["cpu_count"] = os.cpu_count()
    try:
        info["fqdn"] = socket.getfqdn()
    except Exception:
        info["fqdn"] = "unknown"
    # Memory (psutil optional)
    try:
        import psutil  # type: ignore[import]
        mem = psutil.virtual_memory()
        info["memory_total_gb"] = round(mem.total / 1_073_741_824, 2)
        info["memory_avail_gb"] = round(mem.available / 1_073_741_824, 2)
        info["uptime_seconds"] = int(time.time() - psutil.boot_time())
    except ImportError:
        pass
    # Interesting env vars (no secrets — just metadata keys)
    interesting = {"COMPUTERNAME", "USERNAME", "USER", "LOGNAME", "HOME",
                   "USERPROFILE", "APPDATA", "SYSTEMROOT", "PATH"}
    info["env_keys_present"] = sorted(k for k in interesting if k in os.environ)
    return info


class T1082SystemInfoDiscovery(TTP):
    attack_id = "T1082"
    name = "System Information Discovery"
    description = "Collect OS, hardware, hostname, and uptime fingerprint"
    tactic = "discovery"
    supported_platforms = ("windows", "linux", "darwin")

    def run(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        try:
            info = _collect()
            lines = [f"{k}: {v}" for k, v in info.items()]
            return TTPResult(
                ok=True,
                output="\n".join(lines),
                started_at=started,
                finished_at=time.time(),
                extra=info,
            )
        except Exception as exc:
            return TTPResult(ok=False, error=str(exc), started_at=started, finished_at=time.time())

    def sigma_rule(self) -> dict[str, Any]:
        return {
            "title": "System Information Discovery (APT Simulator T1082)",
            "id": "a1082000-0000-0000-0000-000000001082",
            "status": "experimental",
            "description": (
                "Detects commands commonly used to gather OS/hardware fingerprint — "
                "standard adversary post-exploitation recon step."
            ),
            "references": ["https://attack.mitre.org/techniques/T1082"],
            "tags": ["attack.discovery", "attack.t1082"],
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection_win": {
                    "Image|endswith": ["\\systeminfo.exe", "\\winver.exe"],
                },
                "selection_posix": {
                    "CommandLine|contains": ["uname -a", "uname -r", "hostnamectl"],
                },
                "condition": "1 of selection_*",
            },
            "falsepositives": ["IT inventory scripts", "monitoring agents"],
            "level": "low",
        }

    def synthetic_events(self, params: dict[str, Any], result: Any = None) -> list[dict[str, Any]]:
        return [
            {"category": "process_creation",
             "Image": "C:\\Windows\\System32\\systeminfo.exe",
             "CommandLine": "systeminfo"},
            {"category": "process_creation",
             "CommandLine": "uname -a"},
        ]


registry.register(T1082SystemInfoDiscovery())
