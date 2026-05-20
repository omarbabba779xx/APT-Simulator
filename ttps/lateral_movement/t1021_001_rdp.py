"""T1021.001 — Remote Desktop Protocol (simulation only).

Simulation: performs a non-destructive TCP port probe to determine whether
RDP (port 3389) is reachable on a set of target hosts.  This mirrors the
host-enumeration step an adversary takes before attempting RDP-based lateral
movement.  No authentication or session is established.

Defensive value: validates that network-level detections (port-scan rules,
unexpected RDP egress) fire on RDP reconnaissance activity.
"""
from __future__ import annotations

import socket
import time
from pathlib import Path
from typing import Any

from ..base import TTP, TTPResult, registry

_RDP_PORT = 3389
_PROBE_TIMEOUT = 1.5
_MARKER_NAME = "t1021_001_rdp_probe.txt"


class T1021001RDP(TTP):
    attack_id = "T1021.001"
    name = "Remote Desktop Protocol Probe (sim)"
    description = "TCP port probe to detect RDP availability on target hosts"
    tactic = "lateral_movement"
    supported_platforms = ("windows", "linux", "darwin")

    def run(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        hosts: list[str] = list(params.get("hosts", ["127.0.0.1"]))
        port: int = int(params.get("port", _RDP_PORT))
        timeout: float = float(params.get("timeout", _PROBE_TIMEOUT))
        marker_dir = Path(params.get("marker_dir", "data/sim_markers"))
        marker_dir.mkdir(parents=True, exist_ok=True)

        results: list[dict[str, Any]] = []
        for host in hosts:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                code = sock.connect_ex((host, port))
                open_ = code == 0
            except OSError:
                open_ = False
            finally:
                sock.close()
            results.append({"host": host, "port": port, "open": open_})

        marker_path = marker_dir / _MARKER_NAME
        lines = ["APT_SIM_LATERAL_MOVEMENT T1021.001"] + [
            f"{r['host']}:{r['port']} open={r['open']}" for r in results
        ]
        marker_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        open_count = sum(1 for r in results if r["open"])
        return TTPResult(
            ok=True,
            output=f"probed {len(hosts)} host(s) on port {port}: {open_count} open",
            artifacts=[str(marker_path)],
            started_at=started,
            finished_at=time.time(),
            extra={"results": results, "marker": str(marker_path)},
        )

    def cleanup(self, params: dict[str, Any]) -> TTPResult:
        marker_dir = Path(params.get("marker_dir", "data/sim_markers"))
        marker_path = marker_dir / _MARKER_NAME
        if marker_path.exists():
            marker_path.unlink()
        return TTPResult(ok=True, output="marker removed", started_at=time.time(), finished_at=time.time())

    def sigma_rule(self) -> dict[str, Any]:
        return {
            "title": "RDP Lateral Movement Probe (APT Simulator T1021.001)",
            "id": "b1021001-0000-0000-0000-00001021001a",
            "status": "stable",
            "description": (
                "Detects TCP connections to port 3389 (RDP) initiated from non-admin "
                "workstations, indicative of lateral movement or network reconnaissance."
            ),
            "references": ["https://attack.mitre.org/techniques/T1021/001"],
            "tags": ["attack.lateral_movement", "attack.t1021.001"],
            "logsource": {"category": "network_connection", "product": "windows"},
            "detection": {
                "selection": {
                    "DestinationPort": 3389,
                    "Initiated": "true",
                },
                "filter_rdp_client": {
                    "Image|endswith": ["\\mstsc.exe"],
                    "User|contains": ["SYSTEM"],
                },
                "condition": "selection and not filter_rdp_client",
            },
            "falsepositives": ["Legitimate remote administration by IT staff"],
            "level": "medium",
        }

    def synthetic_events(self, params: dict[str, Any], result: Any = None) -> list[dict[str, Any]]:
        hosts = list(params.get("hosts", ["127.0.0.1"]))
        port = int(params.get("port", _RDP_PORT))
        return [
            {
                "category": "network_connection",
                "DestinationPort": port,
                "DestinationIp": host,
                "Initiated": "true",
                "Image": "C:\\Windows\\System32\\cmd.exe",
            }
            for host in hosts[:3]
        ]


registry.register(T1021001RDP())
