"""T1021.002 — SMB/Windows Admin Shares (simulation only).

Simulation: enumerates potential UNC admin-share paths for a set of target
hosts drawn from params.  No actual SMB connection is made — the TTP writes
the enumerated path list to a sim-marker file so downstream DLP/network
rules can validate they would fire on real share enumeration traffic.

Defensive value: validates detection of admin-share reconnaissance patterns
(\\\\host\\ADMIN$, C$, IPC$) commonly seen in lateral-movement playbooks.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from ..base import TTP, TTPResult, registry

_DEFAULT_HOSTS = ["192.168.1.10", "192.168.1.20", "10.0.0.5"]
_ADMIN_SHARES = ["ADMIN$", "C$", "IPC$", "D$"]
_MARKER_NAME = "t1021_002_smb_enum.txt"


class T1021002SMBAdminShares(TTP):
    attack_id = "T1021.002"
    name = "SMB/Windows Admin Shares (sim)"
    description = "Enumerate UNC admin-share paths for target hosts without making real SMB connections"
    tactic = "lateral_movement"
    supported_platforms = ("windows", "linux", "darwin")

    def run(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        hosts: list[str] = list(params.get("hosts", _DEFAULT_HOSTS))
        marker_dir = Path(params.get("marker_dir", "data/sim_markers"))
        marker_dir.mkdir(parents=True, exist_ok=True)
        marker_path = marker_dir / _MARKER_NAME

        paths: list[str] = []
        for host in hosts:
            for share in _ADMIN_SHARES:
                paths.append(f"\\\\{host}\\{share}")

        marker_path.write_text(
            "APT_SIM_LATERAL_MOVEMENT T1021.002\n" + "\n".join(paths) + "\n",
            encoding="utf-8",
        )

        return TTPResult(
            ok=True,
            output=f"enumerated {len(paths)} UNC paths across {len(hosts)} hosts",
            artifacts=[str(marker_path)],
            started_at=started,
            finished_at=time.time(),
            extra={"hosts": hosts, "paths": paths, "marker": str(marker_path)},
        )

    def cleanup(self, params: dict[str, Any]) -> TTPResult:
        marker_dir = Path(params.get("marker_dir", "data/sim_markers"))
        marker_path = marker_dir / _MARKER_NAME
        if marker_path.exists():
            marker_path.unlink()
        return TTPResult(ok=True, output="marker removed", started_at=time.time(), finished_at=time.time())

    def sigma_rule(self) -> dict[str, Any]:
        return {
            "title": "SMB Admin Share Enumeration (APT Simulator T1021.002)",
            "id": "b1021002-0000-0000-0000-00001021002a",
            "status": "stable",
            "description": (
                "Detects access to Windows administrative shares (ADMIN$, C$, IPC$) "
                "from anomalous sources, indicating potential lateral movement."
            ),
            "references": ["https://attack.mitre.org/techniques/T1021/002"],
            "tags": ["attack.lateral_movement", "attack.t1021.002"],
            "logsource": {"category": "network_connection", "product": "windows"},
            "detection": {
                "selection": {
                    "DestinationPort": 445,
                    "Initiated": "true",
                },
                "filter_legitimate": {
                    "Image|endswith": ["\\System32\\svchost.exe"],
                },
                "condition": "selection and not filter_legitimate",
            },
            "falsepositives": ["Legitimate backup or admin tools accessing shares"],
            "level": "medium",
        }

    def synthetic_events(self, params: dict[str, Any], result: Any = None) -> list[dict[str, Any]]:
        hosts = list(params.get("hosts", _DEFAULT_HOSTS))
        return [
            {
                "category": "network_connection",
                "DestinationPort": 445,
                "DestinationIp": host,
                "Initiated": "true",
                "Image": "C:\\Windows\\System32\\net.exe",
            }
            for host in hosts[:3]
        ]


registry.register(T1021002SMBAdminShares())
