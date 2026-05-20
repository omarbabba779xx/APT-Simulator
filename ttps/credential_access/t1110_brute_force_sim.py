"""T1110 — Brute Force (simulation only).

Simulation: writes N synthetic failed-login event records to a sim-marker
file.  No real authentication is attempted — the TTP only produces the artifact
a SIEM would see if real brute-force traffic hit an auth endpoint.

Defensive value: validates that account-lockout thresholds, authentication
rate-limit alerts, and SIEM correlation rules fire on the expected event volume.
"""
from __future__ import annotations

import random
import time
from pathlib import Path
from typing import Any

from ..base import TTP, TTPResult, registry

_DEFAULT_ATTEMPTS = 20
_DEFAULT_USERNAMES = [
    "administrator", "admin", "root", "svc_backup",
    "svc_sql", "helpdesk", "support", "guest",
]
_MARKER_NAME = "t1110_brute_force.jsonl"


class T1110BruteForceSim(TTP):
    attack_id = "T1110"
    name = "Brute Force Authentication Simulation"
    description = "Generate synthetic failed-login event markers to validate brute-force detection rules"
    tactic = "credential_access"
    supported_platforms = ("windows", "linux", "darwin")

    def run(self, params: dict[str, Any]) -> TTPResult:
        import json

        started = time.time()
        attempts: int = int(params.get("attempts", _DEFAULT_ATTEMPTS))
        usernames: list[str] = list(params.get("usernames", _DEFAULT_USERNAMES))
        src_ip: str = str(params.get("src_ip", "198.51.100.42"))  # TEST-NET-3 (RFC 5737)
        seed = params.get("seed", 42)
        marker_dir = Path(params.get("marker_dir", "data/sim_markers"))
        marker_dir.mkdir(parents=True, exist_ok=True)
        marker_path = marker_dir / _MARKER_NAME

        rng = random.Random(seed)
        events: list[dict[str, Any]] = []
        ts = time.time()
        for i in range(attempts):
            user = rng.choice(usernames)
            events.append({
                "EventID": 4625,
                "TargetUserName": user,
                "IpAddress": src_ip,
                "LogonType": 3,
                "FailureReason": "%%2313",
                "timestamp": ts + i * 0.5,
                "_sim": "APT_SIM_CRED_ACCESS_T1110",
            })

        marker_path.write_text(
            "\n".join(json.dumps(e) for e in events) + "\n",
            encoding="utf-8",
        )

        return TTPResult(
            ok=True,
            output=f"wrote {attempts} synthetic failed-login events to {marker_path}",
            artifacts=[str(marker_path)],
            started_at=started,
            finished_at=time.time(),
            extra={"attempts": attempts, "src_ip": src_ip, "marker": str(marker_path)},
        )

    def cleanup(self, params: dict[str, Any]) -> TTPResult:
        marker_dir = Path(params.get("marker_dir", "data/sim_markers"))
        marker_path = marker_dir / _MARKER_NAME
        if marker_path.exists():
            marker_path.unlink()
        return TTPResult(ok=True, output="marker removed", started_at=time.time(), finished_at=time.time())

    def sigma_rule(self) -> dict[str, Any]:
        return {
            "title": "Brute Force — Multiple Failed Logons (APT Simulator T1110)",
            "id": "b1110000-0000-0000-0000-000000001110",
            "status": "stable",
            "description": (
                "Detects more than 5 failed authentication attempts for the same "
                "user within 5 minutes — indicative of brute-force or password spray."
            ),
            "references": [
                "https://attack.mitre.org/techniques/T1110",
                "https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625",
            ],
            "tags": ["attack.credential_access", "attack.t1110", "attack.t1110.001"],
            "logsource": {"product": "windows", "service": "security"},
            "detection": {
                "selection": {
                    "EventID": 4625,
                    "LogonType": 3,
                },
                "timeframe": "5m",
                "condition": "selection | count(TargetUserName) by IpAddress > 5",
            },
            "falsepositives": [
                "Misconfigured service accounts",
                "Legitimate admin password reset",
            ],
            "level": "high",
        }

    def synthetic_events(self, params: dict[str, Any], result: Any = None) -> list[dict[str, Any]]:
        attempts = int(params.get("attempts", _DEFAULT_ATTEMPTS))
        src_ip = str(params.get("src_ip", "198.51.100.42"))
        return [
            {
                "category": "authentication",
                "EventID": 4625,
                "TargetUserName": "administrator",
                "IpAddress": src_ip,
                "LogonType": 3,
            }
            for _ in range(min(attempts, 6))
        ]


registry.register(T1110BruteForceSim())
