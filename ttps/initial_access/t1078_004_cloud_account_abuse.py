"""T1078.004 - Valid Accounts: Cloud Accounts (simulation only).

Simulation: writes CloudTrail-shaped account-use markers for a valid cloud
identity. No cloud SDK is loaded and no remote API is called.

Defensive value: validates alerting for cloud account usage from unusual
source IPs, rapid identity checks, role assumption, and suspicious storage
access after credential use.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from ..base import TTP, TTPResult, registry

_MARKER_NAME = "t1078_004_cloud_account_abuse.jsonl"
_DEFAULT_EVENTS = ["GetCallerIdentity", "AssumeRole", "ListBuckets"]


def _event(
    event_name: str,
    username: str,
    account_id: str,
    source_ip: str,
    event_time: float,
) -> dict[str, Any]:
    return {
        "eventVersion": "1.08",
        "eventSource": "signin.amazonaws.com"
        if event_name == "ConsoleLogin"
        else "sts.amazonaws.com"
        if event_name in {"AssumeRole", "GetCallerIdentity"}
        else "s3.amazonaws.com",
        "eventName": event_name,
        "awsRegion": "us-east-1",
        "sourceIPAddress": source_ip,
        "userAgent": "AptSim/1.0 cloud-account-sim",
        "userIdentity.type": "IAMUser",
        "userIdentity.accountId": account_id,
        "userIdentity.userName": username,
        "responseElements.ConsoleLogin": "Success" if event_name == "ConsoleLogin" else None,
        "eventTime": event_time,
        "_sim": "APT_SIM_INITIAL_ACCESS_T1078_004",
    }


class T1078004CloudAccountAbuse(TTP):
    attack_id = "T1078.004"
    name = "Valid Accounts: Cloud Accounts (sim)"
    description = "Generate CloudTrail-shaped markers for valid cloud account abuse, without cloud API calls"
    tactic = "initial_access"
    supported_platforms = ("windows", "linux", "darwin")

    def run(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        provider = str(params.get("provider", "aws")).lower()
        if provider != "aws":
            return TTPResult(
                ok=False,
                error=f"unsupported provider '{provider}', expected aws",
                started_at=started,
                finished_at=time.time(),
            )

        username = str(params.get("username", "lab-valid-user"))
        account_id = str(params.get("account_id", "123456789012"))
        source_ip = str(params.get("source_ip", "198.51.100.23"))
        event_names = list(params.get("event_names", _DEFAULT_EVENTS))
        event_names = [str(name) for name in event_names[:20]]
        marker_dir = Path(params.get("marker_dir", "data/sim_markers"))
        marker_dir.mkdir(parents=True, exist_ok=True)
        marker_path = marker_dir / _MARKER_NAME

        ts = time.time()
        events = [
            _event(name, username, account_id, source_ip, ts + i)
            for i, name in enumerate(event_names)
        ]
        marker_path.write_text(
            "\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n",
            encoding="utf-8",
        )

        return TTPResult(
            ok=True,
            output=f"wrote {len(events)} synthetic cloud account event(s) to {marker_path}",
            artifacts=[str(marker_path)],
            started_at=started,
            finished_at=time.time(),
            extra={
                "provider": provider,
                "username": username,
                "account_id": account_id,
                "source_ip": source_ip,
                "event_count": len(events),
                "events": event_names,
                "marker": str(marker_path),
            },
        )

    def cleanup(self, params: dict[str, Any]) -> TTPResult:
        marker_dir = Path(params.get("marker_dir", "data/sim_markers"))
        marker_path = marker_dir / _MARKER_NAME
        if marker_path.exists():
            marker_path.unlink()
        return TTPResult(ok=True, output="cloud account marker removed", started_at=time.time(), finished_at=time.time())

    def sigma_rule(self) -> dict[str, Any]:
        return {
            "title": "Valid Cloud Account Abuse (APT Simulator T1078.004)",
            "id": "b1078004-0000-0000-0000-000000107804",
            "status": "experimental",
            "description": (
                "Detects simulated use of a valid AWS identity through console login, "
                "STS identity checks, role assumption, or initial storage enumeration."
            ),
            "references": ["https://attack.mitre.org/techniques/T1078/004/"],
            "tags": [
                "attack.initial_access",
                "attack.persistence",
                "attack.privilege_escalation",
                "attack.defense_evasion",
                "attack.t1078.004",
            ],
            "logsource": {"product": "aws", "service": "cloudtrail"},
            "detection": {
                "selection_console": {
                    "eventName": "ConsoleLogin",
                    "responseElements.ConsoleLogin": "Success",
                },
                "selection_api": {
                    "eventName": ["GetCallerIdentity", "AssumeRole", "ListBuckets"],
                    "userIdentity.type": ["IAMUser", "AssumedRole"],
                },
                "condition": "1 of selection_*",
            },
            "falsepositives": ["Cloud inventory jobs", "Administrator break-glass activity"],
            "level": "high",
        }

    def synthetic_events(self, params: dict[str, Any], result: Any = None) -> list[dict[str, Any]]:
        username = str(params.get("username", "lab-valid-user"))
        account_id = str(params.get("account_id", "123456789012"))
        source_ip = str(params.get("source_ip", "198.51.100.23"))
        ts = time.time()
        return [
            _event("GetCallerIdentity", username, account_id, source_ip, ts),
            _event("AssumeRole", username, account_id, source_ip, ts + 1),
        ]


registry.register(T1078004CloudAccountAbuse())
