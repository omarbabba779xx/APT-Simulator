"""T1048 — Exfiltration Over Alternative Protocol (simulation only).

Simulation: encodes a benign payload with base64 and writes it to a
sim-marker file, mimicking the artifact produced when an adversary tunnels
data over a non-standard protocol (e.g. DNS TXT, ICMP payload, HTTPS with
custom headers).  No actual network traffic is generated.

Defensive value: validates DLP rules that trigger on base64-heavy or
unusually-structured outbound streams, and SIEM rules that detect data staging
before exfiltration over alternative channels.
"""
from __future__ import annotations

import base64
import hashlib
import time
from pathlib import Path
from typing import Any

from ..base import TTP, TTPResult, registry

_SIM_HEADER = b"APT_SIM_EXFIL_ALT_PROTO_T1048\x00"
_MARKER_NAME = "t1048_exfil_alt.b64"
_DEFAULT_PAYLOAD_BYTES = 256


class T1048ExfilAltProtocol(TTP):
    attack_id = "T1048"
    name = "Exfiltration Over Alternative Protocol (sim)"
    description = "Encode and stage a benign payload marker simulating data exfiltration over a non-standard channel"
    tactic = "exfiltration"
    supported_platforms = ("windows", "linux", "darwin")

    def run(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        payload_bytes: int = min(int(params.get("payload_bytes", _DEFAULT_PAYLOAD_BYTES)), 4096)
        protocol: str = str(params.get("protocol", "dns-txt"))
        marker_dir = Path(params.get("marker_dir", "data/sim_markers"))
        marker_dir.mkdir(parents=True, exist_ok=True)
        marker_path = marker_dir / _MARKER_NAME

        # Build benign payload: header + zero-fill (never real user data)
        raw = _SIM_HEADER + b"\x00" * max(0, payload_bytes - len(_SIM_HEADER))
        encoded = base64.b64encode(raw).decode("ascii")
        sha256 = hashlib.sha256(raw).hexdigest()

        marker_path.write_text(
            f"# APT Simulator T1048 - protocol={protocol} sha256={sha256}\n{encoded}\n",
            encoding="utf-8",
        )

        return TTPResult(
            ok=True,
            output=(
                f"staged {len(raw)}B payload via simulated {protocol} channel "
                f"({len(encoded)} base64 chars) → {marker_path}"
            ),
            artifacts=[str(marker_path)],
            started_at=started,
            finished_at=time.time(),
            extra={
                "protocol": protocol,
                "raw_bytes": len(raw),
                "encoded_chars": len(encoded),
                "sha256": sha256,
                "marker": str(marker_path),
            },
        )

    def cleanup(self, params: dict[str, Any]) -> TTPResult:
        marker_dir = Path(params.get("marker_dir", "data/sim_markers"))
        marker_path = marker_dir / _MARKER_NAME
        if marker_path.exists():
            marker_path.unlink()
        return TTPResult(ok=True, output="marker removed", started_at=time.time(), finished_at=time.time())

    def sigma_rule(self) -> dict[str, Any]:
        return {
            "title": "Exfiltration Over Alternative Protocol (APT Simulator T1048)",
            "id": "b1048000-0000-0000-0000-000000001048",
            "status": "experimental",
            "description": (
                "Detects data staging artifacts indicative of exfiltration over "
                "non-standard protocols (DNS TXT, ICMP, custom HTTPS headers)."
            ),
            "references": ["https://attack.mitre.org/techniques/T1048"],
            "tags": ["attack.exfiltration", "attack.t1048"],
            "logsource": {"category": "dns"},
            "detection": {
                "selection_dns_txt": {
                    "QueryType": "TXT",
                    "QueryLength|gt": 50,
                },
                "selection_icmp_large": {
                    "Protocol": "ICMP",
                    "Length|gt": 128,
                },
                "condition": "selection_dns_txt or selection_icmp_large",
            },
            "falsepositives": ["SPF/DKIM/DMARC DNS TXT lookups", "Legitimate ICMP diagnostics"],
            "level": "high",
        }

    def synthetic_events(self, params: dict[str, Any], result: Any = None) -> list[dict[str, Any]]:
        protocol = str(params.get("protocol", "dns-txt"))
        return [
            {
                "category": "dns",
                "QueryType": "TXT",
                "QueryName": "c2.example-lab.internal",
                "QueryLength": 512,
                "_sim_protocol": protocol,
            }
        ]


registry.register(T1048ExfilAltProtocol())
