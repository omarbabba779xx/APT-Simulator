"""T1027 — Obfuscated Files or Information.

Writes a marker file containing benign payload encoded with base64 + single-byte
XOR. Output goes to a sim-marker directory; never touches user files. Generates
the high-entropy artifact pattern that detection tools look for.
"""
from __future__ import annotations

import base64
import os
import secrets
import time
from pathlib import Path
from typing import Any

from ..base import TTP, TTPResult, registry


SIM_MARKER_DIR = Path(os.environ.get("APT_SIM_MARKER_DIR", "data/sim_artifacts"))


class T1027Obfuscation(TTP):
    attack_id = "T1027"
    name = "Obfuscated Files or Information (sim)"
    description = "Writes a base64+XOR-encoded benign payload to the sim marker directory"
    tactic = "defense_evasion"

    def run(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        size = max(64, min(int(params.get("size_bytes", 4096)), 65536))
        SIM_MARKER_DIR.mkdir(parents=True, exist_ok=True)

        plaintext = b"APT_SIMULATOR_BENIGN_MARKER " * (size // 28 + 1)
        plaintext = plaintext[:size]
        xor_key = secrets.token_bytes(1)
        xored = bytes(b ^ xor_key[0] for b in plaintext)
        encoded = base64.b64encode(xored)

        out_path = SIM_MARKER_DIR / f"obf_{int(time.time())}.b64"
        out_path.write_bytes(encoded)

        return TTPResult(
            ok=True,
            output=f"wrote {len(encoded)} encoded bytes to {out_path}",
            artifacts=[str(out_path)],
            started_at=started,
            finished_at=time.time(),
            extra={"xor_key": xor_key.hex(), "size": len(encoded)},
        )

    def cleanup(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        if not SIM_MARKER_DIR.exists():
            return TTPResult(ok=True, output="nothing to clean", started_at=started, finished_at=time.time())
        removed = 0
        for f in SIM_MARKER_DIR.glob("obf_*.b64"):
            f.unlink()
            removed += 1
        return TTPResult(
            ok=True,
            output=f"removed {removed} obfuscated marker files",
            started_at=started,
            finished_at=time.time(),
        )

    def sigma_rule(self) -> dict[str, Any]:
        return {
            "title": "High-Entropy Encoded Artifact Drop (APT Simulator T1027)",
            "id": "a1027000-0000-0000-0000-000000001027",
            "status": "experimental",
            "description": "Detects creation of files with .b64 extension or high-entropy content under unusual paths.",
            "references": ["https://attack.mitre.org/techniques/T1027"],
            "tags": ["attack.defense_evasion", "attack.t1027"],
            "logsource": {"category": "file_event"},
            "detection": {
                "selection": {
                    "TargetFilename|endswith": [".b64", ".enc", ".obf"],
                },
                "condition": "selection",
            },
            "falsepositives": ["Backup tools producing .b64 archives"],
            "level": "medium",
        }

    def synthetic_events(self, params, result=None):  # type: ignore[override]
        artifacts = (result.artifacts if result else None) or [str(SIM_MARKER_DIR / "obf_demo.b64")]
        return [{"category": "file_event", "TargetFilename": str(artifacts[0])}]


registry.register(T1027Obfuscation())
