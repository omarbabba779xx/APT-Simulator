"""T1486 — Data Encrypted for Impact (simulation only).

SAFE. Writes benign marker files to the simulator artifact directory with
``.encrypted`` extensions, simulating the file-creation pattern that
ransomware generates without touching any real user data.

No actual encryption of user data occurs. Marker content is a plaintext
banner. cleanup() removes all generated markers.

Defensive value: validates that alerts fire on .encrypted file creation
events in user directories — the primary ransomware indicator in most SIEM
detection rulesets.
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from ..base import TTP, TTPResult, registry


SIM_MARKER_DIR = Path(os.environ.get("APT_SIM_MARKER_DIR", "data/sim_artifacts"))
MARKER_CONTENT = (
    "APT_SIMULATOR_BENIGN_IMPACT_MARKER\n"
    "This file was created by the APT Simulator for detection validation.\n"
    "No real encryption was performed. Safe to delete.\n"
)


class T1486DataEncryptedSim(TTP):
    attack_id = "T1486"
    name = "Data Encrypted for Impact (sim)"
    description = "Writes benign .encrypted marker files to sim dir to trigger ransomware-impact detection rules"
    tactic = "impact"
    supported_platforms = ("windows", "linux", "darwin")

    def run(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        count = max(1, min(int(params.get("file_count", 5)), 50))
        SIM_MARKER_DIR.mkdir(parents=True, exist_ok=True)

        artifacts: list[str] = []
        ts = int(time.time())
        for i in range(count):
            path = SIM_MARKER_DIR / f"sim_ransom_{ts}_{i:03d}.encrypted"
            try:
                path.write_text(MARKER_CONTENT, encoding="utf-8")
                artifacts.append(str(path))
            except OSError as exc:
                return TTPResult(
                    ok=False,
                    error=f"failed to write marker {path}: {exc}",
                    artifacts=artifacts,
                    started_at=started,
                    finished_at=time.time(),
                )

        return TTPResult(
            ok=True,
            output=f"wrote {len(artifacts)} .encrypted marker file(s) to {SIM_MARKER_DIR}",
            artifacts=artifacts,
            started_at=started,
            finished_at=time.time(),
            extra={"file_count": len(artifacts), "dir": str(SIM_MARKER_DIR)},
        )

    def cleanup(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        if not SIM_MARKER_DIR.exists():
            return TTPResult(ok=True, output="nothing to clean", started_at=started, finished_at=time.time())
        removed = 0
        for f in SIM_MARKER_DIR.glob("sim_ransom_*.encrypted"):
            f.unlink()
            removed += 1
        return TTPResult(
            ok=True,
            output=f"removed {removed} encrypted marker file(s)",
            started_at=started,
            finished_at=time.time(),
        )

    def sigma_rule(self) -> dict[str, Any]:
        return {
            "title": "Mass .encrypted File Creation (APT Simulator T1486)",
            "id": "a1486000-0000-0000-0000-000000001486",
            "status": "experimental",
            "description": (
                "Detects creation of files with .encrypted extension — the primary "
                "indicator of ransomware-style impact. Triggers on the simulator's "
                "benign markers as well as real ransomware."
            ),
            "references": ["https://attack.mitre.org/techniques/T1486"],
            "tags": ["attack.impact", "attack.t1486"],
            "logsource": {"category": "file_event"},
            "detection": {
                "selection": {
                    "TargetFilename|endswith": [".encrypted", ".enc", ".locked", ".crypt"],
                },
                "condition": "selection",
            },
            "falsepositives": ["Legitimate file encryption utilities"],
            "level": "high",
        }

    def synthetic_events(self, params: dict[str, Any], result: Any = None) -> list[dict[str, Any]]:
        if result and result.artifacts:
            sample = result.artifacts[:3]
        else:
            sample = [str(SIM_MARKER_DIR / "sim_ransom_demo_000.encrypted")]
        return [{"category": "file_event", "TargetFilename": p} for p in sample]


registry.register(T1486DataEncryptedSim())
