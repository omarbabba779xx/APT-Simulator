"""T1070.004 — Indicator Removal: File Deletion (sim).

Deletes only files inside the simulator's marker directory. Refuses any path
outside that directory. Produces the file-deletion telemetry that real T1070
abuse generates, without risk of removing user data.
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from ..base import TTP, TTPResult, registry


SIM_MARKER_DIR = Path(os.environ.get("APT_SIM_MARKER_DIR", "data/sim_artifacts")).resolve()


def _within_marker_dir(p: Path) -> bool:
    try:
        p.resolve().relative_to(SIM_MARKER_DIR)
        return True
    except ValueError:
        return False


class T1070FileDeletion(TTP):
    attack_id = "T1070.004"
    name = "Indicator Removal: File Deletion (sim)"
    description = "Deletes simulator marker files only; rejects paths outside marker dir"
    tactic = "defense_evasion"

    def run(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        SIM_MARKER_DIR.mkdir(parents=True, exist_ok=True)

        # Default: drop a marker, then delete it — round trip in one step.
        target = params.get("path")
        if target is None:
            marker = SIM_MARKER_DIR / f"to_delete_{int(time.time())}.tmp"
            marker.write_text("apt-sim marker", encoding="utf-8")
            target_path = marker
        else:
            target_path = Path(str(target))
            if not _within_marker_dir(target_path):
                return TTPResult(
                    ok=False,
                    error=f"refusing to delete path outside marker dir: {target_path}",
                    started_at=started,
                    finished_at=time.time(),
                )

        if not target_path.exists():
            return TTPResult(ok=True, output="file already absent", started_at=started, finished_at=time.time())
        target_path.unlink()
        return TTPResult(
            ok=True,
            output=f"deleted {target_path}",
            artifacts=[str(target_path)],
            started_at=started,
            finished_at=time.time(),
        )

    def sigma_rule(self) -> dict[str, Any]:
        return {
            "title": "Indicator File Deletion (APT Simulator T1070.004)",
            "id": "a1070004-0000-0000-0000-000000001070",
            "status": "experimental",
            "description": "Detects deletion of files matching simulator artifact naming.",
            "references": ["https://attack.mitre.org/techniques/T1070/004"],
            "tags": ["attack.defense_evasion", "attack.t1070.004"],
            "logsource": {"category": "file_event"},
            "detection": {
                "selection": {
                    "TargetFilename|contains": ["\\sim_artifacts\\to_delete_", "/sim_artifacts/to_delete_"],
                    "EventType": "deletion",
                },
                "condition": "selection",
            },
            "falsepositives": ["Simulator cleanup"],
            "level": "low",
        }

    def synthetic_events(self, params, result=None):  # type: ignore[override]
        path = (result.artifacts[0] if result and result.artifacts else str(SIM_MARKER_DIR / "to_delete_demo.tmp"))
        return [{"category": "file_event", "TargetFilename": path, "EventType": "deletion"}]


registry.register(T1070FileDeletion())
