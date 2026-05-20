"""T1560 — Archive Collected Data (simulation only).

Simulation: creates a zip archive containing benign sim-marker files inside
the sim-marker directory.  This mimics the staging step an adversary takes
before exfiltrating collected data.

Defensive value: validates file-activity rules (zip creation on sensitive
hosts), DLP rules that detect archive creation, and UEBA baselines that
flag unusual archiving activity.
"""
from __future__ import annotations

import io
import time
import zipfile
from pathlib import Path
from typing import Any

from ..base import TTP, TTPResult, registry

_MARKER_ARCHIVE = "t1560_staged_data.zip"
_DUMMY_FILES = [
    ("financials_q4.csv", b"APT_SIM_DUMMY_DATA,field1,field2\n1,benign,placeholder\n"),
    ("employee_list.txt", b"APT_SIM_DUMMY_DATA\nuser1\nuser2\nuser3\n"),
    ("network_diagram.xml", b"<?xml version='1.0'?><APT_SIM_DUMMY/>\n"),
]


class T1560ArchiveCollected(TTP):
    attack_id = "T1560"
    name = "Archive Collected Data (sim)"
    description = "Create a zip archive of benign marker files simulating adversary data staging"
    tactic = "collection"
    supported_platforms = ("windows", "linux", "darwin")

    def run(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        marker_dir = Path(params.get("marker_dir", "data/sim_markers"))
        marker_dir.mkdir(parents=True, exist_ok=True)
        archive_path = marker_dir / _MARKER_ARCHIVE

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            for name, content in _DUMMY_FILES:
                zf.writestr(name, content)
        archive_bytes = buf.getvalue()
        archive_path.write_bytes(archive_bytes)

        return TTPResult(
            ok=True,
            output=(
                f"created archive {archive_path} "
                f"({len(archive_bytes)} bytes, {len(_DUMMY_FILES)} entries)"
            ),
            artifacts=[str(archive_path)],
            started_at=started,
            finished_at=time.time(),
            extra={
                "archive": str(archive_path),
                "size_bytes": len(archive_bytes),
                "file_count": len(_DUMMY_FILES),
                "files": [name for name, _ in _DUMMY_FILES],
            },
        )

    def cleanup(self, params: dict[str, Any]) -> TTPResult:
        marker_dir = Path(params.get("marker_dir", "data/sim_markers"))
        archive_path = marker_dir / _MARKER_ARCHIVE
        if archive_path.exists():
            archive_path.unlink()
        return TTPResult(ok=True, output="archive removed", started_at=time.time(), finished_at=time.time())

    def sigma_rule(self) -> dict[str, Any]:
        return {
            "title": "Suspicious Archive Creation — Data Staging (APT Simulator T1560)",
            "id": "b1560000-0000-0000-0000-000000001560",
            "status": "stable",
            "description": (
                "Detects zip/rar/7z archive creation in temp or staging directories "
                "by non-standard processes, indicative of data collection before exfiltration."
            ),
            "references": ["https://attack.mitre.org/techniques/T1560"],
            "tags": ["attack.collection", "attack.t1560", "attack.t1560.001"],
            "logsource": {"category": "file_event", "product": "windows"},
            "detection": {
                "selection": {
                    "TargetFilename|endswith": [".zip", ".7z", ".rar", ".tar.gz"],
                    "TargetFilename|contains": ["\\AppData\\", "\\Temp\\", "\\Users\\Public\\"],
                },
                "filter_legitimate": {
                    "Image|endswith": ["\\7zFM.exe", "\\WinRAR.exe", "\\7z.exe"],
                    "User|contains": ["SYSTEM"],
                },
                "condition": "selection and not filter_legitimate",
            },
            "falsepositives": ["Legitimate archiving tools run by users", "Backup software"],
            "level": "medium",
        }

    def synthetic_events(self, params: dict[str, Any], result: Any = None) -> list[dict[str, Any]]:
        return [
            {
                "category": "file_event",
                "TargetFilename": "C:\\Users\\Public\\" + _MARKER_ARCHIVE,
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "User": "CORP\\jsmith",
            }
        ]


registry.register(T1560ArchiveCollected())
