"""T1055 — Process Injection (simulation only).

Simulation: identifies processes that are common injection targets
(explorer.exe, notepad.exe, svchost.exe, etc.) using stdlib `os`/`pathlib`,
then writes a report to a sim-marker file.  No actual memory write or code
injection is performed — only the reconnaissance/target-selection phase is
simulated.

Uses psutil if available; falls back to a fixed list of synthetic process
entries so the TTP works in minimal environments without psutil installed.

Defensive value: validates detection of process-enumeration activity that
precedes injection, and ensures SIEM rules fire on suspicious ReadProcessMemory
/ OpenProcess audit events targeting high-value processes.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from ..base import TTP, TTPResult, registry

_INJECTION_TARGETS = {"explorer.exe", "notepad.exe", "svchost.exe", "lsass.exe", "winlogon.exe"}
_MARKER_NAME = "t1055_injection_targets.json"

_SYNTHETIC_PROCS = [
    {"pid": 4, "name": "System", "exe": None},
    {"pid": 728, "name": "svchost.exe", "exe": "C:\\Windows\\System32\\svchost.exe"},
    {"pid": 1234, "name": "explorer.exe", "exe": "C:\\Windows\\explorer.exe"},
    {"pid": 5678, "name": "notepad.exe", "exe": "C:\\Windows\\System32\\notepad.exe"},
]


def _enumerate_processes() -> list[dict[str, Any]]:
    """Return list of running processes, using psutil if available."""
    try:
        import psutil  # type: ignore[import]
        procs = []
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                info = proc.info
                procs.append({
                    "pid": info["pid"],
                    "name": info.get("name") or "",
                    "exe": info.get("exe"),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return procs
    except ImportError:
        return _SYNTHETIC_PROCS


class T1055ProcessInjectionSim(TTP):
    attack_id = "T1055"
    name = "Process Injection Target Enumeration (sim)"
    description = "Enumerate high-value processes that are typical injection targets"
    tactic = "defense_evasion"
    supported_platforms = ("windows", "linux", "darwin")

    def run(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        extra_targets: set[str] = set(params.get("extra_targets", []))
        all_targets = _INJECTION_TARGETS | extra_targets
        marker_dir = Path(params.get("marker_dir", "data/sim_markers"))
        marker_dir.mkdir(parents=True, exist_ok=True)
        marker_path = marker_dir / _MARKER_NAME

        all_procs = _enumerate_processes()
        targets_found = [
            p for p in all_procs
            if (p.get("name") or "").lower() in {t.lower() for t in all_targets}
        ]

        report = {
            "_sim": "APT_SIM_DEFENSE_EVASION_T1055",
            "total_processes_scanned": len(all_procs),
            "injection_targets_found": targets_found,
            "target_names": list(all_targets),
        }
        marker_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

        return TTPResult(
            ok=True,
            output=(
                f"scanned {len(all_procs)} processes, "
                f"found {len(targets_found)} injection targets → {marker_path}"
            ),
            artifacts=[str(marker_path)],
            started_at=started,
            finished_at=time.time(),
            extra=report,
        )

    def cleanup(self, params: dict[str, Any]) -> TTPResult:
        marker_dir = Path(params.get("marker_dir", "data/sim_markers"))
        marker_path = marker_dir / _MARKER_NAME
        if marker_path.exists():
            marker_path.unlink()
        return TTPResult(ok=True, output="marker removed", started_at=time.time(), finished_at=time.time())

    def sigma_rule(self) -> dict[str, Any]:
        return {
            "title": "Suspicious Process Injection Target Enumeration (APT Simulator T1055)",
            "id": "b1055000-0000-0000-0000-000000001055",
            "status": "experimental",
            "description": (
                "Detects OpenProcess calls or process-list enumeration targeting "
                "high-value processes (lsass, explorer, svchost), a common precursor "
                "to process injection."
            ),
            "references": ["https://attack.mitre.org/techniques/T1055"],
            "tags": ["attack.defense_evasion", "attack.privilege_escalation", "attack.t1055"],
            "logsource": {"category": "process_access", "product": "windows"},
            "detection": {
                "selection": {
                    "TargetImage|endswith": [
                        "\\lsass.exe",
                        "\\explorer.exe",
                        "\\svchost.exe",
                        "\\winlogon.exe",
                    ],
                    "GrantedAccess|contains": ["0x1010", "0x1038", "0x1fffff"],
                },
                "filter_legitimate": {
                    "SourceImage|endswith": [
                        "\\MsMpEng.exe",
                        "\\svchost.exe",
                        "\\csrss.exe",
                    ],
                },
                "condition": "selection and not filter_legitimate",
            },
            "falsepositives": ["AV/EDR products legitimately reading process memory"],
            "level": "high",
        }

    def synthetic_events(self, params: dict[str, Any], result: Any = None) -> list[dict[str, Any]]:
        return [
            {
                "category": "process_access",
                "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                "SourceImage": "C:\\Windows\\System32\\cmd.exe",
                "GrantedAccess": "0x1010",
            },
            {
                "category": "process_access",
                "TargetImage": "C:\\Windows\\explorer.exe",
                "SourceImage": "C:\\Windows\\System32\\powershell.exe",
                "GrantedAccess": "0x1038",
            },
        ]


registry.register(T1055ProcessInjectionSim())
