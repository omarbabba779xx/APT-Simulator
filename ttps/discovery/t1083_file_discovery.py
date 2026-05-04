"""T1083 — File and Directory Discovery.

Read-only. Walks configured paths up to a depth limit, returns counts + sample
filenames. Mirrors what a recon stage would do without exfil.
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from ..base import TTP, TTPResult, registry


DEFAULT_PATHS = ["%USERPROFILE%/Documents", "%USERPROFILE%/Desktop", "/tmp", "/home"]


class T1083FileDiscovery(TTP):
    attack_id = "T1083"
    name = "File and Directory Discovery"
    description = "Enumerate files in configured paths (read-only)"
    tactic = "discovery"

    def run(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        paths: list[str] = params.get("paths") or DEFAULT_PATHS
        max_depth: int = int(params.get("max_depth", 2))
        max_entries: int = int(params.get("max_entries", 200))

        seen: list[str] = []
        for raw in paths:
            expanded = os.path.expandvars(os.path.expanduser(raw))
            base = Path(expanded)
            if not base.exists():
                continue
            for root, _dirs, files in os.walk(base):
                rel_depth = len(Path(root).relative_to(base).parts)
                if rel_depth > max_depth:
                    continue
                for f in files:
                    seen.append(str(Path(root) / f))
                    if len(seen) >= max_entries:
                        break
                if len(seen) >= max_entries:
                    break
            if len(seen) >= max_entries:
                break

        return TTPResult(
            ok=True,
            output=f"discovered {len(seen)} entries across {len(paths)} paths",
            artifacts=seen[:50],
            started_at=started,
            finished_at=time.time(),
            extra={"total": len(seen), "sample_size": min(50, len(seen))},
        )


    def sigma_rule(self) -> dict[str, Any]:
        return {
            "title": "Recursive File and Directory Enumeration (APT Simulator T1083)",
            "id": "a1083000-0000-0000-0000-000000001083",
            "status": "experimental",
            "description": "Detects bulk directory enumeration patterns from a single process.",
            "references": ["https://attack.mitre.org/techniques/T1083"],
            "tags": ["attack.discovery", "attack.t1083"],
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection_win": {
                    "CommandLine|contains|all": ["dir", "/s"],
                },
                "selection_posix": {
                    "CommandLine|contains": ["find ", "ls -R", "tree "],
                },
                "condition": "1 of selection_*",
            },
            "falsepositives": ["Backup software", "Search indexing"],
            "level": "low",
        }

    def synthetic_events(self, params, result=None):  # type: ignore[override]
        return [
            {"category": "process_creation", "CommandLine": "dir /s C:\\Users"},
            {"category": "process_creation", "CommandLine": "find /home -type f"},
        ]


registry.register(T1083FileDiscovery())
