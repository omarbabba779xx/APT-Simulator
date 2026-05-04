"""T1005 — Data from Local System (collection reconnaissance).

Read-only file metadata scan. Searches the user's home directory for files
matching sensitive filename patterns (credentials, keys, documents, databases)
and returns paths + sizes only — **never reads file content**.

This mirrors exactly what an adversary does after initial access: locate
high-value files before staging and exfiltration.

Safety guarantees:
- Zero file content read.
- Bounded by max_entries and max_depth.
- Only searches within user home directory tree.
- Excludes the simulator's own artifact directory.
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from ..base import TTP, TTPResult, registry


# Sensitive filename patterns (no content, metadata only).
SENSITIVE_PATTERNS: list[str] = [
    "*.pem", "*.key", "*.pfx", "*.p12", "*.cer", "*.crt",
    "id_rsa", "id_ed25519", "id_dsa", "id_ecdsa",
    "*.kdbx", "*.kdb",
    "*.rdp",
    "*.ppk",
    "*password*", "*passwd*", "*credential*", "*secret*",
    "*.env", ".env",
    "*.aws", "credentials",
    "*.ovpn",
    "shadow", "*.shadow",
]


def _is_excluded(path: Path, exclude_dir: Path) -> bool:
    try:
        path.relative_to(exclude_dir)
        return True
    except ValueError:
        return False


def _walk_limited(
    root: Path,
    patterns: list[str],
    max_depth: int,
    max_entries: int,
    exclude_dir: Path,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []

    def _recurse(current: Path, depth: int) -> None:
        if depth > max_depth or len(results) >= max_entries:
            return
        try:
            entries = list(current.iterdir())
        except PermissionError:
            return
        for entry in entries:
            if len(results) >= max_entries:
                break
            if _is_excluded(entry, exclude_dir):
                continue
            if entry.is_file() and not entry.is_symlink():
                name = entry.name.lower()
                for pat in patterns:
                    if entry.match(pat):
                        try:
                            size = entry.stat().st_size
                        except OSError:
                            size = -1
                        results.append({"path": str(entry), "size_bytes": size,
                                         "pattern": pat})
                        break
            elif entry.is_dir() and not entry.is_symlink():
                _recurse(entry, depth + 1)

    _recurse(root, 0)
    return results


class T1005DataFromLocalSystem(TTP):
    attack_id = "T1005"
    name = "Data from Local System"
    description = "Enumerate sensitive files (keys, creds, docs) by name pattern — metadata only, no content read"
    tactic = "collection"
    supported_platforms = ("windows", "linux", "darwin")

    def run(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        max_depth = int(params.get("max_depth", 4))
        max_entries = min(int(params.get("max_entries", 100)), 500)
        root = Path(params.get("root", os.path.expanduser("~")))
        exclude_dir = Path(os.environ.get("APT_SIM_MARKER_DIR", "data/sim_artifacts")).resolve()

        if not root.exists():
            return TTPResult(ok=False, error=f"root path does not exist: {root}",
                             started_at=started, finished_at=time.time())

        try:
            hits = _walk_limited(root, SENSITIVE_PATTERNS, max_depth, max_entries, exclude_dir)
        except Exception as exc:
            return TTPResult(ok=False, error=str(exc), started_at=started, finished_at=time.time())

        return TTPResult(
            ok=True,
            output=f"found {len(hits)} sensitive file(s) under {root} (metadata only, no content read)",
            started_at=started,
            finished_at=time.time(),
            extra={"root": str(root), "hit_count": len(hits), "hits": hits[:20]},
        )

    def sigma_rule(self) -> dict[str, Any]:
        return {
            "title": "Sensitive File Search from Local System (APT Simulator T1005)",
            "id": "a1005000-0000-0000-0000-000000001005",
            "status": "experimental",
            "description": (
                "Detects filesystem enumeration targeting credential and key files — "
                "a pre-exfiltration collection step used by most APT groups."
            ),
            "references": ["https://attack.mitre.org/techniques/T1005"],
            "tags": ["attack.collection", "attack.t1005"],
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection_win": {
                    "CommandLine|contains": [".pem", ".key", ".pfx", "password", "credential"],
                },
                "selection_posix": {
                    "CommandLine|contains": ["id_rsa", ".pem", ".key", "password"],
                },
                "condition": "1 of selection_*",
            },
            "falsepositives": ["Developer tooling", "certificate management scripts"],
            "level": "medium",
        }

    def synthetic_events(self, params: dict[str, Any], result: Any = None) -> list[dict[str, Any]]:
        return [
            {"category": "process_creation",
             "CommandLine": "dir /s /b C:\\Users\\*password*.txt C:\\Users\\*.pem C:\\Users\\*.key"},
            {"category": "process_creation",
             "CommandLine": "find /home -name id_rsa -o -name *.pem -o -name *password*"},
        ]


registry.register(T1005DataFromLocalSystem())
