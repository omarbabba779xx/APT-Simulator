"""Backup export helpers for production-readiness drills."""
from __future__ import annotations

import io
import json
import time
import zipfile
from pathlib import Path
from typing import Any

from .api.state import AppState
from .core.audit import AuditLog


def backup_manifest(state: AppState) -> dict[str, Any]:
    db_path = Path(state.config.orchestrator.db_path)
    audit_path = Path(state.config.orchestrator.audit_dir) / "audit.jsonl"
    audit_ok, broken_line = AuditLog(audit_path).verify()
    return {
        "created_at": time.time(),
        "database": {
            "path": str(db_path),
            "exists": db_path.exists(),
            "bytes": db_path.stat().st_size if db_path.exists() else 0,
        },
        "audit": {
            "path": str(audit_path),
            "exists": audit_path.exists(),
            "bytes": audit_path.stat().st_size if audit_path.exists() else 0,
            "hash_chain_valid": audit_ok,
            "broken_line": broken_line,
        },
        "retention_days": state.config.orchestrator.retention_days,
        "restore_rehearsal": [
            "extract into an isolated lab",
            "restore database file",
            "restore audit JSONL",
            "run python -m orchestrator.main verify-audit <audit.jsonl>",
            "start orchestrator against restored config",
            "run benchmarks/api_smoke.md checks",
        ],
        "excluded": ["keys/", "raw secret material", "external customer artifacts"],
    }


def build_backup_zip(state: AppState) -> bytes:
    manifest = backup_manifest(state)
    db_path = Path(state.config.orchestrator.db_path)
    audit_path = Path(state.config.orchestrator.audit_dir) / "audit.jsonl"
    bundle = io.BytesIO()
    with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("backup_manifest.json", json.dumps(manifest, indent=2, sort_keys=True))
        if db_path.exists():
            archive.write(db_path, "data/apt_sim.db")
        if audit_path.exists():
            archive.write(audit_path, "data/audit/audit.jsonl")
        if Path("config/default.yaml").exists():
            archive.write("config/default.yaml", "config/default.yaml")
        if Path("config/cloud_sandbox_profiles.yaml").exists():
            archive.write(
                "config/cloud_sandbox_profiles.yaml",
                "config/cloud_sandbox_profiles.yaml",
            )
        archive.writestr(
            "README.md",
            "Backup contains non-secret runtime state for restore rehearsal. "
            "Secret material and external customer evidence are intentionally excluded.\n",
        )
    return bundle.getvalue()
