"""Importer readiness for official defensive content sources."""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

import ttps  # noqa: F401
from ttps.base import registry

from .attack_sync import DEFAULT_SNAPSHOT_PATH, drift_status, load_snapshot


OFFICIAL_IMPORTERS: tuple[dict[str, str], ...] = (
    {
        "name": "MITRE ATT&CK STIX",
        "source_url": "https://github.com/mitre/cti",
        "local_command": "python -m orchestrator.attack_sync snapshot --out config/attack_enterprise_snapshot.json",
        "mode": "snapshot_sync",
    },
    {
        "name": "ATT&CK Emulation Library",
        "source_url": "https://github.com/attackevals/ael",
        "local_command": "python -m orchestrator.emulation_plan_import convert <path> --out-dir scenarios/ael",
        "mode": "safe_metadata_to_scenario",
    },
    {
        "name": "Atomic Red Team",
        "source_url": "https://github.com/redcanaryco/atomic-red-team",
        "local_command": "python -m orchestrator.art_import convert <path> --out scenarios/art_imported.yaml",
        "mode": "safe_reference_mapping",
    },
    {
        "name": "Cloud Simulation Reference",
        "source_url": "https://github.com/DataDog/stratus-red-team",
        "local_command": "Use local cloud/cloud_k8s_lab marker-only packs; no cloud provider calls by default.",
        "mode": "local_marker_only_pack",
    },
    {
        "name": "Detection Rule Corpus Comparison",
        "source_url": "https://github.com/SigmaHQ/sigma",
        "local_command": "python -m orchestrator.detection_workbench compare <rule-directory>",
        "mode": "coverage_comparison",
    },
)


def _scenario_tag_counts(scenarios: dict[str, Any]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for scenario in scenarios.values():
        for tag in getattr(scenario, "tags", []) or []:
            counts[str(tag)] += 1
    return counts


def _pack_counts() -> Counter[str]:
    counts: Counter[str] = Counter()
    for ttp in registry.all().values():
        counts[str(getattr(ttp, "pack", "core"))] += 1
    return counts


def build_import_center(scenarios: dict[str, Any]) -> dict[str, object]:
    tag_counts = _scenario_tag_counts(scenarios)
    pack_counts = _pack_counts()
    snapshot = load_snapshot(DEFAULT_SNAPSHOT_PATH)
    drift = drift_status(snapshot)
    ael_count = sum(1 for item in scenarios.values() if "ael_import" in (getattr(item, "tags", []) or []))
    art_count = sum(1 for item in scenarios.values() if "art_import" in (getattr(item, "tags", []) or []))
    cloud_pack_count = pack_counts.get("cloud", 0) + pack_counts.get("cloud_k8s_lab", 0)
    importer_rows = []
    for importer in OFFICIAL_IMPORTERS:
        name = importer["name"]
        if name == "MITRE ATT&CK STIX":
            loaded = Path(DEFAULT_SNAPSHOT_PATH).exists()
            imported_items = int(snapshot.get("active_count", 0))
            status = "synced" if loaded and drift.get("status") == "synced" else "needs_sync"
        elif name == "ATT&CK Emulation Library":
            loaded = ael_count > 0
            imported_items = ael_count
            status = "loaded" if loaded else "ready"
        elif name == "Atomic Red Team":
            loaded = art_count > 0
            imported_items = art_count
            status = "loaded" if loaded else "ready"
        elif name == "Cloud Simulation Reference":
            loaded = cloud_pack_count > 0
            imported_items = cloud_pack_count
            status = "loaded" if loaded else "ready"
        else:
            loaded = True
            imported_items = len(registry.all())
            status = "ready"
        importer_rows.append(
            {
                **importer,
                "status": status,
                "loaded": loaded,
                "imported_items": imported_items,
                "safety": "dry-run and marker-only by default",
            }
        )
    loaded_count = sum(1 for item in importer_rows if item["loaded"])
    return {
        "importer_count": len(importer_rows),
        "loaded_importers": loaded_count,
        "readiness_score": round((loaded_count / len(importer_rows)) * 100, 2) if importer_rows else 0,
        "importers": importer_rows,
        "local_content": {
            "scenarios_loaded": len(scenarios),
            "ael_scenarios": ael_count,
            "atomic_scenarios": art_count,
            "cloud_pack_ttps": cloud_pack_count,
            "registered_ttps": len(registry.all()),
            "tag_counts": dict(sorted(tag_counts.items())),
            "pack_counts": dict(sorted(pack_counts.items())),
        },
        "attack_drift": {
            "status": drift.get("status"),
            "coverage_label": drift.get("coverage_label"),
            "official_active": drift.get("official_active"),
            "local_base_ids": drift.get("local_base_ids"),
            "missing_count": drift.get("missing_count"),
            "deprecated_present_count": drift.get("deprecated_present_count"),
            "revoked_present_count": drift.get("revoked_present_count"),
        },
        "boundaries": [
            "Importers use metadata and local safe equivalents.",
            "Source commands from external offensive test libraries are not executed.",
            "Cloud provider APIs are not contacted by marker-only cloud simulations.",
        ],
    }
