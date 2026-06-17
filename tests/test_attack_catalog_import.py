from __future__ import annotations

import json
from pathlib import Path

from orchestrator.attack_catalog_import import catalog_from_stix


def test_catalog_from_stix_generates_marker_stub(tmp_path: Path) -> None:
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "attack-pattern",
                "name": "Example Technique",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T9999"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "discovery"}
                ],
            }
        ],
    }
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    catalog = catalog_from_stix(str(path))
    assert catalog["ttps"][0]["id"] == "T9999:CATALOG_STUB"
    assert catalog["ttps"][0]["safety_tier"] == "marker-only"
