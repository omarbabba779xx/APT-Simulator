"""Import ATT&CK STIX attack-patterns into marker-only catalog YAML.

This creates safe coverage stubs. It does not execute external tools and it
does not generate offensive payloads.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import typer
import yaml

from .attack_sync import DEFAULT_STIX_URL, EXCLUDED_ATTACK_IDS, _external_attack_id, _load_json_source, _primary_tactic


app = typer.Typer(no_args_is_help=True)


@app.callback()
def _root() -> None:
    """ATT&CK catalog import tools."""


def _load_bundle(source: str) -> dict[str, Any]:
    return _load_json_source(source)


def catalog_from_stix(source: str, pack: str = "attack_enterprise") -> dict[str, Any]:
    bundle = _load_bundle(source)
    items: list[dict[str, Any]] = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        attack_id = _external_attack_id(obj)
        if not attack_id:
            continue
        if attack_id in EXCLUDED_ATTACK_IDS:
            continue
        slug = attack_id.replace(".", "_")
        name = str(obj.get("name", attack_id))
        tactic = _primary_tactic(obj)
        items.append(
            {
                "id": f"{attack_id}:CATALOG_STUB",
                "attack_id": attack_id,
                "name": f"{name} Marker",
                "description": f"Marker-only coverage stub for {name}.",
                "tactic": tactic,
                "platforms": ["windows", "linux", "darwin"],
                "safety_tier": "marker-only",
                "artifact": f"{slug.lower()}_catalog_stub.json",
                "sigma": {
                    "title": f"{name} Marker",
                    "id": f"stub-{slug.lower()}",
                    "status": "experimental",
                    "logsource": {"category": "generic"},
                    "detection": {
                        "selection": {"attack_id": attack_id, "_sim": "APT_SIM_CATALOG_TTP"},
                        "condition": "selection",
                    },
                    "falsepositives": ["simulator-generated marker events"],
                    "level": "informational",
                },
                "synthetic_events": [
                    {
                        "category": "generic",
                        "attack_id": attack_id,
                        "technique_name": name,
                        "_sim": "APT_SIM_CATALOG_TTP",
                    }
                ],
            }
        )
    return {"pack": pack, "ttps": sorted(items, key=lambda item: item["attack_id"])}


@app.command()
def import_stix(
    source: str = typer.Option(DEFAULT_STIX_URL, help="STIX JSON path or URL"),
    out: str = typer.Option("ttps/catalog/attack_enterprise.yaml"),
    pack: str = typer.Option("attack_enterprise"),
    limit: int = typer.Option(0, help="Optional max techniques for test imports"),
) -> None:
    """Generate marker-only catalog entries from ATT&CK Enterprise STIX."""
    data = catalog_from_stix(source, pack=pack)
    if limit > 0:
        data["ttps"] = data["ttps"][:limit]
    out_path = Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    typer.echo(f"Wrote {len(data['ttps'])} catalog TTP(s) to {out_path}")


if __name__ == "__main__":
    app()
