"""Catalog-backed TTP registration.

Catalog TTPs are marker-only simulations declared in YAML. They are designed
for broad ATT&CK coverage expansion without creating one Python module per
variant.
"""
from __future__ import annotations

import copy
import json
import re
import time
from pathlib import Path
from typing import Any

import yaml

from .base import TTP, TTPResult, registry


CATALOG_DIR = Path(__file__).parent / "catalog"
DEFAULT_SAFETY_TIER = "marker-only"
_REGISTERED = False


def slugify(value: str) -> str:
    """Return a filesystem-safe slug for variant IDs and generated files."""
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def _render_value(value: Any, params: dict[str, Any]) -> Any:
    if isinstance(value, str):
        try:
            return value.format(**params)
        except KeyError:
            return value
    if isinstance(value, list):
        return [_render_value(v, params) for v in value]
    if isinstance(value, dict):
        return {k: _render_value(v, params) for k, v in value.items()}
    return value


def _param_defaults(schema: dict[str, Any]) -> dict[str, Any]:
    defaults: dict[str, Any] = {}
    for key, spec in schema.items():
        if isinstance(spec, dict) and "default" in spec:
            defaults[key] = spec["default"]
    return defaults


class CatalogTTP(TTP):
    """Marker-only TTP generated from a catalog entry."""

    def __init__(self, item: dict[str, Any], source_file: str) -> None:
        self.catalog_id = str(item["id"]).upper()
        self.base_attack_id = str(item.get("attack_id", item["id"])).upper()
        setattr(self, "attack_id", self.catalog_id)
        setattr(self, "name", str(item["name"]))
        setattr(self, "description", str(item.get("description", "Catalog-backed marker-only simulation")))
        setattr(self, "tactic", str(item.get("tactic", "discovery")))
        setattr(
            self,
            "supported_platforms",
            tuple(str(p) for p in item.get("platforms", ["windows", "linux", "darwin"])),
        )
        self.safety_tier = str(item.get("safety_tier", DEFAULT_SAFETY_TIER))
        self.pack = str(item.get("pack", Path(source_file).stem))
        self.params_schema = dict(item.get("params_schema", {}))
        self._default_params = _param_defaults(self.params_schema)
        self._sigma_rule = copy.deepcopy(item.get("sigma"))
        self._synthetic_events = list(item.get("synthetic_events", []))
        self._source_file = source_file
        self._artifact = str(item.get("artifact", f"{slugify(self.catalog_id)}.json"))

    def _merged_params(self, params: dict[str, Any]) -> dict[str, Any]:
        merged = dict(self._default_params)
        merged.update(params)
        return merged

    def run(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        merged = self._merged_params(params)
        marker_dir = Path(merged.get("marker_dir", "data/sim_markers"))
        marker_dir.mkdir(parents=True, exist_ok=True)
        marker_path = marker_dir / self._artifact
        events = self.synthetic_events(merged, None)
        marker = {
            "_sim": "APT_SIM_CATALOG_TTP",
            "catalog_id": self.catalog_id,
            "attack_id": self.base_attack_id,
            "name": self.name,
            "pack": self.pack,
            "safety_tier": self.safety_tier,
            "dry_run": bool(merged.get("dry_run", True)),
            "params": {
                key: value
                for key, value in merged.items()
                if key not in {"marker_dir", "safety_token"}
            },
            "events": events,
        }
        marker_path.write_text(json.dumps(marker, indent=2, sort_keys=True), encoding="utf-8")
        return TTPResult(
            ok=True,
            output=f"catalog marker written for {self.catalog_id} to {marker_path}",
            artifacts=[str(marker_path)],
            started_at=started,
            finished_at=time.time(),
            extra={
                "catalog_id": self.catalog_id,
                "attack_id": self.base_attack_id,
                "pack": self.pack,
                "safety_tier": self.safety_tier,
                "event_count": len(events),
                "marker": str(marker_path),
            },
        )

    def cleanup(self, params: dict[str, Any]) -> TTPResult:
        merged = self._merged_params(params)
        marker_path = Path(merged.get("marker_dir", "data/sim_markers")) / self._artifact
        if marker_path.exists():
            marker_path.unlink()
        return TTPResult(ok=True, output="catalog marker removed", started_at=time.time(), finished_at=time.time())

    def sigma_rule(self) -> dict[str, Any] | None:
        if self._sigma_rule is None:
            return None
        rule = copy.deepcopy(self._sigma_rule)
        rule.setdefault("references", [f"https://attack.mitre.org/techniques/{self.base_attack_id[1:].replace('.', '/')}/"])
        tags = list(rule.get("tags", []))
        base_tag = f"attack.{self.base_attack_id.lower()}"
        if base_tag not in tags:
            tags.append(base_tag)
        rule["tags"] = tags
        return rule

    def synthetic_events(
        self,
        params: dict[str, Any],
        result: TTPResult | None = None,
    ) -> list[dict[str, Any]]:
        merged = self._merged_params(params)
        events = [_render_value(copy.deepcopy(event), merged) for event in self._synthetic_events]
        for event in events:
            event.setdefault("_sim", "APT_SIM_CATALOG_TTP")
            event.setdefault("attack_id", self.base_attack_id)
            event.setdefault("catalog_id", self.catalog_id)
            event.setdefault("safety_tier", self.safety_tier)
            event.setdefault("pack", self.pack)
        return events


def load_catalog_items(catalog_dir: Path = CATALOG_DIR) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    if not catalog_dir.exists():
        return items
    for path in sorted(catalog_dir.glob("*.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        pack = str(raw.get("pack", path.stem))
        for item in raw.get("ttps", []):
            item = dict(item)
            item.setdefault("pack", pack)
            item["_source_file"] = str(path)
            items.append(item)
    return items


def register_catalog_ttps(catalog_dir: Path = CATALOG_DIR) -> int:
    """Register catalog-backed TTP variants once."""
    global _REGISTERED
    if _REGISTERED:
        return 0
    count = 0
    for item in load_catalog_items(catalog_dir):
        ttp = CatalogTTP(item, item.get("_source_file", "catalog"))
        registry.register(ttp)
        count += 1
    _REGISTERED = True
    return count


def catalog_summary() -> dict[str, Any]:
    items = load_catalog_items()
    packs: dict[str, int] = {}
    safety: dict[str, int] = {}
    for item in items:
        packs[str(item.get("pack", "unknown"))] = packs.get(str(item.get("pack", "unknown")), 0) + 1
        tier = str(item.get("safety_tier", DEFAULT_SAFETY_TIER))
        safety[tier] = safety.get(tier, 0) + 1
    return {"items": len(items), "packs": packs, "safety_tiers": safety}
