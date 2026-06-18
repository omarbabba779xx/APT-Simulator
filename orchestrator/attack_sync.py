"""ATT&CK STIX synchronization and local drift reporting."""
from __future__ import annotations

import json
import re
import urllib.request
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

import typer

from .catalog_resolver import registered_base_ids


app = typer.Typer(no_args_is_help=True)

DEFAULT_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
DEFAULT_SNAPSHOT_PATH = Path("config/attack_enterprise_snapshot.json")
EXCLUDED_ATTACK_IDS = {"T1588.007"}

OFFICIAL_TACTIC_ORDER = [
    "reconnaissance",
    "resource_development",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "stealth",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
    "defense_impairment",
]


@app.callback()
def _root() -> None:
    """ATT&CK STIX sync and drift tools."""


def _load_json_source(source: str) -> dict[str, Any]:
    if source.startswith(("http://", "https://")):
        with urllib.request.urlopen(source, timeout=45) as resp:
            return json.loads(resp.read().decode("utf-8"))
    return json.loads(Path(source).read_text(encoding="utf-8-sig"))


def _external_attack_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return str(ref["external_id"]).upper()
    return None


def _external_url(obj: dict[str, Any]) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("url"):
            return str(ref["url"])
    return ""


def _phase_names(obj: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for phase in obj.get("kill_chain_phases") or []:
        if phase.get("kill_chain_name") == "mitre-attack":
            out.append(str(phase.get("phase_name", "")).replace("-", "_"))
    return [phase for phase in out if phase]


def _primary_tactic(obj: dict[str, Any]) -> str:
    phases = _phase_names(obj)
    if not phases:
        return "discovery"
    return sorted(phases, key=lambda item: OFFICIAL_TACTIC_ORDER.index(item) if item in OFFICIAL_TACTIC_ORDER else 999)[0]


def _sort_tactics(tactics: set[str]) -> list[str]:
    return sorted(
        tactics,
        key=lambda item: OFFICIAL_TACTIC_ORDER.index(item) if item in OFFICIAL_TACTIC_ORDER else 999,
    )


def build_snapshot(source: str = DEFAULT_STIX_URL) -> dict[str, Any]:
    bundle = _load_json_source(source)
    techniques: dict[str, dict[str, Any]] = {}
    deprecated: dict[str, dict[str, Any]] = {}
    revoked: dict[str, dict[str, Any]] = {}
    tactic_set: set[str] = set()
    active_techniques = 0
    active_subtechniques = 0

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        attack_id = _external_attack_id(obj)
        if not attack_id or attack_id in EXCLUDED_ATTACK_IDS:
            continue

        entry: dict[str, Any] = {
            "id": attack_id,
            "name": str(obj.get("name", attack_id)),
            "tactic": _primary_tactic(obj),
            "tactics": _phase_names(obj),
            "modified": str(obj.get("modified", "")),
            "version": str(obj.get("x_mitre_version", "")),
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique", False)),
            "url": _external_url(obj),
        }

        if obj.get("revoked"):
            revoked[attack_id] = entry
            continue
        if obj.get("x_mitre_deprecated"):
            deprecated[attack_id] = entry
            continue

        techniques[attack_id] = entry
        tactic_set.update(entry["tactics"] or [entry["tactic"]])
        if entry["is_subtechnique"]:
            active_subtechniques += 1
        else:
            active_techniques += 1

    latest_modified = max((item["modified"] for item in techniques.values()), default="")
    return {
        "domain": "enterprise-attack",
        "source": source,
        "generated_at": datetime.now(UTC).isoformat(),
        "bundle_id": str(bundle.get("id", "")),
        "latest_modified": latest_modified,
        "excluded_attack_ids": sorted(EXCLUDED_ATTACK_IDS),
        "tactics": _sort_tactics(tactic_set),
        "tactic_count": len(tactic_set),
        "technique_count": active_techniques,
        "subtechnique_count": active_subtechniques,
        "active_count": len(techniques),
        "deprecated_count": len(deprecated),
        "revoked_count": len(revoked),
        "techniques": dict(sorted(techniques.items())),
        "deprecated": dict(sorted(deprecated.items())),
        "revoked": dict(sorted(revoked.items())),
    }


@lru_cache(maxsize=8)
def _load_snapshot_cached(path_text: str) -> dict[str, Any]:
    p = Path(path_text)
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))
    return {
        "domain": "enterprise-attack",
        "source": "missing",
        "generated_at": "",
        "latest_modified": "",
        "excluded_attack_ids": sorted(EXCLUDED_ATTACK_IDS),
        "tactics": OFFICIAL_TACTIC_ORDER,
        "tactic_count": len(OFFICIAL_TACTIC_ORDER),
        "technique_count": 0,
        "subtechnique_count": 0,
        "active_count": 0,
        "deprecated_count": 0,
        "revoked_count": 0,
        "techniques": {},
        "deprecated": {},
        "revoked": {},
    }


def load_snapshot(path: str | Path = DEFAULT_SNAPSHOT_PATH) -> dict[str, Any]:
    p = Path(path)
    return _load_snapshot_cached(str(p.resolve() if p.exists() else p))


def write_snapshot(snapshot: dict[str, Any], out: str | Path = DEFAULT_SNAPSHOT_PATH) -> Path:
    path = Path(out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _load_snapshot_cached.cache_clear()
    return path


def official_tactic_for(attack_id: str, fallback: str = "discovery") -> str:
    base = attack_id.strip().upper().split(":", 1)[0]
    snapshot = load_snapshot()
    entry = (
        snapshot.get("techniques", {}).get(base)
        or snapshot.get("deprecated", {}).get(base)
        or snapshot.get("revoked", {}).get(base)
    )
    if isinstance(entry, dict):
        return str(entry.get("tactic") or fallback)
    return fallback


def official_tactics_for(attack_id: str, fallback: str = "discovery") -> list[str]:
    base = attack_id.strip().upper().split(":", 1)[0]
    snapshot = load_snapshot()
    entry = (
        snapshot.get("techniques", {}).get(base)
        or snapshot.get("deprecated", {}).get(base)
        or snapshot.get("revoked", {}).get(base)
    )
    if isinstance(entry, dict):
        tactics = entry.get("tactics")
        if isinstance(tactics, list) and tactics:
            return [str(tactic) for tactic in tactics]
        return [str(entry.get("tactic") or fallback)]
    return [fallback]


def tactic_sort_key(tactic: str) -> tuple[int, str]:
    try:
        return OFFICIAL_TACTIC_ORDER.index(tactic), tactic
    except ValueError:
        return len(OFFICIAL_TACTIC_ORDER), tactic


def drift_status(snapshot: dict[str, Any] | None = None) -> dict[str, Any]:
    snap = snapshot or load_snapshot()
    techniques: dict[str, Any] = snap.get("techniques", {})
    official_ids = set(techniques)
    local_ids = registered_base_ids()
    covered_ids = local_ids & official_ids
    missing_ids = official_ids - local_ids
    extra_ids = local_ids - official_ids
    official_tactics = set(str(item) for item in snap.get("tactics", []))
    covered_tactics = {
        str(techniques[attack_id].get("tactic"))
        for attack_id in covered_ids
        if attack_id in techniques
    }
    deprecated_present = sorted(local_ids & set(snap.get("deprecated", {})))
    revoked_present = sorted(local_ids & set(snap.get("revoked", {})))
    return {
        "domain": snap.get("domain", "enterprise-attack"),
        "source": snap.get("source", ""),
        "snapshot_generated_at": snap.get("generated_at", ""),
        "latest_modified": snap.get("latest_modified", ""),
        "official_tactics_total": len(official_tactics),
        "official_tactics_covered": len(covered_tactics & official_tactics),
        "official_tactics": _sort_tactics(official_tactics),
        "covered_tactics": _sort_tactics(covered_tactics & official_tactics),
        "coverage_label": f"{len(covered_tactics & official_tactics)}/{len(official_tactics)}",
        "official_active": len(official_ids),
        "local_base_ids": len(local_ids),
        "covered_ids": len(covered_ids),
        "missing_count": len(missing_ids),
        "extra_count": len(extra_ids),
        "deprecated_present_count": len(deprecated_present),
        "revoked_present_count": len(revoked_present),
        "technique_count": int(snap.get("technique_count", 0)),
        "subtechnique_count": int(snap.get("subtechnique_count", 0)),
        "excluded_attack_ids": list(snap.get("excluded_attack_ids", [])),
        "missing": sorted(missing_ids)[:200],
        "extra": sorted(extra_ids)[:200],
        "deprecated_present": deprecated_present[:200],
        "revoked_present": revoked_present[:200],
        "status": "synced" if not missing_ids and not deprecated_present and not revoked_present else "drift",
    }


def extract_attack_ids(text: str) -> list[str]:
    ids = re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text.upper())
    return sorted(set(ids))


@app.command()
def snapshot(
    source: str = typer.Option(DEFAULT_STIX_URL),
    out: str = typer.Option(str(DEFAULT_SNAPSHOT_PATH)),
) -> None:
    """Fetch ATT&CK STIX and write the compact local snapshot."""
    path = write_snapshot(build_snapshot(source), out)
    typer.echo(f"Wrote ATT&CK snapshot to {path}")


@app.command()
def status(path: str = typer.Option(str(DEFAULT_SNAPSHOT_PATH))) -> None:
    """Print local registry drift against the bundled ATT&CK snapshot."""
    typer.echo(json.dumps(drift_status(load_snapshot(path)), indent=2, sort_keys=True))


if __name__ == "__main__":
    app()
