"""Detection coverage matrix, golden fixtures, and simple query exports."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer
import yaml

import ttps  # noqa: F401
from ttps.base import registry
from ttps.catalog import slugify
from .attack_sync import drift_status, official_tactic_for, tactic_sort_key


app = typer.Typer(no_args_is_help=True)


def _base_attack_id(ttp: Any) -> str:
    return str(getattr(ttp, "base_attack_id", ttp.attack_id))


def _official_tactic(ttp: Any) -> str:
    return official_tactic_for(_base_attack_id(ttp), str(getattr(ttp, "tactic", "discovery")))


def build_matrix() -> dict[str, Any]:
    tactics: dict[str, dict[str, Any]] = {}
    packs: dict[str, int] = {}
    safety_tiers: dict[str, int] = {}
    total = 0
    with_rules = 0
    for ttp in registry.all().values():
        total += 1
        tactic = _official_tactic(ttp)
        pack = str(getattr(ttp, "pack", "core"))
        safety_tier = str(getattr(ttp, "safety_tier", "lab-write"))
        packs[pack] = packs.get(pack, 0) + 1
        safety_tiers[safety_tier] = safety_tiers.get(safety_tier, 0) + 1
        has_rule = ttp.sigma_rule() is not None
        if has_rule:
            with_rules += 1
        bucket = tactics.setdefault(tactic, {"total": 0, "with_rules": 0, "items": []})
        bucket["total"] += 1
        bucket["with_rules"] += int(has_rule)
        bucket["items"].append(
            {
                "id": ttp.attack_id,
                "attack_id": _base_attack_id(ttp),
                "name": ttp.name,
                "declared_tactic": ttp.tactic,
                "pack": pack,
                "safety_tier": safety_tier,
                "platforms": list(ttp.supported_platforms),
                "has_rule": has_rule,
            }
        )
    return {
        "total": total,
        "with_rules": with_rules,
        "without_rules": total - with_rules,
        "rule_coverage_percent": round((with_rules / total) * 100, 2) if total else 0,
        "packs": packs,
        "safety_tiers": safety_tiers,
        "tactics": dict(sorted(tactics.items(), key=lambda item: tactic_sort_key(item[0]))),
        "attack_sync": drift_status(),
    }


def to_ecs_event(event: dict[str, Any], ttp: Any) -> dict[str, Any]:
    return {
        "event.kind": "event",
        "event.category": [str(event.get("category", "threat"))],
        "event.action": str(event.get("eventName") or event.get("Operation") or event.get("action") or "simulated"),
        "threat.technique.id": _base_attack_id(ttp),
        "threat.technique.name": ttp.name,
        "threat.tactic.name": _official_tactic(ttp),
        "observer.product": "APT Simulator",
        "apt_sim.catalog_id": ttp.attack_id,
        "apt_sim.pack": str(getattr(ttp, "pack", "core")),
        "apt_sim.raw": event,
    }


def to_ocsf_event(event: dict[str, Any], ttp: Any) -> dict[str, Any]:
    return {
        "class_uid": 4001,
        "category_uid": 4,
        "activity_name": str(event.get("eventName") or event.get("Operation") or event.get("action") or "Simulated Activity"),
        "metadata": {"product": {"name": "APT Simulator"}},
        "threat": {
            "technique": {"uid": _base_attack_id(ttp), "name": ttp.name},
            "tactic": {"name": _official_tactic(ttp)},
        },
        "unmapped": event,
    }


def export_fixtures(out_dir: str = "detection/fixtures") -> int:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = 0
    for ttp in registry.all().values():
        events = ttp.synthetic_events({}, None)
        if not events:
            continue
        slug = slugify(ttp.attack_id)
        for fmt, transformed in {
            "raw": events,
            "ecs": [to_ecs_event(event, ttp) for event in events],
            "ocsf": [to_ocsf_event(event, ttp) for event in events],
        }.items():
            path = out / f"{slug}.{fmt}.jsonl"
            path.write_text(
                "\n".join(json.dumps(event, sort_keys=True) for event in transformed) + "\n",
                encoding="utf-8",
            )
            written += 1
    return written


def _selection_terms(selection: dict[str, Any]) -> list[str]:
    terms: list[str] = []
    for key, value in selection.items():
        field = key.split("|")[0]
        values = value if isinstance(value, list) else [value]
        inner = " OR ".join(f'{field}="{v}"' for v in values)
        terms.append(f"({inner})")
    return terms


def simple_query(rule: dict[str, Any], target: str) -> str:
    detection = rule.get("detection") or {}
    selections = [value for key, value in detection.items() if key != "condition" and isinstance(value, dict)]
    terms: list[str] = []
    for selection in selections:
        terms.extend(_selection_terms(selection))
    base = " AND ".join(terms) if terms else "*"
    if target == "splunk":
        return f"search {base}"
    if target == "elastic":
        return base.replace("=", ":")
    if target == "sentinel":
        return f"SecurityEvent | where {base.replace('=', ' == ')}"
    if target == "chronicle":
        return base
    return base


def export_queries(out_dir: str = "detection/queries") -> int:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = 0
    for ttp in registry.all().values():
        rule = ttp.sigma_rule()
        if rule is None:
            continue
        slug = slugify(ttp.attack_id)
        data = {target: simple_query(rule, target) for target in ["splunk", "elastic", "sentinel", "chronicle"]}
        (out / f"{slug}.yaml").write_text(yaml.safe_dump(data, sort_keys=True), encoding="utf-8")
        written += 1
    return written


@app.command()
def matrix(out: str = "") -> None:
    """Print or write coverage matrix JSON."""
    data = build_matrix()
    text = json.dumps(data, indent=2, sort_keys=True)
    if out:
        Path(out).write_text(text, encoding="utf-8")
    else:
        typer.echo(text)


@app.command()
def fixtures(out_dir: str = "detection/fixtures") -> None:
    """Write raw, ECS, and OCSF golden telemetry fixtures."""
    count = export_fixtures(out_dir)
    typer.echo(f"Wrote {count} fixture file(s) to {out_dir}")


@app.command()
def queries(out_dir: str = "detection/queries") -> None:
    """Write simple SIEM query sketches for Splunk, Elastic, Sentinel, and Chronicle."""
    count = export_queries(out_dir)
    typer.echo(f"Wrote {count} query file(s) to {out_dir}")


if __name__ == "__main__":
    app()
