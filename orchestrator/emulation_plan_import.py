"""Import ATT&CK Emulation Library plans as safe local scenarios.

The importer reads plan metadata and ATT&CK IDs only. It never copies or runs
source procedure commands.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import typer
import yaml

from .attack_sync import extract_attack_ids
from .catalog_resolver import resolve_attack_id


app = typer.Typer(no_args_is_help=True)


@app.callback()
def _root() -> None:
    """ATT&CK Emulation Library import tools."""


TEXT_SUFFIXES = {".md", ".txt", ".yaml", ".yml", ".json"}
PLAN_DIR_NAMES = {"Emulation_Plan", "CTI_Emulation_Resources", "Operations_Flow"}


def _safe_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_") or "actor"


def _iter_text_files(path: Path) -> list[Path]:
    if path.is_file() and path.suffix.lower() in TEXT_SUFFIXES:
        return [path]
    out: list[Path] = []
    for file_path in sorted(path.rglob("*")):
        if not file_path.is_file() or file_path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        parts = set(file_path.parts)
        if PLAN_DIR_NAMES.intersection(parts) or file_path.name.lower() in {"readme.md", "operations_flow.md"}:
            out.append(file_path)
    return out


def _actor_dirs(root: Path) -> list[Path]:
    if (root / "Enterprise").is_dir():
        root = root / "Enterprise"
    if any((root / name).exists() for name in PLAN_DIR_NAMES) or (root / "README.md").exists():
        return [root]
    return [item for item in sorted(root.iterdir()) if item.is_dir()]


def _load_structured_file(path: Path) -> Any | None:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    try:
        if path.suffix.lower() == ".json":
            return json.loads(text)
        if path.suffix.lower() in {".yaml", ".yml"}:
            return yaml.safe_load(text)
    except (json.JSONDecodeError, yaml.YAMLError):
        return None
    return None


def _extract_from_structured(value: Any) -> tuple[str | None, list[tuple[str, str]]]:
    actor: str | None = None
    found: list[tuple[str, str]] = []
    if isinstance(value, list):
        for index, item in enumerate(value):
            item_actor, item_found = _extract_from_structured(item)
            actor = actor or item_actor
            for attack_id, order in item_found:
                found.append((attack_id, order or f"{index:04d}"))
        return actor, found
    if not isinstance(value, dict):
        return None, []

    details = value.get("emulation_plan_details")
    if isinstance(details, dict):
        actor = str(details.get("adversary_name") or "") or None

    technique = value.get("technique")
    if isinstance(technique, dict) and technique.get("attack_id"):
        found.append((str(technique["attack_id"]).upper(), str(value.get("procedure_step") or "")))

    for key, nested in value.items():
        if key in {"executors", "input_arguments", "platforms"}:
            continue
        item_actor, item_found = _extract_from_structured(nested)
        actor = actor or item_actor
        found.extend(item_found)
    return actor, found


def collect_plan(actor_dir: Path) -> dict[str, Any]:
    actor_name = actor_dir.name.replace("_", " ").title()
    ordered: list[tuple[str, str, str]] = []
    for path in _iter_text_files(actor_dir):
        structured = _load_structured_file(path)
        if structured is not None:
            parsed_actor, entries = _extract_from_structured(structured)
            if parsed_actor:
                actor_name = parsed_actor
            for attack_id, order in entries:
                ordered.append((order or path.name, attack_id, str(path.relative_to(actor_dir))))
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for attack_id in extract_attack_ids(text):
            ordered.append((path.name, attack_id, str(path.relative_to(actor_dir))))

    seen: set[str] = set()
    techniques: list[dict[str, str]] = []
    for order, attack_id, source in sorted(ordered, key=lambda item: (item[0], item[1], item[2])):
        if attack_id in seen:
            continue
        seen.add(attack_id)
        resolved = resolve_attack_id(attack_id)
        techniques.append(
            {
                "attack_id": attack_id,
                "resolved_ttp": resolved or "",
                "source_file": source,
            }
        )
    return {
        "actor": actor_name,
        "actor_slug": _safe_name(actor_name),
        "path": str(actor_dir),
        "techniques": techniques,
        "matched": sum(1 for item in techniques if item["resolved_ttp"]),
        "unmatched": sum(1 for item in techniques if not item["resolved_ttp"]),
    }


def scan_plans(root: str | Path) -> list[dict[str, Any]]:
    base = Path(root)
    if not base.exists():
        raise FileNotFoundError(str(base))
    return [collect_plan(actor_dir) for actor_dir in _actor_dirs(base)]


def build_scenarios(root: str | Path, max_steps: int = 40) -> list[dict[str, Any]]:
    scenarios: list[dict[str, Any]] = []
    for plan in scan_plans(root):
        steps: list[dict[str, Any]] = []
        previous: str | None = None
        for item in plan["techniques"]:
            resolved = str(item["resolved_ttp"])
            if not resolved:
                continue
            step_id = f"s{len(steps) + 1:03d}_{_safe_name(item['attack_id'])}"
            step: dict[str, Any] = {
                "id": step_id,
                "ttp": resolved,
                "params": {
                    "dry_run": True,
                    "source_plan": "attack_emulation_library",
                    "source_attack_id": item["attack_id"],
                },
                "abort_on_fail": False,
            }
            if previous:
                step["depends_on"] = [previous]
            steps.append(step)
            previous = step_id
            if len(steps) >= max_steps:
                break
        if not steps:
            continue
        scenarios.append(
            {
                "name": f"ael_{plan['actor_slug']}",
                "description": (
                    "Safe scenario derived from ATT&CK Emulation Library metadata "
                    f"for {plan['actor']}; runs local simulator TTPs only."
                ),
                "target_platforms": ["any"],
                "actor": plan["actor_slug"],
                "tags": ["ael_import", "source_ael", "static"],
                "steps": steps,
            }
        )
    return scenarios


@app.command()
def scan(path: str) -> None:
    """Report matched and unmatched techniques in an emulation-plan tree."""
    plans = scan_plans(path)
    typer.echo(f"plans: {len(plans)}")
    for plan in plans:
        typer.echo(
            f"{plan['actor_slug']}: {len(plan['techniques'])} technique(s), "
            f"{plan['matched']} matched, {plan['unmatched']} unmatched"
        )


@app.command()
def convert(
    path: str,
    out_dir: str = typer.Option("scenarios/ael"),
    max_steps: int = typer.Option(40, min=1, max=200),
) -> None:
    """Write one safe scenario YAML per emulation plan actor."""
    scenarios = build_scenarios(path, max_steps=max_steps)
    target = Path(out_dir)
    target.mkdir(parents=True, exist_ok=True)
    for scenario in scenarios:
        out = target / f"{scenario['name']}.yaml"
        out.write_text(yaml.safe_dump(scenario, sort_keys=False), encoding="utf-8")
    typer.echo(f"Wrote {len(scenarios)} scenario file(s) to {target}")


if __name__ == "__main__":
    app()
