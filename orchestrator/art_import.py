"""Atomic Red Team importer.

Scans Atomic Red Team test YAML files, identifies which atomic tests target
ATT&CK techniques we have registered TTPs for, and emits scenarios that invoke
OUR safe simulation TTPs for those techniques. The original ART commands are
NEVER executed — this importer only uses ART's catalog to drive coverage
validation against our sandboxed equivalents.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer
import yaml

import ttps  # noqa: F401  (registers TTPs)
from ttps.base import registry


app = typer.Typer(no_args_is_help=True)


@app.callback()
def _root() -> None:
    """Atomic Red Team to APT Simulator scenario importer."""


def _iter_art_files(path: Path):
    if path.is_file():
        yield path
        return
    yield from sorted(path.rglob("T*.yaml"))


def _load_art(path: Path) -> dict[str, Any] | None:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError):
        return None


@app.command()
def scan(path: str) -> None:
    """Report ART techniques that map to our registered TTPs."""
    base = Path(path)
    if not base.exists():
        typer.echo(f"path not found: {path}", err=True)
        raise typer.Exit(code=1)

    matched: list[tuple[str, str, int]] = []
    unmatched: list[str] = []
    for f in _iter_art_files(base):
        doc = _load_art(f)
        if not doc or "attack_technique" not in doc:
            continue
        attack_id = str(doc["attack_technique"]).upper()
        tests = doc.get("atomic_tests") or []
        if registry.get(attack_id) is not None:
            matched.append((attack_id, doc.get("display_name", ""), len(tests)))
        else:
            unmatched.append(attack_id)

    typer.echo(f"matched {len(matched)} ART technique(s) against registered TTPs:")
    for attack_id, name, n in sorted(matched):
        typer.echo(f"  {attack_id:12s}  {name}  ({n} ART test(s))")
    typer.echo(f"\nunmatched: {len(unmatched)} ART technique(s) without a registered TTP")
    if unmatched:
        typer.echo("  " + ", ".join(sorted(set(unmatched))[:20]) + ("..." if len(unmatched) > 20 else ""))


@app.command()
def convert(
    path: str,
    out: str = "scenarios/art_imported.yaml",
    name: str = "art_coverage_walk",
) -> None:
    """Emit a single scenario whose steps run our TTP for each matched ART technique."""
    base = Path(path)
    if not base.exists():
        typer.echo(f"path not found: {path}", err=True)
        raise typer.Exit(code=1)

    seen: dict[str, str] = {}
    for f in _iter_art_files(base):
        doc = _load_art(f)
        if not doc or "attack_technique" not in doc:
            continue
        attack_id = str(doc["attack_technique"]).upper()
        if registry.get(attack_id) is None:
            continue
        if attack_id not in seen:
            seen[attack_id] = doc.get("display_name", "")

    if not seen:
        typer.echo("no matching ART techniques found", err=True)
        raise typer.Exit(code=1)

    steps: list[dict[str, Any]] = []
    prev_id: str | None = None
    for attack_id, display in sorted(seen.items()):
        slug = attack_id.lower().replace(".", "_")
        step_id = f"art_{slug}"
        step: dict[str, Any] = {"id": step_id, "ttp": attack_id, "params": {}}
        if prev_id:
            step["depends_on"] = [prev_id]
        steps.append(step)
        prev_id = step_id

    scenario = {
        "name": name,
        "description": f"Imported ATT&CK coverage walk from {path}; runs our safe TTPs for {len(seen)} matched ART technique(s).",
        "target_platforms": ["any"],
        "actor": "art-import",
        "tags": ["art_import", "coverage_walk"],
        "steps": steps,
    }

    out_path = Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(yaml.safe_dump(scenario, sort_keys=False), encoding="utf-8")

    typer.echo(f"Wrote scenario '{name}' with {len(steps)} step(s) to {out_path}")
    typer.echo(json.dumps(seen, indent=2))


if __name__ == "__main__":
    app()
