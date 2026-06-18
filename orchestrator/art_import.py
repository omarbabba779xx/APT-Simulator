"""Atomic Red Team importer.

Scans Atomic Red Team test YAML files, identifies which atomic tests target
ATT&CK techniques we can resolve to registered local TTPs, and emits scenarios
that invoke safe simulation TTPs for those techniques. Source commands are
never executed; this importer only uses ART metadata to drive coverage
validation against sandboxed equivalents.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer
import yaml

from .catalog_resolver import resolve_ttp


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


def _platforms(tests: list[dict[str, Any]]) -> list[str]:
    out: set[str] = set()
    for test in tests:
        for platform in test.get("supported_platforms") or []:
            out.add(str(platform))
    return sorted(out)


@app.command()
def scan(path: str) -> None:
    """Report ART techniques that map to registered local TTPs."""
    base = Path(path)
    if not base.exists():
        typer.echo(f"path not found: {path}", err=True)
        raise typer.Exit(code=1)

    matched: list[tuple[str, str, int, str]] = []
    unmatched: list[str] = []
    for file_path in _iter_art_files(base):
        doc = _load_art(file_path)
        if not doc or "attack_technique" not in doc:
            continue
        attack_id = str(doc["attack_technique"]).upper()
        tests = doc.get("atomic_tests") or []
        ttp = resolve_ttp(attack_id)
        if ttp is not None:
            matched.append((attack_id, doc.get("display_name", ""), len(tests), ",".join(_platforms(tests))))
        else:
            unmatched.append(attack_id)

    typer.echo(f"matched {len(matched)} ART technique(s) against registered TTPs:")
    for attack_id, name, count, platforms in sorted(matched):
        typer.echo(f"  {attack_id:12s}  {name}  ({count} ART test(s), {platforms or 'no platform'})")
    typer.echo(f"\nunmatched: {len(unmatched)} ART technique(s) without a registered TTP")
    if unmatched:
        typer.echo("  " + ", ".join(sorted(set(unmatched))[:20]) + ("..." if len(unmatched) > 20 else ""))


@app.command()
def convert(
    path: str,
    out: str = "scenarios/art_imported.yaml",
    name: str = "art_coverage_walk",
) -> None:
    """Emit a single scenario whose steps run local TTPs for each matched ART technique."""
    base = Path(path)
    if not base.exists():
        typer.echo(f"path not found: {path}", err=True)
        raise typer.Exit(code=1)

    seen: dict[str, str] = {}
    display_names: dict[str, str] = {}
    for file_path in _iter_art_files(base):
        doc = _load_art(file_path)
        if not doc or "attack_technique" not in doc:
            continue
        attack_id = str(doc["attack_technique"]).upper()
        ttp = resolve_ttp(attack_id)
        if ttp is None:
            continue
        if attack_id not in seen:
            seen[attack_id] = str(ttp.attack_id)
            display_names[attack_id] = str(doc.get("display_name", ""))

    if not seen:
        typer.echo("no matching ART techniques found", err=True)
        raise typer.Exit(code=1)

    steps: list[dict[str, Any]] = []
    prev_id: str | None = None
    for attack_id, resolved_ttp in sorted(seen.items()):
        slug = attack_id.lower().replace(".", "_")
        step_id = f"art_{slug}"
        step: dict[str, Any] = {
            "id": step_id,
            "ttp": resolved_ttp,
            "params": {
                "dry_run": True,
                "source_attack_id": attack_id,
                "source_catalog": "atomic_red_team",
            },
        }
        if prev_id:
            step["depends_on"] = [prev_id]
        steps.append(step)
        prev_id = step_id

    scenario = {
        "name": name,
        "description": (
            f"Imported ATT&CK coverage walk from {path}; runs local safe TTPs "
            f"for {len(seen)} matched ART technique(s)."
        ),
        "target_platforms": ["any"],
        "actor": "art-import",
        "tags": ["art_import", "coverage_walk"],
        "steps": steps,
    }

    out_path = Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(yaml.safe_dump(scenario, sort_keys=False), encoding="utf-8")

    typer.echo(f"Wrote scenario '{name}' with {len(steps)} step(s) to {out_path}")
    typer.echo(json.dumps(display_names, indent=2))


if __name__ == "__main__":
    app()
