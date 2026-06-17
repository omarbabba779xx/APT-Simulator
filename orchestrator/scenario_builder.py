"""Graph-based scenario builder for catalog-scale campaigns."""
from __future__ import annotations

import random
from pathlib import Path
from typing import Any

import typer
import yaml

import ttps  # noqa: F401
from ttps.base import registry


app = typer.Typer(no_args_is_help=True)


@app.callback()
def _root() -> None:
    """Graph scenario generation."""

TACTIC_ORDER = [
    "reconnaissance",
    "resource_development",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
]

ACTOR_PACKS: dict[str, list[str]] = {
    "apt29": ["windows", "identity", "cloud"],
    "fin7": ["windows", "saas", "identity"],
    "lazarus": ["windows", "linux", "cloud"],
    "apt41": ["linux", "cloud", "saas"],
    "ransomware": ["windows", "identity", "linux"],
    "insider": ["saas", "identity", "cloud"],
    "cloud-intrusion": ["cloud", "identity", "saas"],
}

DIFFICULTY_STEPS = {
    "beginner": 6,
    "realistic": 12,
    "stealthy": 18,
    "noisy": 25,
}


def _sort_key(ttp: Any) -> tuple[int, str]:
    try:
        idx = TACTIC_ORDER.index(ttp.tactic)
    except ValueError:
        idx = len(TACTIC_ORDER)
    return idx, ttp.attack_id


def _eligible(actor: str, platforms: set[str]) -> list[Any]:
    packs = set(ACTOR_PACKS.get(actor, []))
    out = []
    for ttp in registry.all().values():
        pack = str(getattr(ttp, "pack", "core"))
        if packs and pack not in packs and pack != "core":
            continue
        if platforms and not platforms.intersection(set(ttp.supported_platforms)):
            continue
        out.append(ttp)
    return sorted(out, key=_sort_key)


def build_scenario(
    actor: str = "cloud-intrusion",
    difficulty: str = "realistic",
    steps: int = 0,
    seed: int = 1,
    platforms: list[str] | None = None,
) -> dict[str, Any]:
    rng = random.Random(seed)
    target_platforms = platforms or ["windows", "linux", "darwin"]
    pool = _eligible(actor, set(target_platforms))
    if not pool:
        raise ValueError(f"no TTPs available for actor={actor}")
    desired = steps or DIFFICULTY_STEPS.get(difficulty, DIFFICULTY_STEPS["realistic"])
    desired = max(1, min(desired, len(pool)))
    selected = sorted(rng.sample(pool, desired), key=_sort_key)

    branch_factor = 1 if difficulty in {"beginner", "stealthy"} else 2
    scenario_steps: list[dict[str, Any]] = []
    for idx, ttp in enumerate(selected):
        step: dict[str, Any] = {
            "id": f"s{idx + 1:03d}_{ttp.attack_id.lower().replace('.', '_').replace(':', '_')}",
            "ttp": ttp.attack_id,
            "params": {"dry_run": True},
            "abort_on_fail": False,
        }
        if idx > 0:
            parent_count = 1 if idx < 3 else rng.randint(1, min(branch_factor, idx))
            parents = rng.sample(scenario_steps[:idx], parent_count)
            step["depends_on"] = [p["id"] for p in parents]
        scenario_steps.append(step)

    return {
        "name": f"{actor}_{difficulty}_{seed}",
        "description": f"Graph-generated {actor} scenario ({difficulty}, seed={seed})",
        "target_platforms": target_platforms,
        "actor": actor,
        "tags": ["generated", actor, difficulty],
        "steps": scenario_steps,
    }


@app.command()
def generate(
    actor: str = typer.Option("cloud-intrusion"),
    difficulty: str = typer.Option("realistic"),
    steps: int = typer.Option(0),
    seed: int = typer.Option(1),
    out: str = typer.Option("scenarios/generated_campaign.yaml"),
    platforms: str = typer.Option("windows,linux,darwin"),
) -> None:
    """Generate a graph scenario from registered TTP packs."""
    scenario = build_scenario(
        actor=actor,
        difficulty=difficulty,
        steps=steps,
        seed=seed,
        platforms=[p.strip() for p in platforms.split(",") if p.strip()],
    )
    out_path = Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(yaml.safe_dump(scenario, sort_keys=False), encoding="utf-8")
    typer.echo(f"Wrote {len(scenario['steps'])} step(s) to {out_path}")


if __name__ == "__main__":
    app()
