"""Graph-based scenario builder for catalog-scale campaigns."""
from __future__ import annotations

import random
from itertools import combinations
from pathlib import Path
from typing import Any

import typer
import yaml

import ttps  # noqa: F401
from ttps.base import registry
from .attack_sync import OFFICIAL_TACTIC_ORDER, official_tactic_for, tactic_sort_key


app = typer.Typer(no_args_is_help=True)


@app.callback()
def _root() -> None:
    """Graph scenario generation."""

TACTIC_ORDER = OFFICIAL_TACTIC_ORDER

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

DEFAULT_PLATFORM_POOL = ("windows", "linux", "darwin")
MAX_VARIANT_STEPS = 80
MAX_VARIANT_SEED = 1_000_000
MAX_BATCH_SCENARIOS = 10_000


def _sort_key(ttp: Any) -> tuple[int, str, str]:
    tactic = official_tactic_for(str(getattr(ttp, "base_attack_id", ttp.attack_id)), ttp.tactic)
    return (*tactic_sort_key(tactic), ttp.attack_id)


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


def platform_sets(platforms: list[str] | None = None) -> list[list[str]]:
    pool = list(platforms or DEFAULT_PLATFORM_POOL)
    return [
        list(group)
        for size in range(1, len(pool) + 1)
        for group in combinations(pool, size)
    ]


def scenario_variant_space(
    actors: list[str] | None = None,
    difficulties: list[str] | None = None,
    max_steps: int = MAX_VARIANT_STEPS,
    max_seed: int = MAX_VARIANT_SEED,
    platforms: list[str] | None = None,
) -> dict[str, Any]:
    selected_actors = actors or list(ACTOR_PACKS)
    selected_difficulties = difficulties or list(DIFFICULTY_STEPS)
    selected_platform_sets = platform_sets(platforms)
    seed_values = max_seed + 1
    total = (
        len(selected_actors)
        * len(selected_difficulties)
        * max_steps
        * seed_values
        * len(selected_platform_sets)
    )
    return {
        "actors": selected_actors,
        "difficulties": selected_difficulties,
        "max_steps": max_steps,
        "seed_min": 0,
        "seed_max": max_seed,
        "seed_values": seed_values,
        "platforms": list(platforms or DEFAULT_PLATFORM_POOL),
        "platform_combinations": len(selected_platform_sets),
        "total_variants": total,
    }


def _variant_dimensions(
    actors: list[str] | None,
    difficulties: list[str] | None,
    max_steps: int,
    max_seed: int,
    platforms: list[str] | None,
) -> tuple[list[str], list[str], list[list[str]], int, int]:
    selected_actors = actors or list(ACTOR_PACKS)
    selected_difficulties = difficulties or list(DIFFICULTY_STEPS)
    selected_platform_sets = platform_sets(platforms)
    seed_values = max_seed + 1
    return selected_actors, selected_difficulties, selected_platform_sets, max_steps, seed_values


def build_scenario_variant(
    index: int,
    *,
    actors: list[str] | None = None,
    difficulties: list[str] | None = None,
    max_steps: int = MAX_VARIANT_STEPS,
    max_seed: int = MAX_VARIANT_SEED,
    platforms: list[str] | None = None,
) -> dict[str, Any]:
    if index < 0:
        raise ValueError("index must be >= 0")

    selected_actors, selected_difficulties, selected_platform_sets, step_values, seed_values = _variant_dimensions(
        actors,
        difficulties,
        max_steps,
        max_seed,
        platforms,
    )
    total = len(selected_actors) * len(selected_difficulties) * len(selected_platform_sets) * step_values * seed_values
    if index >= total:
        raise ValueError(f"index {index} outside variant space of {total}")

    platform_index = index % len(selected_platform_sets)
    index //= len(selected_platform_sets)
    seed = index % seed_values
    index //= seed_values
    steps = (index % step_values) + 1
    index //= step_values
    difficulty = selected_difficulties[index % len(selected_difficulties)]
    index //= len(selected_difficulties)
    actor = selected_actors[index % len(selected_actors)]

    selected_platforms = selected_platform_sets[platform_index]
    scenario = build_scenario(
        actor=actor,
        difficulty=difficulty,
        steps=steps,
        seed=seed,
        platforms=selected_platforms,
    )
    platform_slug = "-".join(selected_platforms)
    scenario["name"] = f"{actor}_{difficulty}_{steps}_seed{seed}_{platform_slug}"
    scenario["tags"] = [*scenario.get("tags", []), "variant", platform_slug]
    return scenario


def build_scenario_batch(
    count: int,
    *,
    offset: int = 0,
    stride: int = 1,
    actors: list[str] | None = None,
    difficulties: list[str] | None = None,
    max_steps: int = MAX_VARIANT_STEPS,
    max_seed: int = MAX_VARIANT_SEED,
    platforms: list[str] | None = None,
    max_count: int = MAX_BATCH_SCENARIOS,
) -> list[dict[str, Any]]:
    if count < 1:
        raise ValueError("count must be >= 1")
    if count > max_count:
        raise ValueError(f"count must be <= {max_count}")
    if stride < 1:
        raise ValueError("stride must be >= 1")
    return [
        build_scenario_variant(
            offset + (idx * stride),
            actors=actors,
            difficulties=difficulties,
            max_steps=max_steps,
            max_seed=max_seed,
            platforms=platforms,
        )
        for idx in range(count)
    ]


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


@app.command()
def count_variants() -> None:
    """Print the scenario variant space size."""
    data = scenario_variant_space()
    typer.echo(yaml.safe_dump(data, sort_keys=False))


@app.command()
def batch(
    count: int = typer.Option(100),
    offset: int = typer.Option(0),
    stride: int = typer.Option(1),
    out: str = typer.Option("scenarios/generated_variants.yaml"),
) -> None:
    """Generate a bounded queue slice from the full variant space."""
    scenarios = build_scenario_batch(count=count, offset=offset, stride=stride)
    out_path = Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(yaml.safe_dump({"campaign": scenarios}, sort_keys=False), encoding="utf-8")
    typer.echo(f"Wrote {len(scenarios)} scenario variant(s) to {out_path}")


if __name__ == "__main__":
    app()
