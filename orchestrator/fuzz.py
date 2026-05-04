"""Fuzzing scenario generator.

Builds a randomized scenario from registered TTPs with bounded parameter
fuzzing, useful for stress-testing detection pipelines and shaking out
parser/validator bugs in the planner.

Reproducible via --seed.

  python -m orchestrator.fuzz generate --seed 42 --steps 5 --out scenarios/fuzz_42.yaml

Cloud TTPs (T1580) and OS-restricted TTPs (registry sims) are excluded by
default since they either need credentials or only run on Windows. Override
with --include-cloud or --include-windows.
"""
from __future__ import annotations

import random
from pathlib import Path
from typing import Any

import typer
import yaml

import ttps  # noqa: F401  (registers TTPs)
from ttps.base import registry


# Bounded parameter spaces per TTP. Keep ranges sane so the generated scenario
# stays SAFE (no DoS, no cloud spend, no real damage).
FUZZ_SPECS: dict[str, dict[str, Any]] = {
    # Cross-platform discovery
    "T1033": {},
    "T1016": {"timeout_seconds": [15, 30]},
    "T1049": {"timeout_seconds": [15, 30]},
    "T1057": {"timeout_seconds": [15, 30, 60]},
    "T1069.001": {"timeout_seconds": [15, 30]},
    "T1082": {},
    "T1083": {
        "max_depth": [1, 2, 3],
        "max_entries": [25, 50, 100, 200],
    },
    # Execution
    "T1059": {
        "command": ["whoami", "hostname", "ifconfig", "ps", "netstat"],
        "timeout_seconds": [10, 15, 30],
    },
    # Credential access
    "T1003": {},
    # Defense evasion
    "T1027": {
        "size_bytes": [256, 1024, 4096, 16384],
    },
    "T1070.004": {},
    # Collection
    "T1005": {"max_depth": [2, 3], "max_entries": [20, 50]},
    # C2
    "T1071.001": {
        "url": ["http://127.0.0.1:8765/healthz"],
        "beacons": [2, 3, 5, 7],
        "interval_seconds": [0.5, 1.0, 1.5],
        "jitter_seconds": [0.1, 0.3, 0.5],
        "jitter_mode": ["uniform", "exponential", "normal"],
        "profile": ["default", "stealth", "noisy"],
        "max_total_seconds": [10, 20, 30],
    },
    "T1105": {"extension": [".exe", ".dll", ".ps1"]},
    # Exfiltration
    "T1041": {"url": ["http://127.0.0.1:8765/healthz"], "max_bytes": [128, 256, 512]},
    # Impact
    "T1486": {"file_count": [2, 3, 5, 10]},
    # Windows-only / cloud TTPs gated behind flags.
    "T1547.001": {"value_name": ["FuzzMarker_a", "FuzzMarker_b", "FuzzMarker_c"]},
    "T1053.005": {"task_name": ["AptSimFuzz_a", "AptSimFuzz_b"], "trigger": ["ONLOGON", "ONSTART"]},
    "T1112": {"value": [0, 1, 2, 100, 9999]},
    "T1580": {"provider": ["aws", "azure", "gcp"]},
}

WINDOWS_ONLY = {"T1547.001", "T1112", "T1053.005"}
CLOUD_ONLY = {"T1580"}


app = typer.Typer(no_args_is_help=True)


@app.callback()
def _root() -> None:
    """Randomized scenario generator."""


def _pick_params(rng: random.Random, attack_id: str) -> dict[str, Any]:
    spec = FUZZ_SPECS.get(attack_id, {})
    out: dict[str, Any] = {}
    for k, v in spec.items():
        if isinstance(v, list):
            out[k] = rng.choice(v)
        else:
            out[k] = v
    return out


def _candidate_pool(include_windows: bool, include_cloud: bool) -> list[str]:
    pool = []
    for attack_id in sorted(registry.all().keys()):
        if attack_id in WINDOWS_ONLY and not include_windows:
            continue
        if attack_id in CLOUD_ONLY and not include_cloud:
            continue
        pool.append(attack_id)
    return pool


@app.command()
def generate(
    seed: int = typer.Option(0, "--seed", help="0 = nondeterministic"),
    steps: int = typer.Option(5, "--steps"),
    out: str = typer.Option("scenarios/fuzz_generated.yaml", "--out"),
    name: str = typer.Option("fuzz_generated", "--name"),
    include_windows: bool = typer.Option(False, "--include-windows"),
    include_cloud: bool = typer.Option(False, "--include-cloud"),
    branching: float = typer.Option(0.4, "--branching", help="probability a step depends on a prior step"),
) -> None:
    """Emit a randomized scenario YAML."""
    if seed:
        rng = random.Random(seed)
    else:
        rng = random.Random()

    pool = _candidate_pool(include_windows, include_cloud)
    if not pool:
        typer.echo("no TTPs available for the selected flags", err=True)
        raise typer.Exit(code=1)

    chosen: list[str] = []
    for _ in range(steps):
        chosen.append(rng.choice(pool))

    scenario_steps: list[dict[str, Any]] = []
    for i, attack_id in enumerate(chosen):
        step_id = f"fuzz_{i:02d}_{attack_id.lower().replace('.', '_')}"
        step: dict[str, Any] = {
            "id": step_id,
            "ttp": attack_id,
            "params": _pick_params(rng, attack_id),
        }
        if i > 0 and rng.random() < branching:
            step["depends_on"] = [scenario_steps[rng.randrange(0, i)]["id"]]
        scenario_steps.append(step)

    target_platforms = ["any"]
    if include_windows and not include_cloud:
        target_platforms = ["windows"]

    scenario = {
        "name": name,
        "description": f"Fuzz-generated scenario (seed={seed}, steps={steps})",
        "target_platforms": target_platforms,
        "actor": "fuzzer",
        "tags": ["fuzz", f"seed_{seed}"],
        "steps": scenario_steps,
    }

    out_path = Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(yaml.safe_dump(scenario, sort_keys=False), encoding="utf-8")
    typer.echo(f"Wrote {len(scenario_steps)} step(s) to {out_path} (seed={seed})")


if __name__ == "__main__":
    app()
