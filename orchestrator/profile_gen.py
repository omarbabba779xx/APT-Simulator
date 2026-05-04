"""Adversary Profile Loader and Profile-Driven Scenario Generator.

Loads adversary profile YAML files from the ``profiles/`` directory and
generates realistic kill-chain scenarios whose TTP selection and C2 config
mirror the documented behaviour of that threat actor.

Usage (CLI):
    python -m orchestrator.profile_gen list
    python -m orchestrator.profile_gen show apt29
    python -m orchestrator.profile_gen generate apt29 --out scenarios/apt29_generated.yaml
    python -m orchestrator.profile_gen generate lazarus --steps 8 --seed 42 --out out.yaml

API (via orchestrator.main):
    GET  /profiles              → list all profiles
    GET  /profiles/{name}       → show profile detail
    POST /profiles/{name}/generate → generate scenario from profile
"""
from __future__ import annotations

import random
from pathlib import Path
from typing import Any

import typer
import yaml

import ttps  # noqa: F401  (register TTPs)
from ttps.base import registry


_PROFILES_DIR = Path(__file__).parent.parent / "profiles"


def _profile_path(name: str) -> Path:
    return _PROFILES_DIR / f"{name.lower()}.yaml"


def load_profile(name: str) -> dict[str, Any]:
    """Load a profile by name (e.g. 'apt29')."""
    path = _profile_path(name)
    if not path.exists():
        raise FileNotFoundError(f"Profile '{name}' not found at {path}")
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def list_profiles() -> list[str]:
    """Return all available profile names (stem of YAML files)."""
    if not _PROFILES_DIR.exists():
        return []
    return sorted(p.stem for p in _PROFILES_DIR.glob("*.yaml"))


def _available_ttps_from_profile(
    profile: dict[str, Any],
    include_platform: str | None = None,
) -> list[str]:
    """Return TTPs from the profile that are currently registered."""
    preferred: list[str] = profile.get("preferred_ttps", [])
    all_ids = set(registry.all().keys())
    available = [t for t in preferred if t in all_ids]
    if include_platform:
        plat = include_platform.lower()
        filtered = []
        for attack_id in available:
            ttp = registry.get(attack_id)
            if ttp and (plat in ttp.supported_platforms or "any" in ttp.supported_platforms):
                filtered.append(attack_id)
        return filtered
    return available


def generate_scenario(
    profile_name: str,
    steps: int = 0,
    seed: int | None = None,
    platform_override: str | None = None,
) -> dict[str, Any]:
    """Generate a scenario dict from the named adversary profile.

    If ``steps`` == 0 (default), uses all available profile TTPs in
    dependency-chain order. Otherwise samples ``steps`` TTPs.

    The generated DAG mirrors a realistic kill-chain order:
    discovery → credential_access → defense_evasion → persistence →
    command_and_control → collection → exfiltration → impact
    """
    profile = load_profile(profile_name)
    c2 = profile.get("c2_profile", {})
    platforms = profile.get("target_platforms", ["windows"])
    plat = platform_override or (platforms[0] if platforms else "windows")

    available = _available_ttps_from_profile(profile, include_platform=plat)
    if not available:
        raise ValueError(f"No registered TTPs match profile '{profile_name}' for platform '{plat}'")

    rng = random.Random(seed)
    if steps > 0:
        steps = max(1, min(steps, len(available)))
        selected = rng.sample(available, steps)
    else:
        selected = list(available)

    # Sort by tactic priority (mirrors realistic kill-chain order).
    _TACTIC_ORDER = [
        "discovery", "credential_access", "defense_evasion",
        "execution", "persistence", "command_and_control",
        "collection", "exfiltration", "impact",
    ]

    def _tactic_rank(attack_id: str) -> int:
        ttp = registry.get(attack_id)
        if ttp is None:
            return 99
        try:
            return _TACTIC_ORDER.index(ttp.tactic)
        except ValueError:
            return 50

    selected.sort(key=_tactic_rank)

    # Build steps with linear DAG (each step depends on the previous).
    step_defs: list[dict[str, Any]] = []
    for i, attack_id in enumerate(selected):
        step: dict[str, Any] = {
            "id": f"step_{i+1:02d}_{attack_id.replace('.', '_').lower()}",
            "ttp": attack_id,
        }
        if i > 0:
            step["depends_on"] = [step_defs[i - 1]["id"]]

        # Inject C2 params for C2 TTPs.
        ttp = registry.get(attack_id)
        if ttp and ttp.tactic in ("command_and_control", "exfiltration"):
            step["params"] = {
                "url": "http://127.0.0.1:8765/healthz",
                "beacons": 3,
                "interval_seconds": min(float(c2.get("interval_seconds", 60)), 30),
                "jitter_seconds": float(c2.get("jitter_seconds", 10)),
                "jitter_mode": c2.get("jitter_mode", "uniform"),
                "profile": c2.get("profile", "default"),
            }

        step_defs.append(step)

    return {
        "name": f"{profile_name.lower()}_profile_generated",
        "description": (
            f"Auto-generated scenario emulating {profile['name']} "
            f"({profile.get('motivation', 'unknown motivation')})."
        ),
        "target_platforms": platforms,
        "actor": f"{profile['name']}-style (emulation)",
        "tags": ["generated", "profile-driven"] + profile.get("tags", []),
        "steps": step_defs,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

app = typer.Typer(no_args_is_help=True)


@app.callback()
def _root() -> None:
    """Adversary profile management and profile-driven scenario generation."""


@app.command()
def list_cmd() -> None:
    """List all available adversary profiles."""
    profiles = list_profiles()
    if not profiles:
        typer.echo("No profiles found in profiles/ directory.")
        raise typer.Exit(1)
    for name in profiles:
        try:
            p = load_profile(name)
            typer.echo(f"  {name:<12} {p.get('name', '?'):<20} [{p.get('origin', '?')}] — {p.get('motivation', '?')}")
        except Exception as exc:
            typer.echo(f"  {name:<12} (error: {exc})")


list_cmd.name = "list"  # type: ignore[attr-defined]


@app.command()
def show(name: str = typer.Argument(help="Profile name (e.g. apt29)")) -> None:
    """Show full details of an adversary profile."""
    try:
        p = load_profile(name)
    except FileNotFoundError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1)
    typer.echo(yaml.dump(p, default_flow_style=False, allow_unicode=True))


@app.command()
def generate(
    profile_name: str = typer.Argument(help="Profile name (e.g. apt29, lazarus)"),
    out: str = typer.Option("", help="Output YAML path (default: scenarios/<profile>_generated.yaml)"),
    steps: int = typer.Option(0, help="Number of steps (0 = all profile TTPs)"),
    seed: int = typer.Option(None, help="RNG seed for reproducibility"),
    platform: str = typer.Option("", help="Platform override (windows/linux/darwin)"),
) -> None:
    """Generate a scenario YAML from an adversary profile."""
    try:
        sc = generate_scenario(
            profile_name,
            steps=steps,
            seed=seed,
            platform_override=platform or None,
        )
    except (FileNotFoundError, ValueError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1)

    out_path = Path(out) if out else Path("scenarios") / f"{profile_name.lower()}_generated.yaml"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(yaml.dump(sc, default_flow_style=False, allow_unicode=True), encoding="utf-8")
    typer.echo(f"Scenario written to {out_path}  ({len(sc['steps'])} steps)")


if __name__ == "__main__":
    app()
