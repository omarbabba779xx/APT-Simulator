"""Scenario YAML loader."""
from __future__ import annotations

from pathlib import Path

import yaml

from .schema import Scenario


def load_scenario(path: str | Path) -> Scenario:
    p = Path(path)
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    scenario = Scenario(**raw)
    scenario.validate_dag()
    return scenario


def load_scenarios_from_dir(dir_path: str | Path) -> dict[str, Scenario]:
    out: dict[str, Scenario] = {}
    d = Path(dir_path)
    if not d.exists():
        return out
    for f in sorted(d.glob("*.yaml")):
        s = load_scenario(f)
        out[s.name] = s
    return out
