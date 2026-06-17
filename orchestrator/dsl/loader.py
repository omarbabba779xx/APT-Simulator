"""Scenario YAML loader."""
from __future__ import annotations

from pathlib import Path

import yaml

from ..scenario_builder import build_scenario_batch
from .schema import Scenario


def load_scenario(path: str | Path) -> Scenario:
    p = Path(path)
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    scenario = Scenario(**raw)
    scenario.validate_dag()
    return scenario


def load_scenario_file(path: str | Path) -> list[Scenario]:
    p = Path(path)
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    if isinstance(raw, dict) and "scenario_pack" in raw:
        pack = raw["scenario_pack"] or {}
        scenarios = [
            Scenario(**scenario)
            for scenario in build_scenario_batch(
                count=int(pack.get("count", 1)),
                offset=int(pack.get("offset", 0)),
                stride=int(pack.get("stride", 1)),
                max_count=int(pack.get("max_count", 5000)),
            )
        ]
    elif isinstance(raw, dict) and "campaign" in raw:
        scenarios = [Scenario(**scenario) for scenario in raw["campaign"]]
    else:
        scenarios = [Scenario(**raw)]
    for scenario in scenarios:
        scenario.validate_dag()
    return scenarios


def load_scenarios_from_dir(dir_path: str | Path) -> dict[str, Scenario]:
    out: dict[str, Scenario] = {}
    d = Path(dir_path)
    if not d.exists():
        return out
    for f in sorted(d.glob("*.yaml")):
        for scenario in load_scenario_file(f):
            out[scenario.name] = scenario
    return out
