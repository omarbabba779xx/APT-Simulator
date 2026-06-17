"""Scenario YAML loader."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .schema import Scenario


try:
    from yaml import CSafeLoader as _SafeLoader
except ImportError:  # pragma: no cover - depends on PyYAML build
    from yaml import SafeLoader as _SafeLoader  # type: ignore[assignment]


_SCENARIO_DIR_CACHE: dict[tuple[str, int, int, int], dict[str, Scenario]] = {}


def _load_yaml(path: Path) -> Any:
    return yaml.load(path.read_text(encoding="utf-8"), Loader=_SafeLoader)


def load_scenario(path: str | Path) -> Scenario:
    p = Path(path)
    raw = _load_yaml(p)
    scenario = Scenario(**raw)
    scenario.validate_dag()
    return scenario


def load_scenario_file(path: str | Path) -> list[Scenario]:
    p = Path(path)
    raw = _load_yaml(p)
    if isinstance(raw, dict) and "campaign" in raw:
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
    files = sorted(d.rglob("*.yaml"))
    stats = [path.stat() for path in files]
    signature = (
        str(d.resolve()),
        len(files),
        max((stat.st_mtime_ns for stat in stats), default=0),
        sum(stat.st_size for stat in stats),
    )
    cached = _SCENARIO_DIR_CACHE.get(signature)
    if cached is not None:
        return dict(cached)
    for f in files:
        for scenario in load_scenario_file(f):
            out[scenario.name] = scenario
    _SCENARIO_DIR_CACHE.clear()
    _SCENARIO_DIR_CACHE[signature] = dict(out)
    return out
