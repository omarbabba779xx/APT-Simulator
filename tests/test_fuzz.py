from __future__ import annotations

from pathlib import Path

import yaml
from typer.testing import CliRunner

from orchestrator.dsl.schema import Scenario
from orchestrator.fuzz import _candidate_pool, app


def test_pool_excludes_windows_and_cloud_by_default() -> None:
    pool = _candidate_pool(include_windows=False, include_cloud=False)
    assert "T1547.001" not in pool
    assert "T1112" not in pool
    assert "T1580" not in pool
    assert "T1033" in pool


def test_pool_includes_when_flagged() -> None:
    pool = _candidate_pool(include_windows=True, include_cloud=True)
    assert {"T1547.001", "T1112", "T1580"} <= set(pool)


def test_seed_reproducible(tmp_path: Path) -> None:
    runner = CliRunner()
    out_a = tmp_path / "a.yaml"
    out_b = tmp_path / "b.yaml"
    runner.invoke(app, ["generate", "--seed", "42", "--steps", "5", "--out", str(out_a), "--name", "t"])
    runner.invoke(app, ["generate", "--seed", "42", "--steps", "5", "--out", str(out_b), "--name", "t"])
    assert out_a.read_text(encoding="utf-8") == out_b.read_text(encoding="utf-8")


def test_generated_scenario_validates(tmp_path: Path) -> None:
    runner = CliRunner()
    out = tmp_path / "f.yaml"
    result = runner.invoke(app, ["generate", "--seed", "7", "--steps", "8", "--out", str(out), "--name", "fuzz_test"])
    assert result.exit_code == 0
    scenario = Scenario(**yaml.safe_load(out.read_text(encoding="utf-8")))
    scenario.validate_dag()
    assert len(scenario.steps) == 8
    # Step ids are unique (validator already checks, but assert anyway).
    assert len({s.id for s in scenario.steps}) == 8


def test_unique_seeds_diverge(tmp_path: Path) -> None:
    runner = CliRunner()
    out_a = tmp_path / "a.yaml"
    out_b = tmp_path / "b.yaml"
    runner.invoke(app, ["generate", "--seed", "1", "--steps", "10", "--out", str(out_a), "--name", "x"])
    runner.invoke(app, ["generate", "--seed", "2", "--steps", "10", "--out", str(out_b), "--name", "x"])
    a = yaml.safe_load(out_a.read_text(encoding="utf-8"))
    b = yaml.safe_load(out_b.read_text(encoding="utf-8"))
    a_steps = [(s["ttp"], s.get("params", {})) for s in a["steps"]]
    b_steps = [(s["ttp"], s.get("params", {})) for s in b["steps"]]
    assert a_steps != b_steps
