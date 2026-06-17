from __future__ import annotations

from pathlib import Path

from orchestrator.detection_matrix import build_matrix, export_fixtures, export_queries
from orchestrator.scenario_builder import build_scenario
from orchestrator.dsl.schema import Scenario


def test_detection_matrix_includes_packs() -> None:
    matrix = build_matrix()
    assert matrix["total"] >= 625
    assert matrix["packs"]["cloud"] >= 5
    assert matrix["safety_tiers"]["marker-only"] >= 625
    assert matrix["rule_coverage_percent"] > 90


def test_export_fixtures_and_queries(tmp_path: Path) -> None:
    fixture_count = export_fixtures(str(tmp_path / "fixtures"))
    query_count = export_queries(str(tmp_path / "queries"))
    assert fixture_count > 0
    assert query_count > 0
    assert any((tmp_path / "fixtures").glob("*.ecs.jsonl"))
    assert any((tmp_path / "fixtures").glob("*.ocsf.jsonl"))
    assert any((tmp_path / "queries").glob("*.yaml"))


def test_graph_scenario_builder_validates() -> None:
    data = build_scenario(actor="cloud-intrusion", difficulty="realistic", steps=8, seed=7)
    scenario = Scenario(**data)
    scenario.validate_dag()
    assert len(scenario.steps) == 8
    assert any(step.depends_on for step in scenario.steps[1:])
