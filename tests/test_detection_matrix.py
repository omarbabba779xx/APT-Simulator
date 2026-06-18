from __future__ import annotations

from pathlib import Path

from orchestrator.detection_matrix import build_matrix, export_fixtures, export_queries
from orchestrator.scenario_builder import build_scenario, build_scenario_batch, scenario_variant_space
from orchestrator.dsl.schema import Scenario


def test_detection_matrix_includes_packs() -> None:
    matrix = build_matrix()
    assert matrix["total"] == 5064
    assert matrix["packs"]["cloud"] >= 5
    assert matrix["packs"]["cloud_k8s_lab"] == 36
    assert matrix["packs"]["ad_enterprise_lab"] == 28
    assert matrix["safety_tiers"]["marker-only"] == 5032
    assert matrix["rule_coverage_percent"] == 100.0
    assert len(matrix["tactics"]) == 15
    assert matrix["attack_sync"]["coverage_label"] == "15/15"
    assert matrix["attack_sync"]["status"] == "synced"


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


def test_scenario_variant_space_exact_count() -> None:
    space = scenario_variant_space()
    assert space["total_variants"] == 15_680_015_680
    assert space["platform_combinations"] == 7
    assert space["seed_values"] == 1_000_001


def test_scenario_variant_batch_validates() -> None:
    batch = build_scenario_batch(count=4, offset=1_000_000)
    assert len(batch) == 4
    assert len({scenario["name"] for scenario in batch}) == 4
    for data in batch:
        scenario = Scenario(**data)
        scenario.validate_dag()
