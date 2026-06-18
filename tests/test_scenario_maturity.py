from __future__ import annotations

from orchestrator.dsl.loader import load_scenarios_from_dir
from orchestrator.scenario_maturity import build_scenario_maturity, scenario_evidence


def test_scenario_maturity_counts_validated_fixture_backed_scenarios() -> None:
    scenarios = load_scenarios_from_dir("scenarios")
    report = build_scenario_maturity(scenarios, limit_items=None)

    assert report["total_scenarios"] == 2534
    assert report["validated_scenarios"] == 12
    assert report["fixture_backed_scenarios"] == 12
    assert report["counts_by_kind"]["generated variant"] == 2500
    assert report["counts_by_kind"]["emulation plan"] == 11
    assert report["counts_by_kind"]["validated actor-chain"] == 12


def test_scenario_evidence_returns_golden_events() -> None:
    evidence = scenario_evidence("validated_cloud_k8s_takeover_path")

    assert evidence["found"] is True
    assert evidence["evidence"]["validation_status"] == "fixture-backed"
    assert len(evidence["golden_events"]) == 2
    assert {event["attack.technique.id"] for event in evidence["golden_events"]} == {"T1611", "T1651"}
