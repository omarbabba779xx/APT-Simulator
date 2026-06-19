from __future__ import annotations

from pathlib import Path

import ttps  # noqa: F401

from orchestrator.dsl.loader import load_scenario_file
from orchestrator.scenario_maturity import load_evidence, load_golden_events
from ttps.base import registry


ROOT = Path(__file__).resolve().parents[1]
DIFFICULTIES = {"beginner", "realistic", "stealthy", "noisy"}
SECTORS = {
    "finance",
    "healthcare",
    "energy",
    "manufacturing",
    "retail",
    "telecom",
    "government",
    "education",
    "logistics",
    "technology",
    "media",
    "defense",
}
REGIONS = {"amer", "emea", "apac", "latam", "global"}
LAB_PROFILES = {"windows-ad", "linux-fleet", "cloud-k8s", "saas-identity"}


def _registered_ttp(attack_id: str) -> bool:
    base = attack_id.split(":", 1)[0]
    return registry.get(attack_id) is not None or registry.get(base) is not None


def test_validated_actor_chain_pack_is_materialized_and_fixture_backed() -> None:
    files = sorted((ROOT / "scenarios" / "validated").glob("*.yaml"))
    assert len(files) == 1000

    scenarios = []
    for path in files:
        loaded = load_scenario_file(path)
        assert len(loaded) == 1
        scenario = loaded[0]
        scenarios.append(scenario)
        assert {"validated", "actor_chain"} <= set(scenario.tags)
        assert len(scenario.steps) >= 8
        assert all(_registered_ttp(step.ttp) for step in scenario.steps)

    scenario_names = {scenario.name for scenario in scenarios}
    evidence = load_evidence()
    golden_events = load_golden_events()

    assert set(evidence) == scenario_names
    assert set(golden_events) == scenario_names
    assert sum(len(events) for events in golden_events.values()) == 2000
    assert all(len(events) == 2 for events in golden_events.values())
    assert all(item["validation_status"] == "fixture-backed" for item in evidence.values())
    assert all(item["sigma_matches"] for item in evidence.values())
    assert all(item["ecs_fields"] for item in evidence.values())
    assert all(item["ocsf_categories"] for item in evidence.values())
    assert all(item["siem_fields"] for item in evidence.values())
    assert all(item["detection_latency_seconds"]["target"] > 0 for item in evidence.values())


def test_validated_actor_chain_pack_has_real_coverage_diversity() -> None:
    scenarios = [load_scenario_file(path)[0] for path in sorted((ROOT / "scenarios" / "validated").glob("*.yaml"))]
    tags = [tag for scenario in scenarios for tag in scenario.tags]

    assert len({scenario.actor for scenario in scenarios if scenario.actor}) >= 40
    assert DIFFICULTIES <= set(tags)
    assert SECTORS <= set(tags)
    assert REGIONS <= set(tags)
    assert LAB_PROFILES <= set(tags)
