from __future__ import annotations

from orchestrator.dsl.loader import load_scenarios_from_dir
from orchestrator.exposure_graph import build_exposure_graph


def test_exposure_graph_includes_domains_and_loaded_scenarios() -> None:
    scenarios = load_scenarios_from_dir("scenarios")
    graph = build_exposure_graph(scenarios)
    assert graph["scenario_count"] == 3522
    assert graph["domain_counts"]["identity"] > 0
    assert graph["domain_counts"]["endpoint"] > 0
    assert graph["domain_counts"]["cloud"] > 0
    assert graph["domain_counts"]["container"] > 0
    assert any(edge["label"] == "reference-path" for edge in graph["edges"])
