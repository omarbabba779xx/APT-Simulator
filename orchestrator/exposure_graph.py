"""Controlled exposure graph for identity, endpoint, cloud, SaaS, and container paths."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer

import ttps  # noqa: F401
from ttps.base import registry
from .attack_sync import official_tactic_for, tactic_sort_key
from .core.config import load_config
from .dsl.loader import load_scenarios_from_dir


app = typer.Typer(no_args_is_help=True)

DOMAIN_BY_PACK = {
    "identity": "identity",
    "ad_enterprise_lab": "identity",
    "windows": "endpoint",
    "linux": "endpoint",
    "core": "endpoint",
    "cloud": "cloud",
    "cloud_k8s_lab": "cloud",
    "saas": "saas",
    "attack_enterprise": "enterprise",
    "attack_variants": "enterprise",
    "attack_scale_variants": "enterprise",
}

DOMAIN_ORDER = ["identity", "endpoint", "cloud", "saas", "container", "enterprise"]


@app.callback()
def _root() -> None:
    """Exposure graph tools."""


def _node(nodes: dict[str, dict[str, Any]], node_id: str, label: str, kind: str, **extra: Any) -> None:
    nodes.setdefault(node_id, {"id": node_id, "label": label, "kind": kind, **extra})


def _edge(edges: set[tuple[str, str, str]], source: str, target: str, label: str) -> None:
    if source != target:
        edges.add((source, target, label))


def _domain_for_ttp(ttp: Any) -> str:
    pack = str(getattr(ttp, "pack", "core"))
    if "kubernetes" in ttp.name.lower() or "container" in ttp.name.lower():
        return "container"
    return DOMAIN_BY_PACK.get(pack, "enterprise")


def build_exposure_graph(scenarios: dict[str, Any] | None = None) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: set[tuple[str, str, str]] = set()
    domain_counts: dict[str, int] = {}
    tactic_counts: dict[str, int] = {}

    for domain in DOMAIN_ORDER:
        _node(nodes, f"domain:{domain}", domain, "domain")

    for ttp in registry.all().values():
        domain = _domain_for_ttp(ttp)
        tactic = official_tactic_for(str(getattr(ttp, "base_attack_id", ttp.attack_id)), ttp.tactic)
        domain_counts[domain] = domain_counts.get(domain, 0) + 1
        tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
        tactic_id = f"tactic:{tactic}"
        pack_id = f"pack:{getattr(ttp, 'pack', 'core')}"
        _node(nodes, tactic_id, tactic, "tactic")
        _node(nodes, pack_id, str(getattr(ttp, "pack", "core")), "pack")
        _edge(edges, f"domain:{domain}", pack_id, "contains")
        _edge(edges, pack_id, tactic_id, "covers")

    scenario_count = 0
    if scenarios:
        for name, scenario in scenarios.items():
            scenario_count += 1
            actor = getattr(scenario, "actor", None) or "unknown"
            actor_id = f"actor:{actor}"
            scenario_id = f"scenario:{name}"
            _node(nodes, actor_id, actor, "actor")
            _node(nodes, scenario_id, name, "scenario", steps=len(scenario.steps))
            _edge(edges, actor_id, scenario_id, "runs")
            previous_domain: str | None = None
            for step in scenario.steps:
                step_ttp = registry.get(step.ttp)
                if not step_ttp:
                    continue
                domain = _domain_for_ttp(step_ttp)
                _edge(edges, scenario_id, f"domain:{domain}", "touches")
                if previous_domain:
                    _edge(edges, f"domain:{previous_domain}", f"domain:{domain}", "path")
                previous_domain = domain

    paths = [
        ["identity", "endpoint", "cloud", "saas"],
        ["identity", "endpoint", "container", "cloud"],
        ["endpoint", "identity", "saas"],
        ["cloud", "identity", "saas"],
    ]
    for path in paths:
        for left, right in zip(path, path[1:]):
            _edge(edges, f"domain:{left}", f"domain:{right}", "reference-path")

    return {
        "nodes": sorted(nodes.values(), key=lambda item: (item["kind"], item["id"])),
        "edges": [
            {"source": source, "target": target, "label": label}
            for source, target, label in sorted(edges)
        ],
        "domain_counts": {domain: domain_counts.get(domain, 0) for domain in DOMAIN_ORDER},
        "tactic_counts": dict(sorted(tactic_counts.items(), key=lambda item: tactic_sort_key(item[0]))),
        "scenario_count": scenario_count,
        "reference_paths": paths,
    }


@app.command()
def graph(
    config: str = "config/default.yaml",
    out: str = "",
) -> None:
    """Print or write the controlled exposure graph."""
    cfg = load_config(config)
    scenarios = load_scenarios_from_dir(cfg.orchestrator.scenarios_dir)
    data = build_exposure_graph(scenarios)
    text = json.dumps(data, indent=2, sort_keys=True)
    if out:
        Path(out).write_text(text, encoding="utf-8")
    else:
        typer.echo(text)


if __name__ == "__main__":
    app()
