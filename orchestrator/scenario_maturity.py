"""Scenario maturity and evidence reporting."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer
import yaml

import ttps  # noqa: F401
from ttps.base import registry

from .attack_sync import official_tactic_for
from .dsl.loader import load_scenarios_from_dir
from .dsl.schema import Scenario


app = typer.Typer(no_args_is_help=True)

DEFAULT_EVIDENCE_PATH = Path("evidence/scenario_evidence.yaml")
DEFAULT_GOLDEN_EVENTS_PATH = Path("evidence/soc_golden_events.jsonl")


try:
    from yaml import CSafeLoader as _SafeLoader
except ImportError:  # pragma: no cover
    from yaml import SafeLoader as _SafeLoader  # type: ignore[assignment]


def _base_attack_id(value: str) -> str:
    return value.split(":", 1)[0].upper()


def _scenario_kind(tags: list[str]) -> tuple[str, str]:
    tag_set = set(tags)
    if "validated" in tag_set:
        return "validated actor-chain", "validated YAML"
    if "variant" in tag_set:
        return "generated variant", "generated YAML"
    if "ael_import" in tag_set or "source_ael" in tag_set:
        return "emulation plan", "emulation library"
    return "static", "static"


def load_evidence(path: str | Path = DEFAULT_EVIDENCE_PATH) -> dict[str, dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return {}
    raw = yaml.load(p.read_text(encoding="utf-8"), Loader=_SafeLoader) or {}
    entries = raw.get("scenarios", [])
    return {
        str(item["scenario"]): dict(item)
        for item in entries
        if isinstance(item, dict) and item.get("scenario")
    }


def load_golden_events(path: str | Path = DEFAULT_GOLDEN_EVENTS_PATH) -> dict[str, list[dict[str, Any]]]:
    p = Path(path)
    if not p.exists():
        return {}
    out: dict[str, list[dict[str, Any]]] = {}
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        scenario = str(event.get("scenario", ""))
        if scenario:
            out.setdefault(scenario, []).append(event)
    return out


def _registered_ttp(attack_id: str) -> Any | None:
    exact = registry.get(attack_id)
    if exact:
        return exact
    return registry.get(_base_attack_id(attack_id))


def _scenario_tactics(scenario: Scenario) -> list[str]:
    tactics: set[str] = set()
    for step in scenario.steps:
        ttp = _registered_ttp(step.ttp)
        tactic = getattr(ttp, "tactic", "") if ttp else ""
        tactics.add(official_tactic_for(_base_attack_id(step.ttp), tactic or "discovery"))
    return sorted(tactics)


def _detection_coverage(scenario: Scenario) -> tuple[int, int, int]:
    registered = 0
    with_rules = 0
    for step in scenario.steps:
        ttp = _registered_ttp(step.ttp)
        if not ttp:
            continue
        registered += 1
        if ttp.sigma_rule() is not None:
            with_rules += 1
    missing = max(len(scenario.steps) - registered, 0)
    return registered, with_rules, missing


def _score_scenario(
    scenario: Scenario,
    *,
    evidence: dict[str, Any] | None,
    kind: str,
    tactics: list[str],
    detection_percent: float,
) -> int:
    dependency_edges = sum(len(step.depends_on) for step in scenario.steps)
    score = 0.0
    if scenario.actor:
        score += 8
    if "validated" in set(scenario.tags):
        score += 12
    score += min(len(scenario.steps), 12)
    score += min(dependency_edges, 12)
    score += min(len(tactics) * 3, 18)
    score += detection_percent * 0.18
    if evidence:
        score += 22
        if evidence.get("runbook"):
            score += 5
        if evidence.get("success_criteria"):
            score += 5
    if len(scenario.target_platforms) > 1:
        score += 6

    if kind == "generated variant":
        score = min(score, 55)
    elif kind == "emulation plan" and not evidence:
        score = min(score, 75)
    return min(round(score), 100)


def _maturity_label(score: int, kind: str, evidence: dict[str, Any] | None) -> str:
    if kind == "generated variant":
        return "variant"
    if score >= 85 and evidence:
        return "fixture-backed"
    if score >= 70:
        return "operational"
    if score >= 50:
        return "coverage"
    return "draft"


def scenario_maturity_item(
    name: str,
    scenario: Scenario,
    evidence_by_name: dict[str, dict[str, Any]] | None = None,
    golden_events_by_name: dict[str, list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    evidence = (evidence_by_name or {}).get(name)
    golden_events = (golden_events_by_name or {}).get(name, [])
    kind, source = _scenario_kind(list(scenario.tags))
    tactics = _scenario_tactics(scenario)
    registered, with_rules, missing = _detection_coverage(scenario)
    detection_percent = round((with_rules / len(scenario.steps)) * 100, 2) if scenario.steps else 0.0
    score = _score_scenario(
        scenario,
        evidence=evidence,
        kind=kind,
        tactics=tactics,
        detection_percent=detection_percent,
    )
    telemetry_sources = sorted(set(evidence.get("telemetry_sources", []))) if evidence else []
    return {
        "name": name,
        "actor": scenario.actor or "",
        "kind": kind,
        "source": source,
        "maturity": _maturity_label(score, kind, evidence),
        "score": score,
        "step_count": len(scenario.steps),
        "distinct_ttps": len({step.ttp for step in scenario.steps}),
        "tactic_count": len(tactics),
        "tactics": tactics,
        "platforms": list(scenario.target_platforms),
        "detection_coverage_percent": detection_percent,
        "registered_steps": registered,
        "steps_with_rules": with_rules,
        "missing_ttp_steps": missing,
        "evidence_status": evidence.get("validation_status", "missing") if evidence else "missing",
        "evidence_confidence": evidence.get("confidence", "") if evidence else "",
        "telemetry_sources": telemetry_sources,
        "golden_event_count": len(golden_events),
        "runbook_steps": len(evidence.get("runbook", [])) if evidence else 0,
        "success_criteria": len(evidence.get("success_criteria", [])) if evidence else 0,
        "tags": list(scenario.tags),
    }


def build_scenario_maturity(
    scenarios: dict[str, Scenario],
    *,
    limit_items: int | None = 500,
) -> dict[str, Any]:
    evidence = load_evidence()
    golden_events = load_golden_events()
    items = [
        scenario_maturity_item(name, scenario, evidence, golden_events)
        for name, scenario in scenarios.items()
    ]
    items.sort(key=lambda item: (-int(item["score"]), str(item["name"])))
    counts_by_kind: dict[str, int] = {}
    counts_by_maturity: dict[str, int] = {}
    telemetry_sources: dict[str, int] = {}
    missing_evidence: list[str] = []
    for item in items:
        counts_by_kind[item["kind"]] = counts_by_kind.get(item["kind"], 0) + 1
        counts_by_maturity[item["maturity"]] = counts_by_maturity.get(item["maturity"], 0) + 1
        if item["evidence_status"] == "missing" and item["kind"] != "generated variant":
            missing_evidence.append(str(item["name"]))
        for source in item["telemetry_sources"]:
            telemetry_sources[source] = telemetry_sources.get(source, 0) + 1
    average = round(sum(int(item["score"]) for item in items) / len(items), 2) if items else 0.0
    visible = items if limit_items is None else items[:limit_items]
    return {
        "total_scenarios": len(items),
        "validated_scenarios": counts_by_kind.get("validated actor-chain", 0),
        "fixture_backed_scenarios": counts_by_maturity.get("fixture-backed", 0),
        "average_score": average,
        "counts_by_kind": counts_by_kind,
        "counts_by_maturity": counts_by_maturity,
        "telemetry_sources": telemetry_sources,
        "missing_evidence": missing_evidence,
        "items": visible,
    }


def scenario_evidence(name: str) -> dict[str, Any]:
    evidence = load_evidence().get(name)
    if not evidence:
        return {"scenario": name, "found": False}
    events = load_golden_events().get(name, [])
    return {"scenario": name, "found": True, "evidence": evidence, "golden_events": events}


@app.callback()
def _root() -> None:
    """Scenario maturity reporting."""


@app.command()
def summary(
    scenarios_dir: str = typer.Option("scenarios"),
    limit_items: int = typer.Option(25),
) -> None:
    """Print scenario maturity summary."""
    scenarios = load_scenarios_from_dir(scenarios_dir)
    report = build_scenario_maturity(scenarios, limit_items=limit_items)
    typer.echo(yaml.safe_dump(report, sort_keys=False))


if __name__ == "__main__":
    app()
