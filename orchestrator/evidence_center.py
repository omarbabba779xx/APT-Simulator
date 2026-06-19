"""Evidence center summaries and export helpers."""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from .dsl.schema import Scenario
from .scenario_maturity import load_evidence, load_golden_events


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


def _counter(items: Counter[str]) -> dict[str, int]:
    return dict(sorted(items.items(), key=lambda item: (-item[1], item[0])))


def _quality_gate(name: str, actual: int, expected: int) -> dict[str, object]:
    return {
        "name": name,
        "actual": actual,
        "expected": expected,
        "passed": actual == expected,
    }


def build_evidence_summary(scenarios: dict[str, Scenario]) -> dict[str, object]:
    evidence = load_evidence()
    golden_events = load_golden_events()

    validated = {
        name: scenario
        for name, scenario in scenarios.items()
        if "validated" in set(scenario.tags)
    }
    validated_names = set(validated)
    evidence_names = set(evidence)
    golden_names = set(golden_events)

    actor_counts: Counter[str] = Counter()
    difficulty_counts: Counter[str] = Counter()
    sector_counts: Counter[str] = Counter()
    region_counts: Counter[str] = Counter()
    lab_counts: Counter[str] = Counter()
    telemetry_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    evidence_quality = {
        "with_sigma_matches": 0,
        "with_ecs_fields": 0,
        "with_ocsf_categories": 0,
        "with_siem_fields": 0,
        "with_detection_latency": 0,
        "with_report_expectations": 0,
    }

    for scenario in validated.values():
        actor_counts[scenario.actor or "unknown"] += 1
        tag_set = set(scenario.tags)
        for tag in sorted(tag_set & DIFFICULTIES):
            difficulty_counts[tag] += 1
        for tag in sorted(tag_set & SECTORS):
            sector_counts[tag] += 1
        for tag in sorted(tag_set & REGIONS):
            region_counts[tag] += 1

    for item in evidence.values():
        status_counts[str(item.get("validation_status", "unknown"))] += 1
        if item.get("lab_profile"):
            lab_counts[str(item["lab_profile"])] += 1
        for source in item.get("telemetry_sources", []):
            telemetry_counts[str(source)] += 1
        if item.get("sigma_matches"):
            evidence_quality["with_sigma_matches"] += 1
        if item.get("ecs_fields"):
            evidence_quality["with_ecs_fields"] += 1
        if item.get("ocsf_categories"):
            evidence_quality["with_ocsf_categories"] += 1
        if item.get("siem_fields"):
            evidence_quality["with_siem_fields"] += 1
        if item.get("detection_latency_seconds", {}).get("target", 0):
            evidence_quality["with_detection_latency"] += 1
        if item.get("report_expectations"):
            evidence_quality["with_report_expectations"] += 1

    scenarios_with_two_events = sum(1 for name in validated_names if len(golden_events.get(name, [])) == 2)
    validated_with_evidence = len(validated_names & evidence_names)
    validated_with_events = len(validated_names & golden_names)
    golden_event_rows = sum(len(events) for events in golden_events.values())
    quality_gates = [
        _quality_gate("validated scenario files", len(validated), 1000),
        _quality_gate("validated evidence contracts", validated_with_evidence, len(validated)),
        _quality_gate("validated golden-event coverage", validated_with_events, len(validated)),
        _quality_gate("two golden events per validated scenario", scenarios_with_two_events, len(validated)),
        _quality_gate("SOC golden event rows", golden_event_rows, len(validated) * 2),
        _quality_gate(
            "validated SIEM field coverage",
            evidence_quality["with_siem_fields"],
            len(validated),
        ),
        _quality_gate(
            "validated latency targets",
            evidence_quality["with_detection_latency"],
            len(validated),
        ),
    ]
    readiness_score = round(
        (sum(1 for gate in quality_gates if gate["passed"]) / len(quality_gates)) * 100,
        2,
    )

    return {
        "counts": {
            "loaded_scenarios": len(scenarios),
            "validated_scenarios": len(validated),
            "evidence_contracts": len(evidence),
            "validated_evidence_contracts": validated_with_evidence,
            "golden_event_rows": golden_event_rows,
            "scenarios_with_golden_events": validated_with_events,
            "scenarios_with_two_golden_events": scenarios_with_two_events,
            "actors": len(actor_counts),
            "telemetry_sources": len(telemetry_counts),
        },
        "readiness_score": readiness_score,
        "quality_gates": quality_gates,
        "status_counts": _counter(status_counts),
        "actors": _counter(actor_counts),
        "difficulties": _counter(difficulty_counts),
        "sectors": _counter(sector_counts),
        "regions": _counter(region_counts),
        "lab_profiles": _counter(lab_counts),
        "telemetry_sources": _counter(telemetry_counts),
        "missing": {
            "validated_without_evidence": sorted(validated_names - evidence_names),
            "validated_without_golden_events": sorted(validated_names - golden_names),
            "evidence_without_loaded_scenario": sorted(evidence_names - set(scenarios)),
            "golden_events_without_loaded_scenario": sorted(golden_names - set(scenarios)),
        },
        "maturity": {
            "validated_scenarios": len(validated),
            "fixture_backed_scenarios": status_counts.get("fixture-backed", 0),
            "evidence_quality": evidence_quality,
            "counts_by_maturity": {"fixture-backed": status_counts.get("fixture-backed", 0)},
        },
    }


def validated_scenario_files(root: Path = Path("scenarios/validated")) -> list[Path]:
    if not root.exists():
        return []
    return sorted(root.glob("*.yaml"))
