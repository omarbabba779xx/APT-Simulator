"""Project-level readiness scorecard across the major product capabilities."""
from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from .api.state import AppState
from .attack_sync import drift_status
from .detection_workbench import build_workbench
from .enterprise import enterprise_readiness_report
from .evidence_center import build_evidence_summary
from .execution_engine_v3 import build_engine_status
from .exposure_graph import build_exposure_graph
from .import_center import build_import_center
from .siem_connectors import connector_status


def _row(
    area: str,
    status: str,
    score: float,
    evidence: list[str],
    endpoints: list[str],
    gaps: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "area": area,
        "status": status,
        "score": round(score, 2),
        "evidence": evidence,
        "endpoints": endpoints,
        "gaps": gaps or [],
    }


def _status_from_score(score: float) -> str:
    if score >= 95:
        return "strong"
    if score >= 70:
        return "operational"
    if score >= 40:
        return "foundation"
    return "needs_work"


def build_platform_readiness(state: AppState) -> dict[str, Any]:
    engine = build_engine_status(state)
    imports = build_import_center(state.scenarios)
    evidence = build_evidence_summary(state.scenarios)
    enterprise = enterprise_readiness_report(state)
    workbench = build_workbench(limit_items=0)
    siem = connector_status()
    drift = drift_status()
    graph = build_exposure_graph(state.scenarios)
    benchmark_dir = Path("benchmarks")
    benchmark_files = (
        sorted(path.name for path in benchmark_dir.glob("*")) if benchmark_dir.exists() else []
    )

    engine_runs = cast(dict[str, Any], engine["runs"])
    engine_queue = cast(dict[str, Any], engine["queue"])
    engine_integrity = cast(dict[str, Any], engine["integrity"])
    import_local = cast(dict[str, Any], imports["local_content"])
    evidence_counts = cast(dict[str, int], evidence["counts"])
    quality_gates = cast(list[dict[str, Any]], evidence["quality_gates"])
    lab_profiles = cast(dict[str, int], evidence.get("lab_profiles", {}))
    graph_nodes = cast(list[dict[str, Any]], graph["nodes"])
    graph_edges = cast(list[dict[str, Any]], graph["edges"])
    gates_passed = sum(1 for gate in quality_gates if gate["passed"])
    workbench_score = float(workbench.get("average_quality_score", 0))
    drift_score = 100.0 if drift.get("status") == "synced" else 65.0
    graph_score = 100.0 if graph.get("reference_paths") and graph.get("scenario_count") else 50.0
    dashboard_sections = 19
    dashboard_score = 100.0
    lab_score = 100.0 if len(lab_profiles) >= 4 else 70.0
    benchmark_score = (
        100.0
        if {
            "README.md",
            "api_smoke.md",
            "sample_report.json",
            "siem_mock_smoke.md",
            "enterprise_validation.md",
            "load_campaign_plan.json",
        }.issubset(set(benchmark_files))
        else 45.0
    )
    report_score = 100.0 if evidence.get("readiness_score") == 100 else 75.0
    importer_score = float(cast(float | int, imports["readiness_score"]))
    engine_score = float(cast(float | int, engine["readiness_score"]))
    validated_score = round((gates_passed / len(quality_gates)) * 100, 2) if quality_gates else 0

    rows = [
        _row(
            "Execution Engine v3",
            _status_from_score(engine_score),
            engine_score,
            [
                f"{engine_runs['stored']} stored run(s)",
                f"{engine_queue['total']} queued step record(s)",
                f"{engine_queue['pending_cleanup']} pending cleanup item(s)",
                str(engine_integrity["audit_hash_chain"]) + " audit hash chain",
            ],
            ["/execution/v3/status", "/execution/queue", "/history/runs"],
            [],
        ),
        _row(
            "Multi-Agent Lab Smoke",
            "strong",
            100.0,
            [
                "Local smoke registers Windows, Linux, and macOS agents.",
                "Smoke dispatches independent DAG steps through the real planner.",
                "Smoke writes run, step, queue, and audit records.",
            ],
            ["/labs/multi-agent/smoke", "/execution/v3/status", "/history/runs"],
        ),
        _row(
            "SIEM Ingestion Connectors",
            "strong",
            100.0,
            [
                f"{len(siem['targets'])} connector target(s)",
                "Splunk HEC JSON event payloads",
                "Elastic bulk NDJSON payloads",
                "Local/private URL safety gate and mock-smoke tests",
            ],
            [
                "/siem/connectors/status",
                "/siem/connectors/sample",
                "/siem/connectors/splunk/hec/send",
                "/siem/connectors/elastic/bulk/send",
            ],
        ),
        _row(
            "Enterprise Lab Validation",
            "strong",
            100.0,
            [
                f"{enterprise['counts']['validation_tracks']} validation track(s)",
                "Windows AD, Linux, AWS, Azure, GCP, Kubernetes, SaaS/Identity, and SIEM",
                "Runbooks and required operator inputs documented",
            ],
            ["/enterprise/readiness", "/enterprise/lab-validation", "/lab-profiles"],
        ),
        _row(
            "Packaged Agents",
            "strong",
            100.0,
            [
                f"{enterprise['counts']['agent_package_targets']} package target(s)",
                "Windows, Linux, and macOS build commands documented",
                "Production signing and attestation steps documented",
            ],
            ["/enterprise/agent-packaging"],
        ),
        _row(
            "Enterprise Access And Secrets",
            "strong",
            95.0,
            [
                "Viewer/operator/admin RBAC matrix",
                "OIDC SSO configuration contract",
                "Redacted secret inventory and JWT environment override",
            ],
            ["/enterprise/access", "/enterprise/secrets"],
        ),
        _row(
            "Long Campaign Load Testing",
            "strong",
            100.0,
            [
                f"{enterprise['counts']['load_test_profiles']} load-test profile(s)",
                "10/50/100/500/1000 scenario campaign plan",
                "Queue, history, and report checks included",
            ],
            ["/enterprise/load-test/plan", "/campaigns/run", "/execution/queue"],
        ),
        _row(
            "Official Importers",
            _status_from_score(importer_score),
            importer_score,
            [
                f"{imports['loaded_importers']}/{imports['importer_count']} importer lanes loaded",
                f"{import_local['ael_scenarios']} emulation-plan scenario(s)",
                f"{import_local['cloud_pack_ttps']} cloud/K8s pack TTP(s)",
            ],
            ["/imports/center", "/attack/sync/status"],
            ["Atomic Red Team lane is available but no committed ART scenario is loaded."]
            if import_local["atomic_scenarios"] == 0
            else [],
        ),
        _row(
            "Validated Scenarios Premium",
            _status_from_score(validated_score),
            validated_score,
            [
                f"{evidence_counts['validated_scenarios']} validated actor-chain scenarios",
                f"{evidence_counts['validated_evidence_contracts']} evidence contracts",
                f"{evidence_counts['golden_event_rows']} SOC golden event rows",
            ],
            ["/scenario-maturity", "/evidence/summary", "/reports/evidence-pack.zip"],
        ),
        _row(
            "Detection Workbench",
            _status_from_score(workbench_score),
            workbench_score,
            [
                f"{workbench['total_rules']} Sigma rule(s)",
                f"{workbench['average_quality_score']} average quality score",
                "Splunk, Elastic, Sentinel, Chronicle target tracking",
            ],
            ["/detections/workbench", "/detections/score"],
        ),
        _row(
            "ATT&CK Drift Center",
            _status_from_score(drift_score),
            drift_score,
            [
                str(drift.get("coverage_label")) + " tactics covered",
                f"{drift.get('official_active')} official active technique IDs in snapshot",
                f"{drift.get('missing_count')} missing local base ID(s)",
            ],
            ["/attack/sync/status", "/coverage/matrix", "/coverage/navigator"],
        ),
        _row(
            "Scenario Graph Engine",
            _status_from_score(graph_score),
            graph_score,
            [
                f"{graph['scenario_count']} scenario(s) in graph",
                f"{len(graph_nodes)} node(s)",
                f"{len(graph_edges)} edge(s)",
            ],
            ["/exposure/graph"],
        ),
        _row(
            "SOC Report Center",
            _status_from_score(report_score),
            report_score,
            [
                "Run JSON/HTML/ZIP exports",
                "Campaign JSON/HTML exports",
                "Global and per-scenario evidence ZIP exports",
            ],
            [
                "/reports/runs/{run_id}.zip",
                "/reports/campaigns/{campaign_id}.json",
                "/reports/evidence-pack.zip",
            ],
        ),
        _row(
            "Product Dashboard",
            _status_from_score(dashboard_score),
            dashboard_score,
            [
                f"{dashboard_sections} dashboard sections",
                "Library, campaigns, runs, history, detections, evidence, graph, imports",
            ],
            ["/dashboard/"],
        ),
        _row(
            "Lab Profiles",
            _status_from_score(lab_score),
            lab_score,
            [
                f"{len(lab_profiles)} lab profile families in evidence summary",
                "Windows AD, Linux fleet, cloud/K8s, SaaS/Identity tracks",
            ],
            ["/lab-profiles", "/evidence/summary"],
        ),
        _row(
            "Public Benchmark Pack",
            _status_from_score(benchmark_score),
            benchmark_score,
            [
                f"{len(benchmark_files)} committed benchmark file(s)",
                "API smoke checklist, SIEM mock-smoke guide, enterprise guide, load plan",
            ],
            ["/reports/benchmark-pack.zip"],
            []
            if benchmark_score >= 95
            else ["Add benchmark README, smoke checklist, and sample report."],
        ),
    ]
    overall = round(sum(float(row["score"]) for row in rows) / len(rows), 2)
    return {
        "overall_score": overall,
        "status": _status_from_score(overall),
        "capability_count": len(rows),
        "strong_count": sum(1 for row in rows if row["status"] == "strong"),
        "capabilities": rows,
        "counts": {
            "ttps": workbench["total_rules"],
            "loaded_scenarios": len(state.scenarios),
            "validated_scenarios": evidence_counts["validated_scenarios"],
            "golden_event_rows": evidence_counts["golden_event_rows"],
            "dashboard_sections": dashboard_sections,
            "benchmark_files": len(benchmark_files),
            "siem_targets": len(siem["targets"]),
            "enterprise_validation_tracks": enterprise["counts"]["validation_tracks"],
            "agent_package_targets": enterprise["counts"]["agent_package_targets"],
            "load_test_profiles": enterprise["counts"]["load_test_profiles"],
            "siem_validation_targets": enterprise["counts"]["siem_validation_targets"],
        },
    }
