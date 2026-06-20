"""Public benchmark pack export."""
from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from typing import Any, cast

from .api.state import AppState
from .enterprise import (
    access_readiness_report,
    agent_packaging_report,
    enterprise_readiness_report,
    lab_validation_report,
    load_test_plan,
    siem_validation_report,
)
from .evidence_center import build_evidence_summary
from .execution_engine_v3 import build_engine_status
from .import_center import build_import_center
from .platform_readiness import build_platform_readiness


BENCHMARK_FILES = (
    Path("benchmarks/README.md"),
    Path("benchmarks/api_smoke.md"),
    Path("benchmarks/siem_mock_smoke.md"),
    Path("benchmarks/enterprise_validation.md"),
    Path("benchmarks/load_campaign_plan.json"),
    Path("benchmarks/sample_report.json"),
)


def build_benchmark_manifest(state: AppState) -> dict[str, Any]:
    evidence = build_evidence_summary(state.scenarios)
    readiness = build_platform_readiness(state)
    quality_gates = cast(list[dict[str, Any]], evidence["quality_gates"])
    return {
        "name": "APT Simulator public benchmark pack",
        "purpose": (
            "Reproducible local verification of counts, readiness, evidence, imports, "
            "and reports."
        ),
        "counts": readiness["counts"],
        "overall_score": readiness["overall_score"],
        "status": readiness["status"],
        "evidence_readiness_score": evidence["readiness_score"],
        "quality_gates_passed": sum(1 for gate in quality_gates if gate["passed"]),
        "quality_gates_total": len(quality_gates),
        "files": [str(path).replace("\\", "/") for path in BENCHMARK_FILES if path.exists()],
        "api_checks": [
            "/healthz",
            "/platform/readiness",
            "/execution/v3/status",
            "/imports/center",
            "/siem/connectors/status",
            "/siem/connectors/sample",
            "POST /labs/multi-agent/smoke",
            "/enterprise/readiness",
            "/enterprise/access",
            "/enterprise/lab-validation",
            "/enterprise/agent-packaging",
            "/enterprise/load-test/plan",
            "/enterprise/siem-validation",
            "/reports/audit-export.zip",
            "/evidence/summary",
            "/detections/workbench",
            "/attack/sync/status",
            "/exposure/graph",
            "/reports/evidence-pack.zip",
        ],
    }


def build_benchmark_zip(state: AppState) -> bytes:
    bundle = io.BytesIO()
    manifest = build_benchmark_manifest(state)
    with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True))
        archive.writestr(
            "api/platform_readiness.json",
            json.dumps(build_platform_readiness(state), indent=2, sort_keys=True),
        )
        archive.writestr(
            "api/execution_engine_v3.json",
            json.dumps(build_engine_status(state), indent=2, sort_keys=True),
        )
        archive.writestr(
            "api/import_center.json",
            json.dumps(build_import_center(state.scenarios), indent=2, sort_keys=True),
        )
        archive.writestr(
            "api/evidence_summary.json",
            json.dumps(build_evidence_summary(state.scenarios), indent=2, sort_keys=True),
        )
        archive.writestr(
            "api/enterprise_readiness.json",
            json.dumps(enterprise_readiness_report(state), indent=2, sort_keys=True),
        )
        archive.writestr(
            "api/enterprise_access.json",
            json.dumps(access_readiness_report(state.config), indent=2, sort_keys=True),
        )
        archive.writestr(
            "api/enterprise_lab_validation.json",
            json.dumps(lab_validation_report(state), indent=2, sort_keys=True),
        )
        archive.writestr(
            "api/enterprise_agent_packaging.json",
            json.dumps(agent_packaging_report(), indent=2, sort_keys=True),
        )
        archive.writestr(
            "api/enterprise_load_test_plan.json",
            json.dumps(load_test_plan(), indent=2, sort_keys=True),
        )
        archive.writestr(
            "api/enterprise_siem_validation.json",
            json.dumps(siem_validation_report(), indent=2, sort_keys=True),
        )
        for path in BENCHMARK_FILES:
            if path.exists():
                archive.write(path, str(path).replace("\\", "/"))
        if Path("README.md").exists():
            archive.write("README.md", "project/README.md")
        if Path("docs/PUBLIC_EVIDENCE.md").exists():
            archive.write("docs/PUBLIC_EVIDENCE.md", "project/docs/PUBLIC_EVIDENCE.md")
        if Path("docs/ENTERPRISE_VALIDATION.md").exists():
            archive.write("docs/ENTERPRISE_VALIDATION.md", "project/docs/ENTERPRISE_VALIDATION.md")
        if Path("docs/PRODUCTION_DEPLOYMENT.md").exists():
            archive.write("docs/PRODUCTION_DEPLOYMENT.md", "project/docs/PRODUCTION_DEPLOYMENT.md")
    return bundle.getvalue()


def sample_benchmark_report() -> dict[str, Any]:
    return {
        "benchmark": "local_api_smoke",
        "expected": {
            "ttps": 5064,
            "loaded_scenarios": 3522,
            "validated_scenarios": 1000,
            "golden_event_rows": 2000,
            "attack_tactics": "15/15",
            "enterprise_validation_tracks": 11,
            "agent_package_targets": 3,
            "load_test_profiles": 5,
            "siem_validation_targets": 4,
        },
        "required_endpoints": [
            "/healthz",
            "/platform/readiness",
            "/execution/v3/status",
            "/imports/center",
            "/siem/connectors/status",
            "/siem/connectors/sample",
            "POST /labs/multi-agent/smoke",
            "/enterprise/readiness",
            "/enterprise/load-test/plan",
            "/evidence/summary",
            "/reports/benchmark-pack.zip",
        ],
    }
