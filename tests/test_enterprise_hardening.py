from __future__ import annotations

import io
import zipfile

from fastapi.testclient import TestClient

from orchestrator.main import build_app


def test_enterprise_hardening_endpoints_are_verifiable() -> None:
    client = TestClient(build_app("config/default.yaml"))

    hardening = client.get("/enterprise/hardening").json()
    assert hardening["status"] == "enterprise-hardening-ready"
    assert hardening["area_count"] == 8
    assert hardening["summary"]["cloud_sandbox_profiles"] == 4
    assert hardening["summary"]["secret_backend_lanes"] == 6

    quality = client.get("/enterprise/quality/ttps").json()
    assert quality["total_ttps"] == 5064
    assert quality["sigma_backed_ttps"] == 5064
    assert quality["quality_lanes"]["catalog_scale_detection_engineering"] > 0

    fleet = client.get("/enterprise/fleet/readiness").json()
    assert fleet["heartbeat_sla_seconds"] == 300
    assert "service wrappers for Windows, Linux, and macOS" in fleet["controls"]

    imports = client.get("/enterprise/import-fidelity").json()
    assert imports["importer_count"] == 5
    assert imports["attack_drift_status"] == "synced"

    cloud = client.get("/enterprise/cloud-sandbox/readiness").json()
    assert cloud["profile_count"] == 4
    assert cloud["live_cloud_api_execution_default"] is False
    assert {"aws", "azure", "gcp", "kubernetes"} <= set(cloud["profiles"])


def test_enterprise_compliance_performance_and_backup_zip() -> None:
    client = TestClient(build_app("config/default.yaml"))

    secrets = client.get("/enterprise/secrets/backends").json()
    assert secrets["backend_count"] == 6
    assert all(item["material"] == "redacted" for item in secrets["backends"])

    plan = client.get("/enterprise/performance/plan").json()
    assert plan["profile_count"] == 5
    assert plan["max_profile_scenarios"] == 1000

    smoke = client.post("/enterprise/performance/smoke", params={"scenario_count": 5}).json()
    assert smoke["status"] == "completed"
    assert smoke["scenario_count"] == 5
    assert smoke["step_count"] >= 5

    compliance = client.get("/enterprise/compliance/readiness").json()
    assert compliance["retention_days"] == 90
    assert "backup ZIP export" in compliance["controls"]

    proof = client.get("/enterprise/public-proof/readiness").json()
    assert proof["file_count"] == proof["expected_file_count"]

    backup = client.get("/reports/backup-export.zip")
    assert backup.status_code == 200
    with zipfile.ZipFile(io.BytesIO(backup.content)) as archive:
        names = set(archive.namelist())
        assert "backup_manifest.json" in names
        assert "README.md" in names
