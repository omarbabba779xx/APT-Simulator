from __future__ import annotations

import io
import json
import zipfile

from fastapi.testclient import TestClient

from orchestrator.enterprise import (
    agent_packaging_report,
    build_audit_export_zip,
    enterprise_readiness_report,
    load_test_plan,
    secrets_status,
)
from orchestrator.core.audit import AuditLog
from orchestrator.main import build_app


def test_enterprise_reports_have_exact_counts() -> None:
    client = TestClient(build_app("config/default.yaml"))

    readiness = client.get("/enterprise/readiness").json()
    assert readiness["status"] == "enterprise-lab-ready"
    assert readiness["counts"]["validation_tracks"] == 11
    assert readiness["counts"]["agent_package_targets"] == 3
    assert readiness["counts"]["load_test_profiles"] == 5
    assert readiness["counts"]["siem_validation_targets"] == 4
    assert readiness["counts"]["real_lab_evidence_records"] >= 0
    assert readiness["counts"]["enterprise_hardening_areas"] == 8
    assert readiness["validation"]["track_count"] == 11

    access = client.get("/enterprise/access").json()
    assert access["roles"] == ["viewer", "operator", "admin"]
    assert access["sso"]["provider"] == "oidc"

    packaging = client.get("/enterprise/agent-packaging").json()
    assert packaging["target_count"] == 3
    assert {item["platform"] for item in packaging["targets"]} == {"windows", "linux", "macos"}
    assert "packaging/linux/apt-agent.service" in packaging["files"]

    load_plan = client.get("/enterprise/load-test/plan").json()
    assert load_plan["max_documented_campaign_size"] == 1000
    assert [item["scenario_count"] for item in load_plan["profiles"]] == [10, 50, 100, 500, 1000]

    siem = client.get("/enterprise/siem-validation").json()
    assert siem["target_count"] == 4
    assert {item["name"] for item in siem["targets"]} == {
        "splunk",
        "elastic",
        "sentinel",
        "chronicle",
    }


def test_enterprise_helpers_are_redacted_and_consistent() -> None:
    build_app("config/default.yaml")

    packaging = agent_packaging_report()
    assert packaging["target_count"] == 3

    plan = load_test_plan()
    assert plan["profile_count"] == 5

    from orchestrator.api.state import get_state

    report = enterprise_readiness_report(get_state())
    secrets = secrets_status(get_state().config)
    assert report["counts"]["validation_tracks"] == 11
    assert report["counts"]["real_lab_evidence_records"] >= 0
    assert report["counts"]["enterprise_hardening_areas"] == 8
    assert all(item["material"] == "redacted" for item in secrets["files"])
    assert all(item["material"] == "redacted" for item in secrets["env_overrides"])


def test_audit_export_zip_contains_manifest_and_jsonl() -> None:
    client = TestClient(build_app("config/default.yaml"))
    response = client.get("/reports/audit-export.zip")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        names = set(archive.namelist())
        assert {"audit_manifest.json", "audit.jsonl", "README.md"} <= names
        manifest = json.loads(archive.read("audit_manifest.json"))
        assert isinstance(manifest["chain_valid"], bool)
        assert manifest["records"] >= 1


def test_audit_export_zip_verifies_clean_audit(tmp_path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    audit = AuditLog(audit_path)
    audit.append("test.event", {"ok": True})

    with zipfile.ZipFile(io.BytesIO(build_audit_export_zip(audit_path))) as archive:
        manifest = json.loads(archive.read("audit_manifest.json"))
        assert manifest["chain_valid"] is True
        assert manifest["records"] == 1
