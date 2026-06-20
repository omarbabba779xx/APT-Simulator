from __future__ import annotations

from fastapi.testclient import TestClient

from orchestrator.lab_evidence import (
    LabEvidenceRecord,
    append_lab_evidence,
    lab_evidence_summary,
    load_lab_evidence,
)
from orchestrator.main import build_app


def test_lab_evidence_registry_roundtrip(tmp_path) -> None:
    path = tmp_path / "lab_evidence.jsonl"
    record = append_lab_evidence(
        LabEvidenceRecord(
            source="splunk",
            evidence_type="siem_export",
            scenario="validated_apt29_identity_cloud_chain",
            attack_ids=["t1078", "T1059.001"],
            artifact_ref="file:///lab/splunk-export.json",
        ),
        path,
    )

    loaded = load_lab_evidence(path)
    summary = lab_evidence_summary(
        {"validated_apt29_identity_cloud_chain": object()},  # type: ignore[dict-item]
        path,
    )

    assert loaded[0].id == record.id
    assert loaded[0].attack_ids == ["T1078", "T1059.001"]
    assert len(record.artifact_sha256) == 64
    assert summary["status"] == "evidence-imported"
    assert summary["records"] == 1
    assert summary["sources"] == {"splunk": 1}
    assert summary["scenarios_with_real_lab_evidence"] == 1
    assert summary["ttps_with_real_lab_evidence"] == 2
    assert summary["siem_targets_with_real_lab_evidence"] == ["splunk"]


def test_lab_evidence_api_uses_configured_registry(tmp_path) -> None:
    evidence_path = tmp_path / "lab_evidence.jsonl"
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "\n".join(
            [
                "orchestrator:",
                f"  lab_evidence_path: {evidence_path.as_posix()}",
                "security:",
                "  require_auth: false",
            ]
        ),
        encoding="utf-8",
    )
    client = TestClient(build_app(str(config_path)))

    template = client.get("/lab-evidence/template")
    assert template.status_code == 200
    assert template.json()["source"] == "splunk"

    imported = client.post(
        "/lab-evidence/import",
        json={
            "source": "sentinel",
            "evidence_type": "siem_export",
            "scenario": "validated_apt29_identity_cloud_chain",
            "attack_ids": ["T1078"],
            "artifact_ref": "file:///lab/sentinel-export.json",
            "siem_rule_ids": ["sigma:T1078"],
        },
    )
    assert imported.status_code == 200
    assert imported.json()["source"] == "sentinel"

    summary = client.get("/lab-evidence/summary")
    assert summary.status_code == 200
    assert summary.json()["records"] == 1
    assert summary.json()["sources"] == {"sentinel": 1}
