"""Importable real-lab evidence registry for scenarios, TTPs, and SIEM traces."""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator

from .dsl.schema import Scenario


EVIDENCE_SOURCES = (
    "windows_ad",
    "linux",
    "aws",
    "azure",
    "gcp",
    "kubernetes",
    "saas_identity",
    "splunk",
    "elastic",
    "sentinel",
    "chronicle",
)
EVIDENCE_TYPES = (
    "host_log",
    "siem_export",
    "screenshot",
    "agent_run",
    "campaign_report",
    "packet_capture",
    "cloud_audit",
)


class LabEvidenceRecord(BaseModel):
    id: str = Field(default_factory=lambda: f"lab-evidence-{uuid.uuid4().hex[:12]}")
    source: str
    evidence_type: str
    scenario: str
    attack_ids: list[str] = Field(default_factory=list)
    environment: str = "user-owned-lab"
    captured_at: float = Field(default_factory=time.time)
    artifact_ref: str
    artifact_sha256: str = ""
    siem_rule_ids: list[str] = Field(default_factory=list)
    notes: str = ""

    @field_validator("source")
    @classmethod
    def _valid_source(cls, value: str) -> str:
        if value not in EVIDENCE_SOURCES:
            raise ValueError(f"source must be one of {EVIDENCE_SOURCES}")
        return value

    @field_validator("evidence_type")
    @classmethod
    def _valid_evidence_type(cls, value: str) -> str:
        if value not in EVIDENCE_TYPES:
            raise ValueError(f"evidence_type must be one of {EVIDENCE_TYPES}")
        return value

    @field_validator("attack_ids")
    @classmethod
    def _valid_attack_ids(cls, values: list[str]) -> list[str]:
        for value in values:
            base = value.upper().removeprefix("T").split(".", 1)[0]
            if not value.upper().startswith("T") or not base.isdigit():
                raise ValueError(f"invalid ATT&CK ID: {value}")
        return [value.upper() for value in values]


def evidence_template() -> dict[str, Any]:
    return {
        "source": "splunk",
        "evidence_type": "siem_export",
        "scenario": "validated_apt29_identity_cloud_chain",
        "attack_ids": ["T1078", "T1087", "T1059"],
        "environment": "user-owned-lab",
        "artifact_ref": "s3://security-lab-evidence/example/splunk-export.json",
        "artifact_sha256": "<sha256-of-export-or-screenshot>",
        "siem_rule_ids": ["sigma:T1078"],
        "notes": "Evidence captured from an authorized lab campaign.",
    }


def append_lab_evidence(record: LabEvidenceRecord, path: str | Path) -> LabEvidenceRecord:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    if not record.artifact_sha256:
        digest_source = json.dumps(
            record.model_dump(mode="json", exclude={"artifact_sha256"}),
            sort_keys=True,
            separators=(",", ":"),
        )
        record.artifact_sha256 = hashlib.sha256(digest_source.encode("utf-8")).hexdigest()
    with out.open("a", encoding="utf-8") as handle:
        handle.write(record.model_dump_json() + "\n")
    return record


def load_lab_evidence(path: str | Path) -> list[LabEvidenceRecord]:
    src = Path(path)
    if not src.exists():
        return []
    records: list[LabEvidenceRecord] = []
    with src.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            records.append(LabEvidenceRecord.model_validate_json(line))
    return records


def lab_evidence_summary(
    scenarios: dict[str, Scenario],
    path: str | Path,
) -> dict[str, Any]:
    records = load_lab_evidence(path)
    source_counts: dict[str, int] = {}
    type_counts: dict[str, int] = {}
    scenarios_with_evidence: set[str] = set()
    attack_ids: set[str] = set()
    siem_sources = {"splunk", "elastic", "sentinel", "chronicle"}
    siem_targets: set[str] = set()
    unknown_scenarios: set[str] = set()
    for record in records:
        source_counts[record.source] = source_counts.get(record.source, 0) + 1
        type_counts[record.evidence_type] = type_counts.get(record.evidence_type, 0) + 1
        scenarios_with_evidence.add(record.scenario)
        attack_ids.update(record.attack_ids)
        if record.source in siem_sources:
            siem_targets.add(record.source)
        if record.scenario not in scenarios:
            unknown_scenarios.add(record.scenario)
    return {
        "status": "evidence-imported" if records else "ready-for-real-lab-evidence",
        "records": len(records),
        "sources": source_counts,
        "evidence_types": type_counts,
        "scenarios_with_real_lab_evidence": len(scenarios_with_evidence),
        "ttps_with_real_lab_evidence": len(attack_ids),
        "siem_targets_with_real_lab_evidence": sorted(siem_targets),
        "unknown_scenarios": sorted(unknown_scenarios),
        "template": evidence_template(),
        "evidence": [
            f"{len(records)} imported real-lab evidence record(s)",
            f"{len(scenarios_with_evidence)} scenario(s) with external lab evidence",
            f"{len(attack_ids)} ATT&CK ID(s) with external lab evidence",
            "Append-only JSONL registry with artifact SHA-256 tracking",
        ],
    }
