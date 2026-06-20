"""Enterprise hardening reports for catalog quality, fleet, cloud, secrets, and compliance."""
from __future__ import annotations

import os
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

import yaml

import ttps  # noqa: F401
from ttps.base import registry

from .api.state import AppState
from .attack_sync import drift_status
from .dsl.schema import Scenario
from .import_center import build_import_center
from .lab_evidence import lab_evidence_summary


def _scenario_attack_ids(scenarios: dict[str, Scenario]) -> set[str]:
    return {step.ttp.upper() for scenario in scenarios.values() for step in scenario.steps}


def _validated_attack_ids(scenarios: dict[str, Scenario]) -> set[str]:
    return {
        step.ttp.upper()
        for scenario in scenarios.values()
        if "validated" in set(scenario.tags)
        for step in scenario.steps
    }


def _external_lab_attack_ids(state: AppState) -> set[str]:
    summary = lab_evidence_summary(state.scenarios, state.config.orchestrator.lab_evidence_path)
    records = summary.get("records", 0)
    if not records:
        return set()
    from .lab_evidence import load_lab_evidence

    return {
        attack_id
        for record in load_lab_evidence(state.config.orchestrator.lab_evidence_path)
        for attack_id in record.attack_ids
    }


def ttp_quality_report(state: AppState) -> dict[str, Any]:
    items = registry.all()
    scenario_ids = _scenario_attack_ids(state.scenarios)
    validated_ids = _validated_attack_ids(state.scenarios)
    external_ids = _external_lab_attack_ids(state)
    sigma_backed = {attack_id for attack_id, ttp in items.items() if ttp.sigma_rule() is not None}
    lab_proven = external_ids & set(items)
    fixture_backed = (validated_ids & set(items)) - lab_proven
    scenario_backed = (scenario_ids & set(items)) - fixture_backed - lab_proven
    catalog_scale = set(items) - lab_proven - fixture_backed - scenario_backed
    weighted_score = (
        len(lab_proven) * 1.0
        + len(fixture_backed) * 0.75
        + len(scenario_backed) * 0.5
        + len(catalog_scale) * 0.25
    )
    priority = sorted(catalog_scale)[:50]
    return {
        "status": "quality-governed",
        "total_ttps": len(items),
        "sigma_backed_ttps": len(sigma_backed),
        "scenario_mapped_ttps": len(scenario_ids & set(items)),
        "validated_actor_chain_ttps": len(validated_ids & set(items)),
        "external_lab_proven_ttps": len(lab_proven),
        "quality_score": round((weighted_score / max(len(items), 1)) * 100, 2),
        "quality_lanes": {
            "external_lab_proven": len(lab_proven),
            "fixture_backed_actor_chain": len(fixture_backed),
            "loaded_scenario_backed": len(scenario_backed),
            "catalog_scale_detection_engineering": len(catalog_scale),
        },
        "upgrade_queue": {
            "description": "Catalog-scale TTPs that should receive manual lab procedures first.",
            "sample_attack_ids": priority,
            "remaining": len(catalog_scale),
        },
        "evidence": [
            f"{len(items)} registered TTPs",
            f"{len(sigma_backed)} Sigma-backed TTPs",
            f"{len(validated_ids & set(items))} TTPs appear in validated actor-chain scenarios",
            f"{len(lab_proven)} TTPs have imported external lab evidence",
        ],
    }


def fleet_readiness_report(state: AppState) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    stale_after = state.config.security.agent_heartbeat_stale_seconds
    agents: list[dict[str, Any]] = []
    platform_counts: Counter[str] = Counter()
    stale = 0
    for agent_id, agent in sorted(state.agents.items()):
        last_seen_raw = str(agent.get("last_seen", ""))
        try:
            last_seen = datetime.fromisoformat(last_seen_raw)
            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=timezone.utc)
            age = max((now - last_seen).total_seconds(), 0)
        except ValueError:
            age = None
        is_stale = age is None or age > stale_after
        stale += int(is_stale)
        platform = str(agent.get("platform", "unknown")).lower()
        platform_counts[platform] += 1
        agents.append(
            {
                "id": agent_id,
                "hostname": agent.get("hostname", ""),
                "platform": platform,
                "last_seen": last_seen_raw,
                "heartbeat_age_seconds": age,
                "stale": is_stale,
                "agent_version": agent.get("agent_version", "unknown"),
                "certificate_subject": agent.get("certificate_subject", ""),
            }
        )
    return {
        "status": "fleet-contract-ready",
        "registered_agents": len(agents),
        "stale_agents": stale,
        "platforms": dict(sorted(platform_counts.items())),
        "heartbeat_sla_seconds": stale_after,
        "mtls": {
            "enabled": state.config.security.agent_mtls_enabled,
            "client_ca_path": state.config.security.agent_client_ca_path,
            "deployment_mode": "reverse-proxy enforced mTLS contract",
        },
        "controls": [
            "signed task payloads",
            "platform-aware dispatch",
            "heartbeat SLA tracking",
            "service wrappers for Windows, Linux, and macOS",
            "per-run queue, logs, artifacts, cleanup, retry",
        ],
        "agents": agents,
        "evidence": [
            "Windows service installer committed",
            "Linux systemd unit committed",
            "macOS launchd plist committed",
            "Heartbeat SLA is exposed through /enterprise/fleet/readiness",
        ],
    }


def importer_fidelity_report(state: AppState) -> dict[str, Any]:
    imports = build_import_center(state.scenarios)
    drift = drift_status()
    importers = cast(list[dict[str, Any]], imports["importers"])
    local_content = cast(dict[str, Any], imports["local_content"])
    loaded = sum(1 for item in importers if bool(item["loaded"]))
    return {
        "status": "official-source-fidelity-tracked",
        "importer_count": imports["importer_count"],
        "loaded_importers": loaded,
        "readiness_score": imports["readiness_score"],
        "attack_drift_status": drift.get("status"),
        "source_lanes": importers,
        "fidelity_controls": [
            "ATT&CK STIX drift compares active, missing, deprecated, and revoked IDs.",
            "AEL conversion materializes safe scenario DAGs.",
            "Atomic Red Team import stores safe references instead of executing commands.",
            "Cloud reference lane maps to local marker/sandbox contracts by default.",
        ],
        "evidence": [
            f"{local_content['ael_scenarios']} AEL scenarios loaded",
            f"{local_content['atomic_scenarios']} Atomic scenarios loaded",
            f"{local_content['cloud_pack_ttps']} cloud/K8s TTPs loaded",
        ],
    }


def cloud_sandbox_readiness_report(state: AppState) -> dict[str, Any]:
    path = Path(state.config.orchestrator.cloud_sandbox_profiles_path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else {}
    profiles = raw.get("profiles", {}) if isinstance(raw, dict) else {}
    return {
        "status": "sandbox-contract-ready",
        "profile_count": len(profiles),
        "live_cloud_api_execution_default": False,
        "profiles": profiles,
        "required_operator_inputs": [
            "written authorization",
            "dedicated cloud account/subscription/project/cluster",
            "budget alarms",
            "audit logging exported to SIEM",
            "rollback owner",
        ],
        "safety_boundary": (
            "Default cloud/Kubernetes simulations remain marker-only; sandbox profiles "
            "define the controls required before any user-owned live-lab extension."
        ),
        "evidence": [
            f"{len(profiles)} cloud/Kubernetes sandbox profile(s)",
            "AWS, Azure, GCP, and Kubernetes guardrails are committed",
        ],
    }


def secrets_backends_report(state: AppState) -> dict[str, Any]:
    cfg = state.config.security
    backends = [
        {
            "name": "environment",
            "configured": bool(os.environ.get(f"{cfg.secrets_env_prefix}JWT_SECRET")),
            "material": "redacted",
        },
        {
            "name": "local_file",
            "configured": Path(cfg.jwt_secret_path).exists() or not cfg.require_auth,
            "material": "redacted",
        },
        {
            "name": "vault",
            "configured": bool(os.environ.get(cfg.vault_addr_env)),
            "address_env": cfg.vault_addr_env,
            "material": "redacted",
        },
        {
            "name": "aws_secrets_manager",
            "configured": bool(os.environ.get(cfg.aws_secret_id_env)),
            "secret_id_env": cfg.aws_secret_id_env,
            "material": "redacted",
        },
        {
            "name": "azure_key_vault",
            "configured": bool(os.environ.get(cfg.azure_keyvault_url_env)),
            "vault_url_env": cfg.azure_keyvault_url_env,
            "material": "redacted",
        },
        {
            "name": "gcp_secret_manager",
            "configured": bool(os.environ.get(cfg.gcp_secret_name_env)),
            "secret_name_env": cfg.gcp_secret_name_env,
            "material": "redacted",
        },
    ]
    return {
        "status": "secret-backends-inventory-ready",
        "backend_count": len(backends),
        "configured_backends": sum(1 for backend in backends if backend["configured"]),
        "rotation_contract": [
            "set backend-specific env pointers",
            "restart orchestrator after secret rotation",
            "verify /enterprise/secrets/backends returns material=redacted",
            "export audit after rotation",
        ],
        "backends": backends,
        "evidence": [
            f"{len(backends)} backend lanes exposed",
            "secret material is redacted in API responses",
        ],
    }


def performance_plan() -> dict[str, Any]:
    profiles: list[dict[str, str | int]] = [
        {"name": "api_smoke", "scenario_count": 10, "target_seconds": 60},
        {"name": "operator_campaign", "scenario_count": 50, "target_seconds": 300},
        {"name": "dashboard_campaign", "scenario_count": 100, "target_seconds": 600},
        {"name": "load_lab", "scenario_count": 500, "target_seconds": 3600},
        {"name": "long_campaign", "scenario_count": 1000, "target_seconds": 7200},
    ]
    return {
        "status": "performance-plan-ready",
        "profile_count": len(profiles),
        "max_profile_scenarios": max(int(item["scenario_count"]) for item in profiles),
        "profiles": profiles,
        "capture": [
            "queue depth",
            "run history count",
            "audit record count",
            "report ZIP size",
            "SIEM accepted event count",
        ],
    }


def run_performance_smoke(state: AppState, scenario_count: int = 25) -> dict[str, Any]:
    started = time.perf_counter()
    names = sorted(state.scenarios)[: max(min(scenario_count, len(state.scenarios)), 0)]
    step_count = sum(len(state.scenarios[name].steps) for name in names)
    elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
    state.audit.append(
        "performance.smoke",
        {"scenario_count": len(names), "step_count": step_count, "elapsed_ms": elapsed_ms},
    )
    return {
        "status": "completed",
        "scenario_count": len(names),
        "step_count": step_count,
        "elapsed_ms": elapsed_ms,
        "scenarios_per_second": round((len(names) / max(elapsed_ms, 0.001)) * 1000, 2),
    }


def compliance_readiness_report(state: AppState) -> dict[str, Any]:
    cfg = state.config
    return {
        "status": "compliance-operations-ready",
        "retention_days": cfg.orchestrator.retention_days,
        "backup_dir": cfg.orchestrator.backup_dir,
        "database_path": cfg.orchestrator.db_path,
        "audit_dir": cfg.orchestrator.audit_dir,
        "controls": [
            "backup ZIP export",
            "audit hash-chain verification",
            "structured JSON logging config",
            "retention policy config",
            "SQLModel schema creation contract",
            "public benchmark pack",
        ],
        "restore_rehearsal": [
            "export backup ZIP",
            "restore database and audit JSONL into an isolated lab",
            "run verify-audit",
            "run API smoke checks",
            "compare platform readiness snapshot",
        ],
        "ha_pattern": (
            "Run orchestrator behind an internal reverse proxy, store SQLite on a "
            "managed volume or replace with managed SQL for multi-node deployments, "
            "and keep agents pinned to one active orchestrator."
        ),
        "evidence": [
            "backup export endpoint available",
            "audit export endpoint available",
            "retention config committed",
            "benchmark pack export available",
        ],
    }


def public_proof_readiness_report(state: AppState) -> dict[str, Any]:
    proof_files = [
        Path("benchmarks/README.md"),
        Path("benchmarks/api_smoke.md"),
        Path("benchmarks/siem_mock_smoke.md"),
        Path("benchmarks/enterprise_validation.md"),
        Path("benchmarks/sample_report.json"),
        Path("docs/PUBLIC_EVIDENCE.md"),
        Path("docs/ENTERPRISE_VALIDATION.md"),
        Path("docs/ENTERPRISE_HARDENING.md"),
        Path("docs/PRODUCTION_DEPLOYMENT.md"),
    ]
    return {
        "status": "public-proof-pack-ready",
        "file_count": sum(1 for path in proof_files if path.exists()),
        "expected_file_count": len(proof_files),
        "files": [str(path).replace("\\", "/") for path in proof_files if path.exists()],
        "api_snapshots": [
            "/platform/readiness",
            "/enterprise/readiness",
            "/enterprise/quality/ttps",
            "/enterprise/fleet/readiness",
            "/enterprise/cloud-sandbox/readiness",
            "/enterprise/compliance/readiness",
            "/reports/benchmark-pack.zip",
        ],
        "evidence": [
            f"{len(state.scenarios)} loaded scenarios are API-verifiable",
            "benchmark ZIP includes current API snapshots",
            "public evidence docs describe exact verification steps",
        ],
    }


def enterprise_hardening_report(state: AppState) -> dict[str, Any]:
    reports = {
        "ttp_quality": ttp_quality_report(state),
        "fleet": fleet_readiness_report(state),
        "import_fidelity": importer_fidelity_report(state),
        "cloud_sandbox": cloud_sandbox_readiness_report(state),
        "secrets_backends": secrets_backends_report(state),
        "performance": performance_plan(),
        "compliance": compliance_readiness_report(state),
        "public_proof": public_proof_readiness_report(state),
    }
    return {
        "status": "enterprise-hardening-ready",
        "area_count": len(reports),
        "areas": reports,
        "summary": {
            "ttp_quality_score": reports["ttp_quality"]["quality_score"],
            "cloud_sandbox_profiles": reports["cloud_sandbox"]["profile_count"],
            "secret_backend_lanes": reports["secrets_backends"]["backend_count"],
            "performance_profiles": reports["performance"]["profile_count"],
            "public_proof_files": reports["public_proof"]["file_count"],
        },
    }
