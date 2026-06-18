"""Lab profile catalog for scenario selection and SOC validation."""
from __future__ import annotations

from typing import Any


LAB_PROFILES: dict[str, dict[str, Any]] = {
    "windows-ad": {
        "id": "windows-ad",
        "name": "Windows AD Lab",
        "platforms": ["windows"],
        "domains": ["identity", "endpoint", "directory_service"],
        "telemetry_sources": ["windows_security", "directory_service", "windows_process", "windows_registry"],
        "recommended_scenarios": [
            "validated_windows_ad_kerberos_lateral",
            "validated_enterprise_lab_kerberos_chain",
            "validated_ransomware_ad_preimpact",
            "validated_lockbit_ad_preimpact_chain",
            "validated_fin7_ad_lateral_fraud_path",
        ],
        "success_checks": [
            "Domain login, discovery, credential marker, and lateral movement stages appear in order.",
            "Registry, service, and policy changes remain marker-only.",
            "Run report exports JSON, HTML, and ZIP artifacts.",
        ],
    },
    "linux-fleet": {
        "id": "linux-fleet",
        "name": "Linux Fleet Lab",
        "platforms": ["linux"],
        "domains": ["endpoint", "c2", "file_event"],
        "telemetry_sources": ["linux_process", "file_event", "http", "dns"],
        "recommended_scenarios": [
            "validated_apt41_linux_k8s_pivot",
            "validated_enterprise_lab_linux_fleet_chain",
            "validated_turla_linux_low_noise_chain",
            "validated_lazarus_linux_build_agent",
            "validated_sandworm_linux_cleanup_path",
        ],
        "success_checks": [
            "Shell, cron, transfer, archive, C2, and cleanup markers are visible.",
            "No host persistence change is made outside marker artifacts.",
            "Detection latency fields are present in SOC evidence.",
        ],
    },
    "cloud-k8s": {
        "id": "cloud-k8s",
        "name": "Cloud/Kubernetes Lab",
        "platforms": ["linux"],
        "domains": ["cloud", "container", "identity"],
        "telemetry_sources": ["cloud_api", "cloudtrail", "metadata", "kubernetes_audit", "container_runtime"],
        "recommended_scenarios": [
            "validated_cloud_k8s_takeover_path",
            "validated_cloud_intrusion_aws_to_k8s",
            "validated_k8s_lab_cluster_takeover",
            "validated_apt41_k8s_secret_pivot",
            "validated_sandworm_k8s_disruption_path",
        ],
        "success_checks": [
            "Cloud access precedes Kubernetes discovery and role binding.",
            "Container execution and escape signals remain synthetic.",
            "Cloud and Kubernetes datasets appear together in evidence fixtures.",
        ],
    },
    "saas-identity": {
        "id": "saas-identity",
        "name": "SaaS/Identity Lab",
        "platforms": ["windows", "linux", "darwin"],
        "domains": ["identity", "saas", "cloud"],
        "telemetry_sources": ["identity", "m365", "okta", "google_workspace", "saas"],
        "recommended_scenarios": [
            "validated_scattered_spider_identity_cloud",
            "validated_saas_lab_token_abuse_chain",
            "validated_insider_m365_drive_share",
            "validated_clop_saas_extortion_chain",
            "validated_lazarus_dev_saas_exfil",
        ],
        "success_checks": [
            "Identity pressure, token creation, collection, and external share are correlated.",
            "SaaS and identity events carry SIEM fields and latency targets.",
            "No provider API is contacted by marker-only simulations.",
        ],
    },
}


def list_lab_profiles() -> list[dict[str, Any]]:
    return [LAB_PROFILES[key] for key in sorted(LAB_PROFILES)]


def get_lab_profile(profile_id: str) -> dict[str, Any] | None:
    return LAB_PROFILES.get(profile_id)
