from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from itertools import count
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import ttps  # noqa: E402,F401
from orchestrator.dsl.loader import load_scenario_file  # noqa: E402
from orchestrator.dsl.schema import Scenario  # noqa: E402
from ttps.base import registry  # noqa: E402


VALIDATED_DIR = ROOT / "scenarios" / "validated"
EVIDENCE_PATH = ROOT / "evidence" / "scenario_evidence.yaml"
GOLDEN_EVENTS_PATH = ROOT / "evidence" / "soc_golden_events.jsonl"
MANAGED_FILE_RE = re.compile(r"^validated_.+_\d{4}\.yaml$")


@dataclass(frozen=True)
class ActorProfile:
    slug: str
    label: str


@dataclass(frozen=True)
class ScenarioTemplate:
    slug: str
    label: str
    platforms: tuple[str, ...]
    tags: tuple[str, ...]
    lab_profile: str
    telemetry_sources: tuple[str, ...]
    datasets: tuple[str, str]
    steps: tuple[tuple[str, str], ...]


ACTORS: tuple[ActorProfile, ...] = (
    ActorProfile("apt29", "APT29"),
    ActorProfile("fin7", "FIN7"),
    ActorProfile("lazarus", "Lazarus"),
    ActorProfile("apt41", "APT41"),
    ActorProfile("turla", "Turla"),
    ActorProfile("sandworm", "Sandworm"),
    ActorProfile("scattered-spider", "Scattered Spider"),
    ActorProfile("lockbit", "LockBit-style"),
    ActorProfile("clop", "Cl0p-style"),
    ActorProfile("insider", "Insider"),
    ActorProfile("cloud-intrusion", "Cloud Intrusion"),
    ActorProfile("enterprise-lab", "Enterprise Lab"),
    ActorProfile("saas-lab", "SaaS Lab"),
    ActorProfile("k8s-lab", "Kubernetes Lab"),
    ActorProfile("mustang-panda", "Mustang Panda"),
    ActorProfile("carbanak", "Carbanak"),
    ActorProfile("blind-eagle", "Blind Eagle"),
    ActorProfile("volt-typhoon", "Volt Typhoon-style"),
    ActorProfile("oilrig", "OilRig-style"),
    ActorProfile("kimsuky", "Kimsuky-style"),
    ActorProfile("gamaredon", "Gamaredon-style"),
    ActorProfile("blackcat", "BlackCat-style"),
    ActorProfile("play", "Play-style"),
    ActorProfile("akira", "Akira-style"),
    ActorProfile("qakbot", "QakBot-style"),
    ActorProfile("icedid", "IcedID-style"),
    ActorProfile("bumblebee", "Bumblebee-style"),
    ActorProfile("emotet", "Emotet-style"),
    ActorProfile("wizard-spider", "Wizard Spider-style"),
    ActorProfile("conti", "Conti-style"),
    ActorProfile("storm-0558", "Storm-0558-style"),
    ActorProfile("apt28", "APT28-style"),
    ActorProfile("apt34", "APT34-style"),
    ActorProfile("apt35", "APT35-style"),
    ActorProfile("apt36", "APT36-style"),
    ActorProfile("apt40", "APT40-style"),
    ActorProfile("apt33", "APT33-style"),
    ActorProfile("apt32", "APT32-style"),
    ActorProfile("ta505", "TA505-style"),
    ActorProfile("unc2452", "UNC2452-style"),
)


DIFFICULTIES = ("beginner", "realistic", "stealthy", "noisy")
SECTORS = (
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
)
REGIONS = ("amer", "emea", "apac", "latam", "global")


TEMPLATES: tuple[ScenarioTemplate, ...] = (
    ScenarioTemplate(
        slug="identity-saas",
        label="identity to SaaS collection",
        platforms=("any",),
        tags=("identity", "saas", "cloud", "m365", "okta"),
        lab_profile="saas-identity",
        telemetry_sources=("identity", "m365", "okta", "saas", "google_workspace"),
        datasets=("apt_sim.identity.signin", "apt_sim.saas.audit"),
        steps=(
            ("T1110.003:M365_PASSWORD_SPRAY", "password_spray"),
            ("T1556.009:OKTA_MFA_POLICY_WEAKEN", "mfa_policy_marker"),
            ("T1078.004:IDENTITY_RISKY_SIGNIN", "risky_signin"),
            ("T1098.003:ENTRA_APP_ROLE_GRANT", "app_role_grant"),
            ("T1098.005:SAAS_TOKEN_CREATED", "token_creation"),
            ("T1087.004:M365_GROUP_ENUMERATION", "group_enumeration"),
            ("T1530:GOOGLE_DRIVE_BULK_DOWNLOAD", "drive_collection"),
            ("T1567.002:SAAS_EXTERNAL_SHARE", "external_share"),
            ("T1070.004", "cleanup_marker"),
        ),
    ),
    ScenarioTemplate(
        slug="windows-ad",
        label="Windows AD lateral path",
        platforms=("windows",),
        tags=("windows", "ad", "identity", "lateral"),
        lab_profile="windows-ad",
        telemetry_sources=("windows_eventlog", "sysmon", "ldap", "kerberos", "edr"),
        datasets=("apt_sim.windows.security", "apt_sim.windows.sysmon"),
        steps=(
            ("T1078.002:AD_DOMAIN_ACCOUNT_LOGIN", "domain_logon"),
            ("T1033:AD_USER_DISCOVERY", "user_discovery"),
            ("T1087.002:AD_DOMAIN_ACCOUNT_ENUM", "account_enum"),
            ("T1069.002:AD_DOMAIN_GROUP_ENUM", "group_enum"),
            ("T1018:AD_REMOTE_SYSTEM_DISCOVERY", "remote_systems"),
            ("T1201:AD_PASSWORD_POLICY_DISCOVERY", "password_policy"),
            ("T1003.002:AD_SAM_ACCESS_MARKER", "credential_marker"),
            ("T1021.002:AD_SMB_ADMIN_SHARE_PATH", "smb_path"),
            ("T1021.006:AD_WINRM_LATERAL_PATH", "winrm_path"),
            ("T1112:AD_REGISTRY_POLICY_CHANGE", "registry_policy"),
            ("T1543.003:AD_WINDOWS_SERVICE_CREATE", "service_marker"),
        ),
    ),
    ScenarioTemplate(
        slug="cloud-k8s",
        label="cloud to Kubernetes control path",
        platforms=("linux",),
        tags=("cloud", "kubernetes", "container", "linux"),
        lab_profile="cloud-k8s",
        telemetry_sources=("cloud_api", "cloudtrail", "kubernetes_audit", "container_runtime"),
        datasets=("apt_sim.cloudtrail", "apt_sim.kubernetes.audit"),
        steps=(
            ("T1078.004:AWS_IAM_CONSOLE_RISK", "cloud_login"),
            ("T1526:AWS_SERVICE_DISCOVERY", "service_discovery"),
            ("T1580:CLOUD_INFRA_DISCOVERY", "infra_discovery"),
            ("T1552.005:INSTANCE_METADATA_TOKEN_READ", "metadata_token"),
            ("T1651:CLOUD_ADMIN_COMMAND", "admin_command"),
            ("T1613:K8S_RESOURCE_DISCOVERY_ADV", "k8s_discovery"),
            ("T1059.013:K8S_API_EXEC", "k8s_exec"),
            ("T1098.006:K8S_CLUSTER_ROLE_BINDING", "cluster_role_binding"),
            ("T1543.005:K8S_SERVICE_CREATED", "service_create"),
            ("T1611:K8S_HOST_ESCAPE_SIGNAL", "host_escape_signal"),
        ),
    ),
    ScenarioTemplate(
        slug="linux-stealth",
        label="Linux low-noise persistence and C2 path",
        platforms=("linux",),
        tags=("linux", "stealth", "persistence", "c2"),
        lab_profile="linux-fleet",
        telemetry_sources=("linux_process", "authlog", "auditd", "network", "file"),
        datasets=("apt_sim.linux.process", "apt_sim.linux.audit"),
        steps=(
            ("T1087.001:LINUX_LOCAL_ACCOUNT_DISCOVERY", "local_accounts"),
            ("T1082", "system_discovery"),
            ("T1057", "process_discovery"),
            ("T1059.004:LINUX_SHELL_HISTORY_DISABLE", "shell_history_marker"),
            ("T1053.003:LINUX_CRON_MARKER", "cron_marker"),
            ("T1105:LINUX_CURL_TOOL_TRANSFER", "tool_transfer"),
            ("T1027", "obfuscation_marker"),
            ("T1071.001", "web_c2_marker"),
            ("T1560", "archive_marker"),
            ("T1070.004:LINUX_LOG_CLEAR", "cleanup_marker"),
        ),
    ),
    ScenarioTemplate(
        slug="ransomware-preimpact",
        label="ransomware pre-impact chain",
        platforms=("windows",),
        tags=("windows", "ad", "ransomware", "impact"),
        lab_profile="windows-ad",
        telemetry_sources=("windows_eventlog", "sysmon", "edr", "backup", "identity"),
        datasets=("apt_sim.windows.security", "apt_sim.edr.alert"),
        steps=(
            ("T1078.002:AD_DOMAIN_ACCOUNT_LOGIN", "domain_logon"),
            ("T1087.002:AD_DOMAIN_ACCOUNT_ENUM", "account_enum"),
            ("T1069.002:AD_DOMAIN_GROUP_ENUM", "group_enum"),
            ("T1018:AD_REMOTE_SYSTEM_DISCOVERY", "remote_systems"),
            ("T1003.002:AD_SAM_ACCESS_MARKER", "sam_marker"),
            ("T1003.003:AD_NTDS_ACCESS_MARKER", "ntds_marker"),
            ("T1021.006:AD_WINRM_LATERAL_PATH", "winrm_lateral"),
            ("T1484.001:AD_GROUP_POLICY_MODIFICATION", "gpo_marker"),
            ("T1543.003:AD_WINDOWS_SERVICE_CREATE", "service_marker"),
            ("T1560", "archive_marker"),
            ("T1486", "impact_marker"),
            ("T1531:AD_ACCOUNT_ACCESS_REMOVAL", "account_removal_marker"),
        ),
    ),
    ScenarioTemplate(
        slug="hybrid-repo-cloud",
        label="hybrid endpoint to source repository and cloud path",
        platforms=("windows", "linux"),
        tags=("hybrid", "cloud", "saas", "kubernetes", "repository"),
        lab_profile="cloud-k8s",
        telemetry_sources=("endpoint", "cloud_api", "github", "kubernetes_audit", "saas"),
        datasets=("apt_sim.endpoint.process", "apt_sim.github.audit"),
        steps=(
            ("T1082", "system_discovery"),
            ("T1033", "user_discovery"),
            ("T1047:WINDOWS_WMI_PROCESS_CREATE", "wmi_marker"),
            ("T1078.004:GCP_CONSOLE_SESSION", "gcp_console"),
            ("T1580:GCP_PROJECT_ENUMERATION", "project_enum"),
            ("T1098.005:SAAS_TOKEN_CREATED", "token_creation"),
            ("T1213.003:GITHUB_PRIVATE_REPO_CLONE", "repo_clone"),
            ("T1613:K8S_RESOURCE_DISCOVERY_ADV", "k8s_discovery"),
            ("T1071.001", "web_c2_marker"),
            ("T1567.002:SAAS_EXTERNAL_SHARE", "external_share"),
            ("T1560", "archive_marker"),
            ("T1070.004", "cleanup_marker"),
        ),
    ),
    ScenarioTemplate(
        slug="fincrime-collection",
        label="financial intrusion collection path",
        platforms=("windows",),
        tags=("windows", "fincrime", "collection", "lateral"),
        lab_profile="windows-ad",
        telemetry_sources=("windows_eventlog", "sysmon", "edr", "file", "network"),
        datasets=("apt_sim.windows.powershell", "apt_sim.network.exfil"),
        steps=(
            ("T1059.001:WINDOWS_POWERSHELL_ENCODED", "powershell_marker"),
            ("T1047:WINDOWS_WMI_PROCESS_CREATE", "wmi_marker"),
            ("T1053.005", "scheduled_task"),
            ("T1543.003:WINDOWS_SERVICE_CREATE", "service_marker"),
            ("T1057", "process_discovery"),
            ("T1003", "credential_marker"),
            ("T1110", "bruteforce_marker"),
            ("T1021.002", "smb_lateral"),
            ("T1005", "local_collection"),
            ("T1560", "archive_marker"),
            ("T1105", "tool_transfer"),
            ("T1041", "exfil_marker"),
        ),
    ),
    ScenarioTemplate(
        slug="cloud-storage",
        label="cloud storage discovery and transfer path",
        platforms=("any",),
        tags=("cloud", "storage", "exfiltration"),
        lab_profile="cloud-k8s",
        telemetry_sources=("cloud_api", "cloudtrail", "storage", "identity"),
        datasets=("apt_sim.cloudtrail", "apt_sim.cloud.storage"),
        steps=(
            ("T1078.004:AWS_CONSOLE_LOGIN_SUCCESS", "cloud_login"),
            ("T1526:AWS_SERVICE_DISCOVERY", "service_discovery"),
            ("T1619:CLOUD_STORAGE_DISCOVERY", "storage_discovery"),
            ("T1580:CLOUD_INFRA_DISCOVERY", "infra_discovery"),
            ("T1530:AWS_S3_OBJECT_BURST", "object_burst"),
            ("T1530:AWS_S3_OBJECT_COLLECTION_ADV", "object_collection"),
            ("T1537:CLOUD_ACCOUNT_DATA_TRANSFER", "account_transfer"),
            ("T1560", "archive_marker"),
            ("T1048", "exfil_marker"),
            ("T1070.004", "cleanup_marker"),
        ),
    ),
    ScenarioTemplate(
        slug="ad-disruption",
        label="AD disruption rehearsal path",
        platforms=("windows",),
        tags=("windows", "ad", "disruption", "impact"),
        lab_profile="windows-ad",
        telemetry_sources=("windows_eventlog", "sysmon", "ldap", "gpo", "edr"),
        datasets=("apt_sim.windows.security", "apt_sim.ad.gpo"),
        steps=(
            ("T1078.002:AD_DOMAIN_ACCOUNT_LOGIN", "domain_logon"),
            ("T1087.002:AD_DOMAIN_ACCOUNT_ENUM", "account_enum"),
            ("T1069.002:AD_DOMAIN_GROUP_ENUM", "group_enum"),
            ("T1018:AD_REMOTE_SYSTEM_DISCOVERY", "remote_systems"),
            ("T1201:AD_PASSWORD_POLICY_DISCOVERY", "password_policy"),
            ("T1003.003:AD_NTDS_ACCESS_MARKER", "ntds_marker"),
            ("T1484.001:AD_GROUP_POLICY_MODIFICATION", "gpo_marker"),
            ("T1543.003:AD_WINDOWS_SERVICE_CREATE", "service_marker"),
            ("T1531:AD_ACCOUNT_ACCESS_REMOVAL", "account_removal_marker"),
            ("T1070.004", "cleanup_marker"),
        ),
    ),
    ScenarioTemplate(
        slug="saas-token",
        label="SaaS token abuse and external sharing path",
        platforms=("any",),
        tags=("identity", "saas", "m365", "github", "collection"),
        lab_profile="saas-identity",
        telemetry_sources=("identity", "m365", "github", "saas", "google_workspace"),
        datasets=("apt_sim.identity.audit", "apt_sim.saas.audit"),
        steps=(
            ("T1110.003:M365_PASSWORD_SPRAY", "password_spray"),
            ("T1078.004:AZURE_PORTAL_RISKY_SIGNIN", "azure_signin"),
            ("T1098.003:ENTRA_APP_ROLE_GRANT", "app_role_grant"),
            ("T1098.005:SAAS_TOKEN_CREATED", "token_creation"),
            ("T1087.004:M365_GROUP_ENUMERATION", "group_enum"),
            ("T1213.003:GITHUB_PRIVATE_REPO_CLONE", "repo_clone"),
            ("T1530:GOOGLE_DRIVE_BULK_DOWNLOAD", "drive_download"),
            ("T1567.002:SAAS_EXTERNAL_SHARE", "external_share"),
            ("T1070.004", "cleanup_marker"),
        ),
    ),
    ScenarioTemplate(
        slug="k8s-deployment",
        label="Kubernetes deployment and workload control path",
        platforms=("linux",),
        tags=("kubernetes", "container", "cloud", "linux"),
        lab_profile="cloud-k8s",
        telemetry_sources=("kubernetes_audit", "container_runtime", "cloud_api", "linux_process"),
        datasets=("apt_sim.kubernetes.audit", "apt_sim.container.runtime"),
        steps=(
            ("T1613:K8S_RESOURCE_DISCOVERY_ADV", "resource_discovery"),
            ("T1059.013:K8S_API_EXEC", "api_exec"),
            ("T1098.006:K8S_CLUSTER_ROLE_BINDING", "role_binding"),
            ("T1610:K8S_DEPLOYMENT_CREATED", "deployment_create"),
            ("T1543.005:K8S_SERVICE_CREATED", "service_create"),
            ("T1105:LINUX_CURL_TOOL_TRANSFER", "tool_transfer"),
            ("T1071.001", "web_c2_marker"),
            ("T1560", "archive_marker"),
            ("T1611:K8S_HOST_ESCAPE_SIGNAL", "host_escape_signal"),
        ),
    ),
    ScenarioTemplate(
        slug="m365-data",
        label="M365 data discovery and exposure path",
        platforms=("any",),
        tags=("identity", "m365", "saas", "collection", "exfiltration"),
        lab_profile="saas-identity",
        telemetry_sources=("identity", "m365", "mail", "sharepoint", "saas"),
        datasets=("apt_sim.m365.audit", "apt_sim.sharepoint.audit"),
        steps=(
            ("T1110.003:M365_PASSWORD_SPRAY", "password_spray"),
            ("T1078.004:IDENTITY_RISKY_SIGNIN", "risky_signin"),
            ("T1087.004:M365_GROUP_ENUMERATION", "group_enum"),
            ("T1098.005:SAAS_TOKEN_CREATED", "token_creation"),
            ("T1530:GOOGLE_DRIVE_BULK_DOWNLOAD", "drive_download"),
            ("T1567.002:SAAS_EXTERNAL_SHARE", "external_share"),
            ("T1048", "exfil_marker"),
            ("T1070.004", "cleanup_marker"),
        ),
    ),
)


BASE_ECS_FIELDS = (
    "@timestamp",
    "ecs.version",
    "event.dataset",
    "event.action",
    "event.kind",
    "event.severity",
    "host.name",
    "user.name",
    "process.name",
    "source.ip",
    "destination.ip",
    "rule.name",
)
OCSF_CATEGORIES = ("activity", "identity", "network", "system", "findings")
SIEM_FIELDS = (
    "attack.technique.id",
    "rule.name",
    "event.dataset",
    "event.severity",
    "observer.vendor",
    "related.user",
)
LATENCY_TARGETS = {
    "beginner": 300,
    "realistic": 240,
    "stealthy": 600,
    "noisy": 180,
}


def slugify(value: str) -> str:
    value = value.lower().replace("&", "and")
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-")


def base_attack_id(value: str) -> str:
    return value.split(":", 1)[0].upper()


def registered_ttp(attack_id: str) -> Any | None:
    exact = registry.get(attack_id)
    if exact:
        return exact
    return registry.get(base_attack_id(attack_id))


def scenario_name(index: int, actor: ActorProfile, template: ScenarioTemplate, sector: str, difficulty: str) -> str:
    return f"validated_{actor.slug}_{template.slug}_{sector}_{difficulty}_{index:04d}".replace("-", "_")


def build_scenario(index: int) -> dict[str, Any]:
    actor = ACTORS[index % len(ACTORS)]
    template = TEMPLATES[(index * 7 + index // len(ACTORS)) % len(TEMPLATES)]
    sector = SECTORS[(index * 5 + index // len(ACTORS)) % len(SECTORS)]
    difficulty = DIFFICULTIES[(index * 3 + index // len(ACTORS)) % len(DIFFICULTIES)]
    region = REGIONS[(index * 2 + index // len(ACTORS)) % len(REGIONS)]
    name = scenario_name(index + 1, actor, template, sector, difficulty)

    steps: list[dict[str, Any]] = []
    for offset, (ttp_id, label) in enumerate(template.steps, start=1):
        step_id = f"s{offset:02d}_{slugify(label).replace('-', '_')}"
        step: dict[str, Any] = {
            "id": step_id,
            "ttp": ttp_id,
            "params": {
                "dry_run": True,
                "safety_mode": "marker_only",
                "lab_profile": template.lab_profile,
                "principal": f"lab.{actor.slug}",
                "sector": sector,
                "region": region,
                "difficulty": difficulty,
                "variant_index": index + 1,
            },
        }
        if steps:
            step["depends_on"] = [steps[-1]["id"]]
        steps.append(step)

    tags = ["validated", "actor_chain", difficulty, sector, region, template.lab_profile, *template.tags]
    return {
        "name": name,
        "description": (
            f"Fixture-backed {template.label} for {actor.label} style defensive validation "
            f"in the {sector} sector ({region}, {difficulty})."
        ),
        "target_platforms": list(template.platforms),
        "actor": actor.label,
        "tags": list(dict.fromkeys(tags)),
        "steps": steps,
    }


def validate_scenario(scenario: Scenario) -> None:
    scenario.validate_dag()
    missing = [step.ttp for step in scenario.steps if registered_ttp(step.ttp) is None]
    if missing:
        raise ValueError(f"{scenario.name} references unregistered TTPs: {', '.join(missing)}")


def scenario_profile(scenario: Scenario) -> tuple[str, tuple[str, ...], tuple[str, str], str, str, str]:
    tags = set(scenario.tags)
    difficulty = next((tag for tag in scenario.tags if tag in DIFFICULTIES), "realistic")
    sector = next((tag for tag in scenario.tags if tag in SECTORS), "enterprise")
    region = next((tag for tag in scenario.tags if tag in REGIONS), "global")

    for template in TEMPLATES:
        if template.slug.replace("-", "_") in scenario.name or template.slug in tags:
            return template.lab_profile, template.telemetry_sources, template.datasets, difficulty, sector, region

    if "kubernetes" in tags or "container" in tags:
        template = next(t for t in TEMPLATES if t.slug == "cloud-k8s")
    elif "windows" in tags or "ad" in tags or "ransomware" in tags:
        template = next(t for t in TEMPLATES if t.slug == "windows-ad")
    elif "linux" in tags:
        template = next(t for t in TEMPLATES if t.slug == "linux-stealth")
    elif "saas" in tags or "identity" in tags or "m365" in tags:
        template = next(t for t in TEMPLATES if t.slug == "identity-saas")
    elif "cloud" in tags or "storage" in tags:
        template = next(t for t in TEMPLATES if t.slug == "cloud-storage")
    else:
        template = next(t for t in TEMPLATES if t.slug == "hybrid-repo-cloud")
    return template.lab_profile, template.telemetry_sources, template.datasets, difficulty, sector, region


def detection_ids(scenario: Scenario) -> list[str]:
    ids: list[str] = []
    for step in scenario.steps:
        attack_id = base_attack_id(step.ttp)
        if attack_id not in ids:
            ids.append(attack_id)
    return ids


def evidence_for_scenario(scenario: Scenario) -> dict[str, Any]:
    lab_profile, telemetry_sources, _datasets, difficulty, sector, region = scenario_profile(scenario)
    target = LATENCY_TARGETS.get(difficulty, 300)
    ids = detection_ids(scenario)
    return {
        "scenario": scenario.name,
        "validation_status": "fixture-backed",
        "confidence": "high",
        "lab_profile": lab_profile,
        "sector": sector,
        "region": region,
        "difficulty": difficulty,
        "telemetry_sources": list(telemetry_sources),
        "expected_detection_count": len(scenario.steps),
        "fixture": "evidence/soc_golden_events.jsonl",
        "sigma_matches": ids,
        "ecs_fields": list(BASE_ECS_FIELDS),
        "ocsf_categories": list(OCSF_CATEGORIES),
        "siem_fields": list(SIEM_FIELDS),
        "detection_latency_seconds": {
            "target": target,
            "warning": target * 3,
            "critical": target * 6,
        },
        "report_expectations": [
            "scenario summary",
            "ordered step timeline",
            "detection coverage",
            "SOC evidence fixtures",
            "cleanup status",
            "coverage gaps",
            "latency target",
        ],
        "runbook": [
            "Start scenario in dry-run mode against an authorized lab profile.",
            "Confirm that every step appears in dependency order.",
            "Verify Sigma matches, ECS fields, OCSF categories, and SIEM fields.",
            "Review the two golden SOC events tied to the scenario.",
            "Export JSON, HTML, and ZIP artifacts for SOC review.",
        ],
        "success_criteria": [
            "All steps validate as an acyclic DAG.",
            "Every step resolves to a registered TTP.",
            "Every registered TTP has detection metadata available to the workbench.",
            "Golden events include ECS, OCSF, SIEM, latency, and cleanup fields.",
            "No non-lab network, cloud, identity, or SaaS provider call is required.",
        ],
    }


def event_techniques(scenario: Scenario) -> tuple[str, str]:
    if scenario.name == "validated_cloud_k8s_takeover_path":
        return "T1651", "T1611"
    ids = detection_ids(scenario)
    return ids[0], ids[-1]


def golden_events_for_scenario(scenario: Scenario) -> list[dict[str, Any]]:
    lab_profile, _telemetry_sources, datasets, difficulty, sector, region = scenario_profile(scenario)
    first_technique, last_technique = event_techniques(scenario)
    actor = scenario.actor or "Unknown"
    common = {
        "ecs.version": "8.11.0",
        "event.kind": "alert",
        "ocsf.version": "1.2.0",
        "scenario": scenario.name,
        "scenario.actor": actor,
        "scenario.difficulty": difficulty,
        "scenario.sector": sector,
        "scenario.region": region,
        "lab.profile": lab_profile,
        "siem.fields": ["attack.technique.id", "event.dataset", "rule.name", "event.severity"],
    }
    return [
        {
            **common,
            "@timestamp": "2026-06-19T00:01:00Z",
            "attack.technique.id": first_technique,
            "cleanup.status": "not_required",
            "detection.intent": "initial chain marker",
            "detection.latency.seconds": 120,
            "event.action": "initial_chain_marker",
            "event.dataset": datasets[0],
            "event.severity": 60,
            "ocsf.class_uid": 1002,
            "rule.name": f"{scenario.name} initial chain marker",
        },
        {
            **common,
            "@timestamp": "2026-06-19T00:02:00Z",
            "attack.technique.id": last_technique,
            "cleanup.status": "marker_only",
            "detection.intent": "terminal evidence marker",
            "detection.latency.seconds": 240,
            "event.action": "terminal_evidence_marker",
            "event.dataset": datasets[1],
            "event.severity": 70,
            "ocsf.class_uid": 1003,
            "rule.name": f"{scenario.name} terminal evidence marker",
        },
    ]


def load_validated_scenarios() -> dict[str, Scenario]:
    scenarios: dict[str, Scenario] = {}
    for path in sorted(VALIDATED_DIR.glob("*.yaml")):
        loaded = load_scenario_file(path)
        if len(loaded) != 1:
            raise ValueError(f"{path} must contain exactly one scenario")
        scenario = loaded[0]
        validate_scenario(scenario)
        scenarios[scenario.name] = scenario
    return scenarios


def reset_managed_files() -> None:
    resolved_dir = VALIDATED_DIR.resolve()
    for path in sorted(VALIDATED_DIR.glob("*.yaml")):
        if not MANAGED_FILE_RE.match(path.name):
            continue
        resolved_path = path.resolve()
        if resolved_dir not in resolved_path.parents:
            raise ValueError(f"refusing to delete path outside validated directory: {resolved_path}")
        path.unlink()


def materialize_scenarios(target: int, *, refresh_generated: bool = False) -> None:
    VALIDATED_DIR.mkdir(parents=True, exist_ok=True)
    if refresh_generated:
        reset_managed_files()
    existing = {path.stem for path in VALIDATED_DIR.glob("*.yaml")}
    if len(existing) > target:
        raise ValueError(f"{VALIDATED_DIR} already contains {len(existing)} files, target is {target}")

    for index in count():
        if len(existing) >= target:
            break
        raw = build_scenario(index)
        name = raw["name"]
        if name in existing:
            continue
        scenario = Scenario(**raw)
        validate_scenario(scenario)
        path = VALIDATED_DIR / f"{name}.yaml"
        path.write_text(yaml.safe_dump(raw, sort_keys=False, allow_unicode=False), encoding="utf-8")
        existing.add(name)


def write_evidence(scenarios: dict[str, Scenario]) -> None:
    entries = [evidence_for_scenario(scenario) for scenario in sorted(scenarios.values(), key=lambda item: item.name)]
    payload = {
        "version": 2,
        "description": "Fixture-backed evidence contracts for validated actor-chain scenarios.",
        "scenarios": entries,
    }
    EVIDENCE_PATH.write_text(yaml.safe_dump(payload, sort_keys=False, allow_unicode=False), encoding="utf-8")

    events: list[dict[str, Any]] = []
    for scenario in sorted(scenarios.values(), key=lambda item: item.name):
        events.extend(golden_events_for_scenario(scenario))
    GOLDEN_EVENTS_PATH.write_text(
        "\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n",
        encoding="utf-8",
    )


def run(target: int, *, refresh_generated: bool = False) -> dict[str, int]:
    materialize_scenarios(target, refresh_generated=refresh_generated)
    scenarios = load_validated_scenarios()
    if len(scenarios) != target:
        raise ValueError(f"expected {target} validated scenarios, loaded {len(scenarios)}")
    write_evidence(scenarios)
    events = GOLDEN_EVENTS_PATH.read_text(encoding="utf-8").splitlines()
    if len(events) != target * 2:
        raise ValueError(f"expected {target * 2} golden event rows, found {len(events)}")
    return {"validated_scenarios": len(scenarios), "golden_events": len(events)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Materialize the validated actor-chain scenario pack.")
    parser.add_argument("--target", type=int, default=1000)
    parser.add_argument("--refresh-generated", action="store_true")
    args = parser.parse_args()
    counts = run(args.target, refresh_generated=args.refresh_generated)
    print(json.dumps(counts, sort_keys=True))


if __name__ == "__main__":
    main()
