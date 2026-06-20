# Enterprise Validation

This guide describes how to validate APT Simulator in a user-owned enterprise lab. The project remains lab-safe by default: generated scale coverage is marker-only and dry-run oriented, cloud simulations do not contact cloud providers, and public SIEM URLs require explicit operator opt-in.

## Validation Tracks

APT Simulator exposes 11 enterprise validation tracks through `/enterprise/lab-validation`:

| Track | Purpose |
| --- | --- |
| Windows AD Lab | Domain login, discovery, credential markers, lateral movement markers, policy, and service telemetry. |
| Linux Fleet Lab | Shell, cron, SSH, transfer, archive, C2, cleanup, and log marker telemetry. |
| AWS Lab | Cloud account, IAM, storage, metadata, and control-plane marker telemetry. |
| Azure Lab | Cloud identity, role, storage, and SaaS-style marker telemetry. |
| GCP Lab | Project, storage, service-account, and cloud audit marker telemetry. |
| Kubernetes Lab | Resource discovery, role binding, deployment, pod, and host-escape signal markers. |
| SaaS And Identity Lab | MFA policy, risky sign-in, token, sharing, and SaaS collection marker telemetry. |
| Splunk Validation | HEC ingestion using committed SOC golden events and Sigma/SPL validation. |
| Elastic Validation | Bulk API ingestion using committed SOC golden events and Sigma/Elastic validation. |
| Microsoft Sentinel Validation | Data Collector ingestion, KQL rule review, and golden-event comparison workflow. |
| Google Chronicle Validation | UDM ingestion, YARA-L style rule review, and golden-event comparison workflow. |

## Windows AD Lab

Use a disposable domain lab with at least one domain controller, one member server, and one workstation. Register agents only on approved lab hosts. Start with validated Windows AD scenarios and then compare generated telemetry with the expected SOC evidence contracts.

Recommended checks:

```bash
curl http://127.0.0.1:8000/lab-profiles
curl http://127.0.0.1:8000/scenario-library?source=validated%20actor-chain
curl -X POST http://127.0.0.1:8000/labs/multi-agent/smoke
```

## Linux Fleet Lab

Use disposable Linux hosts or VMs with audit/log forwarding enabled. Run Linux fleet scenarios first in dry-run mode, then verify cleanup metadata and expected ECS/OCSF fields.

Recommended checks:

```bash
python -m agent.main run-local scenarios/linux_recon_to_c2.yaml --dry-run
curl http://127.0.0.1:8000/scenario-maturity
curl http://127.0.0.1:8000/evidence/summary
```

## Cloud And Kubernetes Labs

Use sandbox accounts and clusters with explicit boundaries. The committed cloud/Kubernetes pack is marker-only; it is intended to validate telemetry, detection mappings, and runbooks without changing real cloud resources.

Recommended checks:

```bash
curl http://127.0.0.1:8000/exposure/graph
curl http://127.0.0.1:8000/coverage/matrix
curl http://127.0.0.1:8000/enterprise/lab-validation
curl http://127.0.0.1:8000/enterprise/cloud-sandbox/readiness
```

## SaaS And Identity Lab

Use test tenants and dedicated lab identities. Validate sign-in, token, policy, and sharing telemetry against the expected event contracts and SIEM field mappings.

Recommended checks:

```bash
curl http://127.0.0.1:8000/scenario-library?source=validated%20actor-chain
curl http://127.0.0.1:8000/scenario-evidence/validated_apt29_identity_cloud_chain
```

## SIEM Validation

Splunk, Elastic, Microsoft Sentinel, and Google Chronicle have guarded send endpoints. All four endpoints use committed SOC golden events, allow localhost/private-network lab targets by default, and require explicit `allow_external=true` for public URLs.

```bash
curl http://127.0.0.1:8000/siem/connectors/status
curl http://127.0.0.1:8000/siem/connectors/sample?limit=2
curl http://127.0.0.1:8000/enterprise/siem-validation
```

Use localhost or private-network mock endpoints for repeatable CI smoke tests. For public endpoints, set `allow_external=true` only after confirming the lab scope and credentials.

## Real-Lab Evidence Import

Use the lab evidence registry to attach externally captured proof from user-owned labs. Evidence records are stored as append-only JSONL and reference external artifacts by URI/path plus SHA-256.

```bash
curl http://127.0.0.1:8000/lab-evidence/template
curl http://127.0.0.1:8000/lab-evidence/summary
curl -X POST http://127.0.0.1:8000/lab-evidence/import \
  -H "Content-Type: application/json" \
  -d "{\"source\":\"splunk\",\"evidence_type\":\"siem_export\",\"scenario\":\"validated_apt29_identity_cloud_chain\",\"attack_ids\":[\"T1078\"],\"artifact_ref\":\"file:///lab/splunk-export.json\"}"
```

## Evidence To Capture

- `/enterprise/readiness`
- `/platform/readiness`
- `/reports/benchmark-pack.zip`
- `/reports/evidence-pack.zip`
- `/reports/audit-export.zip`
- `/lab-evidence/summary`
- SIEM screenshots or query exports from the user-owned lab
- Campaign report JSON/HTML artifacts
