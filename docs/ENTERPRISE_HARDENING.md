# Enterprise Hardening

This document maps the remaining enterprise-grade gaps to concrete local surfaces. These checks do not claim that a customer SIEM, cloud tenant, or identity provider has been validated until a user imports real lab evidence.

## API Surfaces

```bash
curl http://127.0.0.1:8000/enterprise/hardening
curl http://127.0.0.1:8000/enterprise/quality/ttps
curl http://127.0.0.1:8000/enterprise/fleet/readiness
curl http://127.0.0.1:8000/enterprise/import-fidelity
curl http://127.0.0.1:8000/enterprise/cloud-sandbox/readiness
curl http://127.0.0.1:8000/enterprise/secrets/backends
curl http://127.0.0.1:8000/enterprise/performance/plan
curl -X POST "http://127.0.0.1:8000/enterprise/performance/smoke?scenario_count=25"
curl http://127.0.0.1:8000/enterprise/compliance/readiness
curl http://127.0.0.1:8000/enterprise/public-proof/readiness
curl -o backup-export.zip http://127.0.0.1:8000/reports/backup-export.zip
```

## Hardening Areas

| Area | Purpose |
| --- | --- |
| TTP Quality Governance | Separates external-lab-proven, fixture-backed, loaded-scenario-backed, and catalog-scale TTPs. |
| Agent Fleet Operations | Tracks heartbeat SLA, platform coverage, service wrappers, and mTLS deployment contract. |
| Official Import Fidelity | Tracks ATT&CK STIX drift, AEL, Atomic Red Team, cloud reference, and detection corpus lanes. |
| Cloud Sandbox Guardrails | Defines AWS, Azure, GCP, and Kubernetes guardrails before any user-owned live-lab extension. |
| Enterprise Secret Backends | Exposes redacted readiness for environment, local file, Vault, AWS, Azure, and GCP secret lanes. |
| Performance Benchmark Plan | Defines 10, 50, 100, 500, and 1,000 scenario performance profiles plus metadata smoke. |
| Compliance Operations | Covers backup export, retention, audit verification, restore rehearsal, HA pattern, and migrations contract. |
| Public Proof Pack | Lists the files and API snapshots needed to prove public project claims. |

## Evidence Rules

- Imported SIEM screenshots, logs, host traces, and cloud audit exports must use `/lab-evidence/import`.
- Backup exports intentionally exclude `keys/`, raw secret material, and external customer evidence.
- Cloud/Kubernetes simulations stay marker-only until a user-owned sandbox profile and written authorization are supplied.
- TTPs without external lab evidence remain useful for detection engineering, but they are not procedure-grade.
