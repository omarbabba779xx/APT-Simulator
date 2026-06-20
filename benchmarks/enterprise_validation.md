# Enterprise Validation Smoke

This file lists the enterprise validation surfaces that can be checked from a local or user-owned lab deployment.

## API Checks

```bash
curl http://127.0.0.1:8000/enterprise/readiness
curl http://127.0.0.1:8000/enterprise/lab-validation
curl http://127.0.0.1:8000/enterprise/access
curl http://127.0.0.1:8000/enterprise/agent-packaging
curl http://127.0.0.1:8000/enterprise/load-test/plan
curl http://127.0.0.1:8000/enterprise/siem-validation
curl http://127.0.0.1:8000/lab-evidence/summary
curl http://127.0.0.1:8000/enterprise/hardening
curl http://127.0.0.1:8000/enterprise/quality/ttps
curl http://127.0.0.1:8000/enterprise/fleet/readiness
curl http://127.0.0.1:8000/enterprise/cloud-sandbox/readiness
curl http://127.0.0.1:8000/enterprise/compliance/readiness
curl -o audit-export.zip http://127.0.0.1:8000/reports/audit-export.zip
curl -o backup-export.zip http://127.0.0.1:8000/reports/backup-export.zip
```

## Expected Values

- `/enterprise/readiness.status = enterprise-lab-ready`
- `/enterprise/readiness.counts.validation_tracks = 11`
- `/enterprise/readiness.counts.agent_package_targets = 3`
- `/enterprise/readiness.counts.load_test_profiles = 5`
- `/enterprise/readiness.counts.siem_validation_targets = 4`
- `/enterprise/readiness.counts.enterprise_hardening_areas = 8`
- `/platform/readiness.capability_count = 25`
- `/platform/readiness.counts.siem_targets = 4`
- `/platform/readiness.counts.cloud_sandbox_profiles = 4`
- `/platform/readiness.counts.secret_backend_lanes = 6`

## Enterprise Lab Tracks

- Windows AD
- Linux fleet
- AWS
- Azure
- GCP
- Kubernetes
- SaaS and identity
- Splunk
- Elastic
- Microsoft Sentinel
- Google Chronicle
