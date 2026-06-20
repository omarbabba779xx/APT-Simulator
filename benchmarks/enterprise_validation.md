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
curl -o audit-export.zip http://127.0.0.1:8000/reports/audit-export.zip
```

## Expected Values

- `/enterprise/readiness.status = enterprise-lab-ready`
- `/enterprise/readiness.counts.validation_tracks = 11`
- `/enterprise/readiness.counts.agent_package_targets = 3`
- `/enterprise/readiness.counts.load_test_profiles = 5`
- `/enterprise/readiness.counts.siem_validation_targets = 4`
- `/platform/readiness.capability_count = 16`

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
