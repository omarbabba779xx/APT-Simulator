# API Smoke Checks

Run these commands against a local orchestrator.

```bash
curl http://127.0.0.1:8000/healthz
curl http://127.0.0.1:8000/platform/readiness
curl http://127.0.0.1:8000/execution/v3/status
curl http://127.0.0.1:8000/imports/center
curl http://127.0.0.1:8000/siem/connectors/status
curl http://127.0.0.1:8000/siem/connectors/sample?limit=2
curl -X POST http://127.0.0.1:8000/labs/multi-agent/smoke
curl http://127.0.0.1:8000/enterprise/readiness
curl http://127.0.0.1:8000/enterprise/access
curl http://127.0.0.1:8000/enterprise/lab-validation
curl http://127.0.0.1:8000/enterprise/agent-packaging
curl http://127.0.0.1:8000/enterprise/load-test/plan
curl http://127.0.0.1:8000/enterprise/siem-validation
curl http://127.0.0.1:8000/lab-evidence/summary
curl http://127.0.0.1:8000/lab-evidence/template
curl http://127.0.0.1:8000/enterprise/hardening
curl http://127.0.0.1:8000/enterprise/quality/ttps
curl http://127.0.0.1:8000/enterprise/fleet/readiness
curl http://127.0.0.1:8000/enterprise/import-fidelity
curl http://127.0.0.1:8000/enterprise/cloud-sandbox/readiness
curl http://127.0.0.1:8000/enterprise/performance/plan
curl http://127.0.0.1:8000/enterprise/compliance/readiness
curl http://127.0.0.1:8000/evidence/summary
curl http://127.0.0.1:8000/attack/sync/status
curl http://127.0.0.1:8000/detections/workbench
curl http://127.0.0.1:8000/exposure/graph
curl -o evidence-pack.zip http://127.0.0.1:8000/reports/evidence-pack.zip
curl -o audit-export.zip http://127.0.0.1:8000/reports/audit-export.zip
curl -o benchmark-pack.zip http://127.0.0.1:8000/reports/benchmark-pack.zip
```

Minimum expected API values:

```text
/healthz.scenarios_loaded = 3522
/platform/readiness.counts.ttps = 5064
/platform/readiness.counts.validated_scenarios = 1000
/platform/readiness.counts.siem_targets = 4
/platform/readiness.counts.enterprise_validation_tracks = 11
/platform/readiness.counts.agent_package_targets = 3
/platform/readiness.counts.load_test_profiles = 5
/platform/readiness.counts.siem_validation_targets = 4
/platform/readiness.capability_count = 25
/platform/readiness.counts.enterprise_hardening_areas = 8
/platform/readiness.counts.cloud_sandbox_profiles = 4
/platform/readiness.counts.secret_backend_lanes = 6
/evidence/summary.counts.golden_event_rows = 2000
/attack/sync/status.coverage_label = 15/15
/labs/multi-agent/smoke.ok = true
/siem/connectors/status.targets = ["splunk_hec", "elastic_bulk", "sentinel_data_collector", "chronicle_udm"]
/enterprise/readiness.status = enterprise-lab-ready
```
