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
curl http://127.0.0.1:8000/evidence/summary
curl http://127.0.0.1:8000/attack/sync/status
curl http://127.0.0.1:8000/detections/workbench
curl http://127.0.0.1:8000/exposure/graph
curl -o evidence-pack.zip http://127.0.0.1:8000/reports/evidence-pack.zip
curl -o benchmark-pack.zip http://127.0.0.1:8000/reports/benchmark-pack.zip
```

Minimum expected API values:

```text
/healthz.scenarios_loaded = 3522
/platform/readiness.counts.ttps = 5064
/platform/readiness.counts.validated_scenarios = 1000
/platform/readiness.counts.siem_targets = 2
/evidence/summary.counts.golden_event_rows = 2000
/attack/sync/status.coverage_label = 15/15
/labs/multi-agent/smoke.ok = true
/siem/connectors/status.targets = ["splunk_hec", "elastic_bulk"]
```
