# Public Benchmark Pack

This folder contains reproducible local checks for the public project claims.

## Verified Targets

| Target | Expected value |
| --- | ---: |
| TTP catalog | 5,064 |
| Loaded YAML scenarios | 3,522 |
| Validated actor-chain scenarios | 1,000 |
| SOC golden event rows | 2,000 |
| ATT&CK Enterprise tactics | 15/15 |
| Enterprise validation tracks | 11 |
| Agent package targets | 3 |
| Load-test profiles | 5 |
| SIEM validation targets | 4 |

## API Evidence

Start the orchestrator:

```bash
python -m orchestrator.main serve --host 127.0.0.1 --port 8000
```

Then run the checks in `api_smoke.md`.

The dynamic benchmark bundle is available at:

```text
http://127.0.0.1:8000/reports/benchmark-pack.zip
```

It contains current API snapshots for platform readiness, Execution Engine v3, import center, evidence summary, enterprise readiness, access, lab validation, agent packaging, load-test plan, and SIEM validation.

Extra validation surfaces:

- `POST /labs/multi-agent/smoke` proves three local lab agents can receive independent DAG steps through the planner.
- `/siem/connectors/status` and `/siem/connectors/sample` expose Splunk HEC and Elastic bulk payload contracts.
- `siem_mock_smoke.md` documents local mock ingestion checks.
- `/enterprise/readiness` exposes enterprise validation, access, secrets, audit, packaging, SIEM, and load readiness.
- `enterprise_validation.md` documents the 11 enterprise validation tracks.
- `load_campaign_plan.json` defines 10, 50, 100, 500, and 1,000 scenario load profiles.
