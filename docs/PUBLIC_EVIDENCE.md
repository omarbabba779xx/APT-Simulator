# Public Evidence And Verification

This document gives reviewers a fast way to verify the project without trusting README claims.

## Verification Commands

```bash
python -m pytest tests/test_conformance.py tests/test_scenario_maturity.py -q
python -m orchestrator.scenario_maturity summary --limit-items 5
python -m orchestrator.attack_sync status --path config/attack_enterprise_snapshot.json
curl http://127.0.0.1:8000/platform/readiness
curl http://127.0.0.1:8000/imports/center
curl http://127.0.0.1:8000/execution/v3/status
curl http://127.0.0.1:8000/siem/connectors/status
curl http://127.0.0.1:8000/siem/connectors/sample?limit=2
curl -X POST http://127.0.0.1:8000/labs/multi-agent/smoke
curl http://127.0.0.1:8000/enterprise/readiness
curl http://127.0.0.1:8000/enterprise/load-test/plan
curl -o audit-export.zip http://127.0.0.1:8000/reports/audit-export.zip
```

Expected core results:

- 5,064 registered TTPs.
- 3,522 loaded YAML scenarios.
- 1,000 validated actor-chain YAML scenarios.
- 2,000 SOC golden event rows.
- 5,064 Sigma rules.
- 4 SIEM connector targets.
- 11 enterprise validation tracks.
- 3 agent package targets.
- 5 load-test profiles.
- 4 SIEM validation targets.
- 15/15 current ATT&CK Enterprise tactics covered.

## Reviewer Walkthrough

1. Start dashboard:

   ```bash
   python -m orchestrator.main serve
   ```

2. Open `http://127.0.0.1:8000/dashboard/`.
3. Check Scenario Library source filter `validated actor-chain`.
4. Open Scenario Maturity and confirm 1,000 fixture-backed scenarios.
5. Start one validated scenario.
6. Open History and download JSON, HTML, and ZIP artifacts.
7. Open Labs and choose one of Windows AD, Linux Fleet, Cloud/Kubernetes, or SaaS/Identity.
8. Open Evidence Center and download the global evidence ZIP or one scenario ZIP.
9. Open Platform Readiness and confirm the 17-area scorecard.
10. Open Import Center and review source lanes, local counts, and safety boundaries.
11. Download `/reports/benchmark-pack.zip` and inspect `manifest.json`.
12. Run `POST /labs/multi-agent/smoke` and confirm three distinct lab agents receive steps.
13. Review `/siem/connectors/status` and `/siem/connectors/sample?limit=2`.
14. Review `/enterprise/readiness` and confirm enterprise validation counts.
15. Download `/reports/audit-export.zip` and inspect `audit_manifest.json`.

## Capability Matrix

| Capability | Project evidence |
| --- | --- |
| ATT&CK coverage | Bundled Enterprise snapshot, drift status, 15/15 tactics, 696 local base IDs |
| Scenario depth | 1,000 fixture-backed actor-chain DAGs with runbooks and success criteria |
| SOC evidence | ECS fields, OCSF categories, SIEM fields, latency targets, 2,000 golden events |
| Evidence exports | `/evidence/summary`, `/reports/evidence-pack.zip`, and per-scenario ZIP bundles |
| Platform readiness | `/platform/readiness` 17-area scorecard and `/reports/benchmark-pack.zip` |
| Import center | `/imports/center` for ATT&CK STIX, AEL, Atomic Red Team, cloud reference, and rule-corpus lanes |
| Multi-agent lab | `/labs/multi-agent/smoke` registers three lab agents and records planner dispatch proof |
| SIEM ingestion | `/siem/connectors/status`, `/siem/connectors/sample`, Splunk HEC, Elastic bulk, Sentinel Data Collector, Chronicle UDM, mock-smoke tests |
| Real-lab evidence import | `/lab-evidence/summary`, `/lab-evidence/template`, append-only JSONL registry |
| Enterprise readiness | `/enterprise/readiness`, `/enterprise/lab-validation`, `/enterprise/agent-packaging`, `/enterprise/load-test/plan` |
| Audit export | `/reports/audit-export.zip` with raw JSONL and chain-verification manifest |
| Campaigns | 10/50/100 launch controls, scheduling, repeat, pause, resume, retry failed |
| Execution state | `/execution/v3/status`, persistent run history, queue entries, step logs, cleanup status |
| Reports | JSON, HTML, and ZIP artifact bundles |
| Lab tracks | Windows AD, Linux Fleet, Cloud/Kubernetes, SaaS/Identity |
| Safety | Dry-run and marker-only default for scale coverage |

## Honest Boundaries

- The 15,680,015,680 value is deterministic variant space, not committed files.
- The 5,064 TTPs are registered catalog/code entries with Sigma rules, not 5,064 manually validated live procedures.
- The strongest evidence tier is the 1,000 validated actor-chain scenario pack.
- Cloud, SaaS, Kubernetes, identity, and impact steps are marker-only unless an authorized lab explicitly enables otherwise.
