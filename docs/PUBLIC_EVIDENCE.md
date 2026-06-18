# Public Evidence And Verification

This document gives reviewers a fast way to verify the project without trusting README claims.

## Verification Commands

```bash
python -m pytest tests/test_conformance.py tests/test_scenario_maturity.py -q
python -m orchestrator.scenario_maturity summary --limit-items 5
python -m orchestrator.attack_sync status --path config/attack_enterprise_snapshot.json
```

Expected core results:

- 5,064 registered TTPs.
- 2,572 loaded YAML scenarios.
- 50 validated actor-chain YAML scenarios.
- 100 SOC golden event rows.
- 5,064 Sigma rules.
- 15/15 current ATT&CK Enterprise tactics covered.

## Reviewer Walkthrough

1. Start dashboard:

   ```bash
   python -m orchestrator.main serve
   ```

2. Open `http://127.0.0.1:8000/dashboard/`.
3. Check Scenario Library source filter `validated actor-chain`.
4. Open Scenario Maturity and confirm 50 fixture-backed scenarios.
5. Start one validated scenario.
6. Open History and download JSON, HTML, and ZIP artifacts.
7. Open Labs and choose one of Windows AD, Linux Fleet, Cloud/Kubernetes, or SaaS/Identity.

## Capability Matrix

| Capability | Project evidence |
| --- | --- |
| ATT&CK coverage | Bundled Enterprise snapshot, drift status, 15/15 tactics, 696 local base IDs |
| Scenario depth | 50 fixture-backed actor-chain DAGs with runbooks and success criteria |
| SOC evidence | ECS fields, OCSF categories, SIEM fields, latency targets, 100 golden events |
| Campaigns | 10/50/100 launch controls, scheduling, repeat, pause, resume, retry failed |
| Execution state | Persistent run history, queue entries, step logs, cleanup status |
| Reports | JSON, HTML, and ZIP artifact bundles |
| Lab tracks | Windows AD, Linux Fleet, Cloud/Kubernetes, SaaS/Identity |
| Safety | Dry-run and marker-only default for scale coverage |

## Honest Boundaries

- The 15,680,015,680 value is deterministic variant space, not committed files.
- The 5,064 TTPs are registered catalog/code entries with Sigma rules, not 5,064 manually validated live procedures.
- The strongest evidence tier is the 50 validated actor-chain scenario pack.
- Cloud, SaaS, Kubernetes, identity, and impact steps are marker-only unless an authorized lab explicitly enables otherwise.
