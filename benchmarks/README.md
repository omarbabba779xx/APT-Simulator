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

It contains current API snapshots for platform readiness, Execution Engine v3, import center, and evidence summary.
