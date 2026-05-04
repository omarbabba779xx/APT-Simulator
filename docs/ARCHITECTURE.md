# Architecture

## Components

### Orchestrator (`orchestrator/`)

FastAPI server. Holds the in-memory `Planner` (active runs + step states), an
`AuditLog` (hash-chained JSONL), a `KillSwitch`, and the loaded `Scenario`
catalog. Issues signed task descriptors to agents on beacon.

Modules:

- `core/config.py` — pydantic config models, YAML loader.
- `core/killswitch.py` — checks env var `APT_SIM_STOP` and a flag file.
- `core/audit.py` — append-only JSONL with sha256 chain (`prev` → `hash`).
- `core/signer.py` — Ed25519 keygen, sign, verify (CLI: `python -m orchestrator.core.signer init`).
- `core/planner.py` — Run / StepState; DAG-aware task dispatch.
- `dsl/schema.py` — pydantic models for scenarios + DAG validation.
- `dsl/loader.py` — YAML loader.
- `api/` — FastAPI routers (`agents`, `scenarios`, `ttps`, `killswitch`).
- `main.py` — Typer CLI: `serve`, `verify-audit`.

### Agent (`agent/`)

- `safety.py` — pre-flight: killswitch + lab whitelist.
- `runtime.py` — TTP loader + signature verifier.
- `beacon.py` — register → poll → execute → report. TTL self-terminate.
- `main.py` — CLI: `apt-agent run --server URL`.

### TTPs (`ttps/`)

Plugin library, each module self-registers on import. Phase 1 set:

| ATT&CK ID | Tactic      | Module                                  | Notes                                                 |
|-----------|-------------|-----------------------------------------|-------------------------------------------------------|
| T1033     | Discovery   | `discovery/t1033_user_discovery.py`     | Read-only system queries.                             |
| T1083     | Discovery   | `discovery/t1083_file_discovery.py`     | Bounded directory walk, no exfil.                     |
| T1059     | Execution   | `execution/t1059_command_sim.py`        | Fixed allowlist; never executes user-supplied shell.  |
| T1547.001 | Persistence | `persistence/t1547_registry_runkey.py`  | Writes only under `HKCU\Software\AptSimulator\Test`.  |

## Data flow

1. Operator `POST /scenarios/run` (by name or inline).
2. Planner instantiates a `Run`, expands steps into `StepState` dict.
3. Each agent on beacon calls `next_task_for_agent` → planner returns a step
   whose dependencies are all `success`.
4. Task is signed (Ed25519 over canonical JSON) before transmission.
5. Agent verifies signature → runs the registered TTP → POSTs result.
6. Planner cascades `abort_on_fail`. When all steps terminal → run completes.
7. Every state transition is audit-logged (hash-chained JSONL).

## Safety guardrails (recap)

- Killswitch (env or file) — orchestrator aborts runs, agents exit on next beacon or local check.
- Lab whitelist — agent refuses to start outside allowed hostnames/CIDRs.
- Signed payloads — agent rejects unsigned tasks when key is configured.
- TTL — agent self-terminates after `--ttl-seconds` (default 4 h).
- Allowlisted commands — T1059 cannot run arbitrary shell.
- Isolated registry path — T1547 cannot touch real Run keys.
- Hash-chained audit — tamper with any past line breaks `verify-audit`.

## Roadmap (phases)

- **Phase 2** — chained APT scenarios (APT29, FIN7), C2 traffic patterns,
  Sigma rule generation, dashboard.
- **Phase 3** — cloud TTPs (AWS/Azure/GCP), Atomic Red Team integration,
  purple-team coverage matrix.
