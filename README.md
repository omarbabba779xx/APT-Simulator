# APT Simulator

Defensive Advanced Persistent Threat emulation framework. Built for purple team exercises, detection engineering, and SOC training in **authorized lab environments only**.

## Mission

Replay realistic adversary behavior chains (mapped to MITRE ATT&CK) so blue teams can validate detections, tune SIEM rules, and measure coverage gaps — without using real malware.

## Non-goals

- Not a weaponized offensive tool. Payloads are simulated artifacts, not destructive code.
- Not for use against systems you do not own or have written authorization to test.
- Not a replacement for full red team engagement.

## Architecture

```
+-------------------+        +---------------------+
|  Scenario YAML    | -----> |  Orchestrator       |
|  (DSL)            |        |  (FastAPI)          |
+-------------------+        +----------+----------+
                                        |
                          +-------------+-------------+
                          |             |             |
                     +----v---+    +----v---+    +----v---+
                     | Agent  |    | Agent  |    | Agent  |
                     | Win/Lin|    | Win/Lin|    | Win/Lin|
                     +--------+    +--------+    +--------+
                          |             |             |
                       (TTPs executed inside lab VM only)
                          |             |             |
                          +------+------+------+------+
                                 |
                       +---------v---------+
                       | Telemetry / JSONL |
                       | (SIEM-compatible) |
                       +-------------------+
```

## Safety guardrails

1. **Kill-switch**: presence of `data/STOP` or env `APT_SIM_STOP=1` halts all agents within one beacon cycle.
2. **Lab whitelist**: agents refuse to run if hostname/IP is not in `config/lab_whitelist.yaml`.
3. **Signed payloads**: every TTP payload signed with Ed25519. Agents verify before execution.
4. **TTL auto-uninstall**: agents self-terminate after configured TTL without orchestrator heartbeat.
5. **Simulation-only Impact**: destructive tactics (T1485, T1486) write benign marker files, never real data.
6. **Audit log**: hash-chained JSONL of every action; tampering detectable.

## Quick start

```bash
# 1. Install
python -m venv .venv
. .venv/Scripts/activate   # Windows
pip install -e ".[dev]"

# 2. Generate signing keys (one-time)
python -m orchestrator.core.signer init

# 3. Add this host to lab whitelist
edit config/lab_whitelist.yaml

# 4. Start orchestrator
apt-orchestrator serve

# 5. In another terminal — run agent
apt-agent run --server http://127.0.0.1:8000

# 6. Launch a scenario
curl -X POST http://127.0.0.1:8000/scenarios/run \
     -H "Content-Type: application/json" \
     -d @scenarios/basic_recon.yaml
```

## Project layout

```
orchestrator/   FastAPI server, planner, kill-switch, audit, DSL loader
agent/          Beacon agent (Windows / Linux)
ttps/           TTP plugin library, mapped to MITRE ATT&CK IDs
scenarios/      YAML scenario definitions
detection/      Generated Sigma rules + detection coverage reports
config/         Defaults + lab whitelist
tests/          pytest suite
docs/           Architecture + threat model
```

## MITRE ATT&CK coverage (Phase 1 + 2 + 3)

| Tactic               | TTP                                | ATT&CK ID  | Platforms             |
|----------------------|------------------------------------|------------|-----------------------|
| Discovery            | System Owner/User Discovery        | T1033      | all                   |
| Discovery            | File and Directory Discovery       | T1083      | all                   |
| Discovery            | Process Discovery                  | T1057      | all                   |
| Discovery            | Network Config Discovery           | T1016      | all                   |
| Discovery            | Network Connections Discovery      | T1049      | all                   |
| Discovery            | Cloud Infrastructure Discovery     | T1580      | all (cloud creds req) |
| Execution            | Command Interpreter (sim)          | T1059      | all                   |
| Initial Access       | Valid Cloud Accounts (sim)         | T1078.004  | all                   |
| Persistence          | Registry Run Key (sim, Windows)    | T1547.001  | windows               |
| Persistence          | Scheduled Task (sim, Windows)      | T1053.005  | windows               |
| Persistence          | SSH Authorized Keys (sim)          | T1098.004  | linux/macOS           |
| Persistence          | Systemd User Service (sim)         | T1543.002  | linux                 |
| Credential Access    | Credential Target Enumeration      | T1003      | all                   |
| Defense Evasion      | Obfuscated File Artifact (sim)     | T1027      | all                   |
| Defense Evasion      | Indicator Removal: File Deletion   | T1070.004  | all                   |
| Defense Evasion      | Modify Registry (sim, Windows)     | T1112      | windows               |
| Command & Control    | HTTP C2 Beaconing (sim)            | T1071.001  | all                   |
| Command & Control    | Ingress Tool Transfer (sim)        | T1105      | all                   |
| Collection           | Data from Local System (sim)       | T1005      | all                   |
| Collection           | Data from Cloud Storage Object     | T1530      | all                   |
| Exfiltration         | Exfil Over C2 Channel (sim)        | T1041      | all                   |
| Impact               | Data Encrypted for Impact (sim)    | T1486      | all                   |

Each TTP ships a Sigma rule, synthetic SIEM events, and cleanup method.
24 TTPs across 10 tactics. Full roadmap in `docs/ROADMAP.md`.

## Key Features

- **ATT&CK Navigator Export** — `GET /coverage/navigator` returns a full Navigator v4 layer JSON. Import directly into [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to visualize coverage.
- **Adversary Profiles** — 4 built-in profiles (APT29, FIN7, Lazarus, APT41) in `profiles/`. `POST /profiles/{name}/generate` generates a scenario matching that actor's documented behaviour.
- **Profile-Driven Scenario Generator** — `python -m orchestrator.profile_gen generate apt29 --steps 8`
- **Standalone Agent** — `apt-agent run-local scenarios/basic_recon.yaml --dry-run` runs TTPs without an orchestrator (offline CI mode).
- **Metrics API** — `GET /metrics` returns run counts, TTP success rates, agent breakdown.
- **Live Audit Feed** — Dashboard WebSocket panel shows every audit event in real time.
- **Step Detail Modal** — Click any run row in the dashboard to see per-step timing, output, and errors.
- **Cloud Account + Storage Simulation** — `scenarios/cloud_account_storage_sim.yaml` generates CloudTrail-style markers for T1078.004 and T1530 without contacting cloud providers.

## CLI Reference

```bash
# Start orchestrator
apt-orchestrator serve

# Run a scenario locally (no orchestrator needed)
apt-agent run-local scenarios/basic_recon.yaml --skip-safety

# Export ATT&CK Navigator layer
python -m orchestrator.navigator_export export --out layer.json

# List adversary profiles
python -m orchestrator.profile_gen list

# Generate a scenario from a profile
python -m orchestrator.profile_gen generate lazarus --steps 10 --out scenarios/lazarus_gen.yaml

# Export Sigma rules
python -m orchestrator.sigma_export export --out detection/sigma/

# Fuzz a random scenario
python -m orchestrator.fuzz generate --seed 42

# Replay audit log
python -m orchestrator.replay list-runs

# Detection diff
python -m orchestrator.detection_diff verify --run-id <id>
```

## License

MIT — see `LICENSE`. Includes ethical use notice.
