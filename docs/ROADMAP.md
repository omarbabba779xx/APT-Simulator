# Roadmap

## Phase 1 — Foundation ✅ Complete

- [x] Project scaffold, packaging, CI-ready layout
- [x] Hash-chained audit log (SHA-256 hash chain, OTel export)
- [x] Ed25519 payload signing (keygen + verify on agent)
- [x] Killswitch (env + flag file) + lab whitelist (hostname + CIDR)
- [x] Scenario DSL (YAML + pydantic + DAG validator with cycle detection)
- [x] Orchestrator (FastAPI) + Planner (in-memory, DAG-aware dispatch)
- [x] Beacon agent (Windows/Linux, TTL self-terminate, jitter)
- [x] Initial TTPs: T1033, T1083, T1059 (sim), T1547.001 (sim)
- [x] Persist runs to SQLite across restarts (SQLModel)
- [x] Sigma rule auto-generation per TTP (`sigma_export export`)
- [x] JWT-based RBAC (viewer / operator / admin)
- [x] pytest suite: DSL, audit, killswitch, planner, signer, TTPs, RBAC

## Phase 2 + Phase 3 — Realism & Advanced ✅ Complete

- [x] More TTPs: T1057, T1003, T1027, T1071.001, T1112, T1070.004, T1098.004, T1543.002, T1580
- [x] New Phase 2 TTPs: T1016, T1049, T1053.005, T1105, T1486 (impact sim)
- [x] Chained scenarios: APT29-style, FIN7-style, Lazarus-style, Linux recon, cross-platform
- [x] Realistic C2 traffic patterns: jitter modes (uniform/exponential/normal), sleep windows, UA rotation
- [x] Detection coverage dashboard (live event feed, run step-detail modal, MITRE matrix)
- [x] Auto-import Atomic Red Team YAML (`art_import scan / convert`)
- [x] Sigma rule evaluator + detection diff (`detection_diff verify / report`)
- [x] Sigma transpiler to Splunk SPL + Elastic Lucene (`sigma_transpile transpile`)
- [x] Fuzz scenario generator (bounded, reproducible, `--seed`)
- [x] Audit replay CLI (`replay show / list-runs`)
- [x] Coverage HTML report (`coverage_report generate`)
- [x] `/runs/{run_id}/steps` step-detail API endpoint
- [x] New Phase 3 TTPs: T1082, T1069.001, T1005 (collection), T1041 (exfil sim)
- [x] **ATT&CK Navigator layer export** — `GET /coverage/navigator` + CLI (`navigator_export export`)
- [x] **Adversary profiles** (APT29, FIN7, Lazarus, APT41) in `profiles/*.yaml`
- [x] **Profile-driven scenario generator** — `profile_gen generate <actor>` + `POST /profiles/{id}/generate`
- [x] **Standalone agent local-run mode** — `apt-agent run-local <scenario.yaml>` (no orchestrator needed)
- [x] **Metrics endpoint** — `GET /metrics` (run stats, TTP success rates, agent breakdown)
- [x] APT41 Linux intrusion scenario (full kill-chain with collection + exfil)
- [x] pytest suite covering current features

## Phase 4 — Cloud + Scale

- [x] AWS Stratus-style simulated TTPs: T1078.004 (Cloud Account abuse), T1530 (Data from Storage)
- [x] Catalog-driven TTP packs for Windows, Linux, cloud, identity, and SaaS marker-only variants
- [x] ATT&CK STIX importer and full Enterprise marker-only catalog with 5,064 registered TTPs/variants
- [x] ECS / OCSF golden telemetry fixture export
- [x] Detection scoring with coverage percentage, missing fields, and false-positive risk
- [x] Graph-based scenario builder with actor and difficulty profiles
- [x] Campaign queue and synthetic replay event generation
- [x] ATT&CK sync snapshot and drift status for 15/15 Enterprise tactics
- [x] ATT&CK Emulation Library safe scenario import
- [x] Cloud/Kubernetes marker-only lab pack
- [x] Active Directory/Windows enterprise marker-only lab pack
- [x] Scheduled and recurring campaign runs
- [x] Detection-as-code workbench for Sigma quality, fields, risk, and target readiness
- [x] Controlled exposure graph across identity, endpoint, cloud, SaaS, and container domains
- [x] Fixture-backed validated actor-chain scenarios with maturity scoring and SOC evidence contracts
- [x] Azure / Entra ID privilege escalation simulation
- [x] GCP resource manager discovery expansion
- [ ] gRPC C2 channel option (alternative to HTTP)
- [ ] PyInstaller / Nuitka agent builds for portable Windows/Linux/macOS deployment
- [ ] Multi-agent parallel dispatch (multiple agents on same scenario)
- [ ] SIEM connector: direct Splunk HEC / Elastic ingest pipeline push
