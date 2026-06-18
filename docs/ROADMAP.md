# Roadmap

## Phase 1 - Foundation - Complete

- [x] Project scaffold, packaging, CI-ready layout.
- [x] Hash-chained audit log, payload signing, killswitch, and lab whitelist.
- [x] Scenario DSL with YAML, pydantic models, DAG validation, and cycle detection.
- [x] FastAPI orchestrator, DAG-aware planner, and beacon agent.
- [x] SQLite persistence for agents, runs, and step instances.
- [x] Sigma rule export per TTP.
- [x] JWT-based RBAC with viewer, operator, and admin roles.
- [x] pytest coverage for DSL, audit, killswitch, planner, signer, TTPs, and RBAC.

## Phase 2 + Phase 3 - Realism And Advanced Coverage - Complete

- [x] Core endpoint, host, credential, C2, persistence, collection, exfiltration, and impact simulations.
- [x] Chained scenarios for APT29-style, FIN7-style, Lazarus-style, Linux recon, and cross-platform flows.
- [x] C2 traffic patterns with jitter modes, sleep windows, and user-agent rotation.
- [x] Dashboard with coverage, event feed, step detail, and ATT&CK matrix views.
- [x] Atomic Red Team import path for safe defensive references.
- [x] Sigma evaluator, detection diff, and transpilers for Splunk and Elastic query sketches.
- [x] Fuzz scenario generator and audit replay CLI.
- [x] ATT&CK Navigator export.
- [x] Actor profiles and profile-driven scenario generation.
- [x] Standalone local-run mode.
- [x] Metrics endpoint.

## Phase 4 - Cloud, Scale, And Detection Engineering - Complete

- [x] Catalog-driven Windows, Linux, cloud, identity, SaaS, Cloud/Kubernetes, and AD/Windows enterprise packs.
- [x] ATT&CK STIX snapshot sync and full Enterprise marker-only catalog.
- [x] 5,064 registered TTPs/variants and 5,064 Sigma rules.
- [x] 15/15 current ATT&CK Enterprise tactics covered.
- [x] 2,500 committed generated YAML scenarios.
- [x] 11 safe emulation-plan scenarios.
- [x] Detection workbench for Sigma quality, field gaps, false-positive risk, and target readiness.
- [x] Controlled exposure graph across identity, endpoint, cloud, SaaS, and container domains.
- [x] Scheduled and recurring campaign runs.

## Phase 5 - Evidence, Product Readiness, And Persistent Operations - Complete

- [x] 50 fixture-backed validated actor-chain scenarios.
- [x] 100 SOC golden event rows with ECS, OCSF, SIEM, latency, and cleanup fields.
- [x] Scenario maturity scoring with evidence-quality counters.
- [x] Persistent execution queue entries.
- [x] Persistent run history, step logs, and artifact records.
- [x] JSON, HTML, and ZIP run artifact exports.
- [x] Cleanup-plan endpoint for terminal run review.
- [x] Lab profiles for Windows AD, Linux fleet, Cloud/Kubernetes, and SaaS/Identity testing.
- [x] Dashboard History, Labs, and Access views.
- [x] Public evidence and verification guide.

## Next Reference-Level Work

- [ ] Direct SIEM connectors for Splunk HEC and Elastic ingest pipeline push.
- [ ] Portable agent builds for Windows, Linux, and macOS.
- [ ] Stronger multi-host execution policies with host groups and explicit step placement.
- [ ] Rich downloadable evidence packs with screenshots or recorded dashboard walkthroughs.
- [ ] More actor-chain scenarios validated in real lab environments.
