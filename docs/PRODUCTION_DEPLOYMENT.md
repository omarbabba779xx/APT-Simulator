# Production Deployment

APT Simulator can be deployed as an internal defensive lab service. Production deployment should keep the orchestrator, agents, SIEM endpoints, and lab networks under written authorization and change control.

## Baseline

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
python -m orchestrator.main serve --host 127.0.0.1 --port 8000
```

For containerized deployments, start from `docker-compose.yml` or the Helm chart in `helm/apt-simulator/`.

## Authentication And Access

Enable local JWT RBAC for shared environments:

```yaml
security:
  require_auth: true
  jwt_secret_path: keys/jwt_secret.bin
  jwt_algorithm: HS256
  rbac_role_claim: role
```

Use the environment override for production secret injection:

```bash
export APT_SIM_JWT_SECRET="<secret-from-vault>"
```

The `/enterprise/access` endpoint exposes the viewer/operator/admin matrix and the OIDC/JWKS validation status. Set the OIDC fields when integrating with an enterprise identity provider:

```yaml
security:
  sso_enabled: true
  sso_provider: oidc
  oidc_issuer: https://idp.example.com/
  oidc_audience: apt-simulator
  oidc_jwks_url: https://idp.example.com/.well-known/jwks.json
  rbac_role_claim: role
  rbac_role_map:
    soc-operators: operator
    soc-admins: admin
```

For offline validation or CI, use `oidc_jwks_path` with a local JWKS file instead of `oidc_jwks_url`.

## Secrets Management

The `/enterprise/secrets` endpoint returns a redacted inventory only. It never returns secret material. Use environment variables or a deployment-time secret mount for:

- `APT_SIM_JWT_SECRET`
- signing private key material
- signing public key material
- SIEM endpoint credentials

## Agent Packaging

Build agents from the repository root:

```powershell
.\packaging\build_agent.ps1
```

```bash
./packaging/build_agent.sh
```

The `/enterprise/agent-packaging` endpoint lists the Windows, Linux, and macOS build matrix, including the Windows service installer, Linux systemd unit, and macOS launchd plist. Production builds should be signed or attested before fleet deployment.

## Audit Export

The audit log is hash-chained JSONL. Export it with:

```bash
curl -o audit-export.zip http://127.0.0.1:8000/reports/audit-export.zip
```

The ZIP contains:

- `audit.jsonl`
- `audit_manifest.json`
- chain validation status
- first and last timestamps
- final hash

## SIEM Validation

Splunk HEC, Elastic bulk, Microsoft Sentinel Data Collector, and Google Chronicle UDM ingestion are implemented as guarded send endpoints. They use committed SOC golden events and enforce localhost/private-network safety by default.

Use:

```bash
curl http://127.0.0.1:8000/enterprise/siem-validation
curl http://127.0.0.1:8000/siem/connectors/status
```

## Real-Lab Evidence Registry

External SIEM exports, screenshots, host logs, and campaign reports can be registered through:

```bash
curl http://127.0.0.1:8000/lab-evidence/template
curl http://127.0.0.1:8000/lab-evidence/summary
```

The registry stores references and SHA-256 values. It does not bundle customer lab artifacts by default.

## Load Testing

The enterprise load plan defines 10, 50, 100, 500, and 1,000 scenario profiles:

```bash
curl http://127.0.0.1:8000/enterprise/load-test/plan
curl "http://127.0.0.1:8000/scenario-builder/batch-preview?count=100"
```

For long campaigns, capture queue depth, history records, reports, audit export, and SIEM ingest results.

## Verification Bundle

Export the benchmark bundle after deployment:

```bash
curl -o benchmark-pack.zip http://127.0.0.1:8000/reports/benchmark-pack.zip
```

The benchmark bundle includes readiness snapshots, enterprise validation snapshots, public evidence docs, and load-test artifacts.
