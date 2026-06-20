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

The `/enterprise/access` endpoint exposes the viewer/operator/admin matrix and the OIDC SSO configuration contract. Set the OIDC fields when integrating with an enterprise identity provider:

```yaml
security:
  sso_enabled: true
  sso_provider: oidc
  oidc_issuer: https://idp.example.com/
  oidc_audience: apt-simulator
  oidc_jwks_url: https://idp.example.com/.well-known/jwks.json
  rbac_role_claim: role
```

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

The `/enterprise/agent-packaging` endpoint lists the Windows, Linux, and macOS build matrix. Production builds should be signed or attested before fleet deployment.

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

Splunk HEC and Elastic bulk ingestion are implemented as guarded send endpoints. Microsoft Sentinel and Google Chronicle are supported through query validation and field-mapping workflows in the Detection Workbench.

Use:

```bash
curl http://127.0.0.1:8000/enterprise/siem-validation
curl http://127.0.0.1:8000/siem/connectors/status
```

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
