# apt-simulator Helm chart

Deploys the APT Simulator to Kubernetes:

- **orchestrator** — single Deployment + ClusterIP Service + PVC
- **agent** — DaemonSet (one beacon per node)
- **NetworkPolicy** — restricts orchestrator ingress to agent pods + optional operator namespace

## Install

```bash
# Build and load images first (or push to your registry).
docker build -f Dockerfile.orchestrator -t apt-sim/orchestrator:latest .
docker build -f Dockerfile.agent -t apt-sim/agent:latest .

# Install into the lab namespace.
kubectl create namespace apt-sim-lab
helm install apt-sim ./helm/apt-simulator -n apt-sim-lab
```

## Safety

- Only deploy in an isolated lab cluster. The agent DaemonSet runs simulated TTPs on every node it lands on.
- `agent.labOverride: true` (default) bypasses the host whitelist — required for containers but **dangerous outside a lab**.
- `auth.enabled: true` to force JWT-bearer auth on every orchestrator endpoint.

## Values

See `values.yaml` for the complete schema.
