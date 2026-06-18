# Expansion Architecture

APT Simulator now supports two TTP surfaces:

- Python TTPs in `ttps/*/*.py` for simulations that need custom logic.
- Catalog TTPs in `ttps/catalog/*.yaml` for marker-only variants at scale.

Catalog entries register as normal TTPs. They provide metadata, safety tier,
Sigma rule, synthetic events, parameter defaults, cleanup, and marker output.

## Safety Tiers

| Tier | Meaning |
| --- | --- |
| `marker-only` | Writes only simulator marker files and synthetic telemetry. |
| `read-only` | Allows local read-only enumeration. |
| `lab-write` | Allows bounded writes under simulator-controlled paths. |
| `network-lab-only` | Allows only lab/loopback network targets. |

Explicit `live_mode` is blocked unless `APT_SIM_LIVE_MODE=authorized` is set.
If `APT_SIM_SAFETY_TOKEN` is set, the run params must include the same
`safety_token`.

## Scaling ATT&CK Coverage

The repository includes `ttps/catalog/attack_enterprise.yaml`, generated from
ATT&CK Enterprise STIX, plus controlled marker-only variants in
`ttps/catalog/attack_variants.yaml`. The registry currently loads 851 safe
TTPs/variants across Python modules and catalog-backed entries.

Refresh marker-only stubs from ATT&CK Enterprise STIX:

```bash
apt-attack-import import-stix --out ttps/catalog/attack_enterprise.yaml
```

Use `--limit` for partial imports during review:

```bash
apt-attack-import import-stix --limit 50 --out ttps/catalog/attack_enterprise_sample.yaml
```

This is how the project maintains broad ATT&CK coverage without handwritten
Python modules for every technique.

## Detection Exports

```bash
apt-detection-matrix matrix
apt-detection-matrix fixtures --out-dir detection/fixtures
apt-detection-matrix queries --out-dir detection/queries
```

Fixtures are emitted as:

- raw simulator events
- ECS-shaped JSONL
- OCSF-shaped JSONL

Query sketches are emitted for:

- Splunk
- Elastic
- Sentinel
- Chronicle

## Scenario And Scale Tools

```bash
apt-scenario-builder generate --actor cloud-intrusion --difficulty realistic --steps 12
apt-campaign build-queue --actors apt29,fin7,cloud-intrusion --repeats 5
apt-campaign materialize-variants --count 2500 --offset 0 --stride 6272006 --out-dir scenarios/generated
apt-campaign replay-events --events 10000
```

Generated scenarios use DAG dependencies and dry-run parameters by default.
