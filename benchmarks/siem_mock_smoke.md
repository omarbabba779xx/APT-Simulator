# SIEM Mock Smoke

APT Simulator includes lab-safe SIEM connector senders for Splunk HEC, Elastic bulk, Microsoft Sentinel Data Collector, and Google Chronicle UDM ingestion.

The send endpoints are guarded:

- Localhost and private-network URLs are allowed by default.
- Public URLs require `allow_external=true`.
- Payloads come from committed SOC golden events.

## Preview Payloads

```bash
curl http://127.0.0.1:8000/siem/connectors/status
curl http://127.0.0.1:8000/siem/connectors/sample?limit=2
```

## Splunk HEC Compatible Mock

```bash
curl -X POST http://127.0.0.1:8000/siem/connectors/splunk/hec/send \
  -H "Content-Type: application/json" \
  -d "{\"url\":\"http://127.0.0.1:18088/services/collector/event\",\"token\":\"test-token\",\"event_limit\":2}"
```

Expected request shape:

- Method: `POST`
- Header: `Authorization: Splunk test-token`
- Header: `Content-Type: application/json`
- Body: newline-delimited HEC event records

## Elastic Bulk Compatible Mock

```bash
curl -X POST http://127.0.0.1:8000/siem/connectors/elastic/bulk/send \
  -H "Content-Type: application/json" \
  -d "{\"url\":\"http://127.0.0.1:19200\",\"api_key\":\"test-key\",\"event_limit\":2}"
```

Expected request shape:

- Method: `POST`
- Path: `/_bulk`
- Header: `Authorization: ApiKey test-key`
- Header: `Content-Type: application/x-ndjson`
- Body: Elastic bulk NDJSON action/event pairs

## Microsoft Sentinel Data Collector Compatible Mock

```bash
curl -X POST http://127.0.0.1:8000/siem/connectors/sentinel/data-collector/send \
  -H "Content-Type: application/json" \
  -d "{\"url\":\"http://127.0.0.1:18090/api/logs?api-version=2016-04-01\",\"workspace_id\":\"workspace-123\",\"shared_key\":\"<base64-shared-key>\",\"event_limit\":2}"
```

Expected request shape:

- Method: `POST`
- Header: `Authorization: SharedKey workspace-123:<signature>`
- Header: `Log-Type: AptSimulator_CL`
- Body: JSON array of Sentinel-ready event records

## Google Chronicle UDM Compatible Mock

```bash
curl -X POST http://127.0.0.1:8000/siem/connectors/chronicle/udm/send \
  -H "Content-Type: application/json" \
  -d "{\"url\":\"http://127.0.0.1:18091/v2/udmevents:batchCreate\",\"bearer_token\":\"test-token\",\"event_limit\":2}"
```

Expected request shape:

- Method: `POST`
- Header: `Authorization: Bearer test-token`
- Header: `Content-Type: application/json`
- Body: Chronicle-style UDM event envelope
