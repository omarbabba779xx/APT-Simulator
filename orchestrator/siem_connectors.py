"""Lab-safe SIEM connector payloads and senders."""
from __future__ import annotations

import json
import socket
import urllib.parse
import urllib.request
import base64
import hashlib
import hmac
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any

from .scenario_maturity import load_golden_events


SUPPORTED_TARGETS = (
    "splunk_hec",
    "elastic_bulk",
    "sentinel_data_collector",
    "chronicle_udm",
)


def sample_golden_events(limit: int = 10) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for rows in load_golden_events().values():
        events.extend(rows)
        if len(events) >= limit:
            break
    return events[:limit]


def splunk_hec_payload(
    events: list[dict[str, Any]],
    *,
    index: str = "apt_simulator",
    sourcetype: str = "_json",
    source: str = "apt-simulator",
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for event in events:
        out.append(
            {
                "time": _event_epoch_hint(event),
                "host": str(event.get("host.name") or "apt-simulator-lab"),
                "source": source,
                "sourcetype": sourcetype,
                "index": index,
                "event": event,
            }
        )
    return out


def elastic_bulk_payload(events: list[dict[str, Any]], *, index: str = "apt-simulator") -> str:
    lines: list[str] = []
    for event in events:
        scenario = str(event.get("scenario", "scenario")).replace(" ", "_")
        action = {"index": {"_index": index, "_id": f"{scenario}-{len(lines) // 2:04d}"}}
        lines.append(json.dumps(action, sort_keys=True, separators=(",", ":")))
        lines.append(json.dumps(event, sort_keys=True, separators=(",", ":")))
    return "\n".join(lines) + ("\n" if lines else "")


def sentinel_data_collector_payload(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "TimeGenerated": event.get("@timestamp"),
            "Scenario": event.get("scenario"),
            "AttackId": event.get("threat.technique.id"),
            "Host": event.get("host.name"),
            "Source": event.get("event.provider", "apt-simulator"),
            "RawEvent": event,
        }
        for event in events
    ]


def chronicle_udm_payload(events: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "events": [
            {
                "metadata": {
                    "product_name": "APT Simulator",
                    "vendor_name": "APT Simulator",
                    "event_type": "GENERIC_EVENT",
                    "collected_timestamp": event.get("@timestamp"),
                },
                "principal": {
                    "hostname": event.get("host.name", "apt-simulator-lab"),
                },
                "security_result": {
                    "rule_name": event.get("rule.name", event.get("scenario", "scenario")),
                    "severity": "INFORMATIONAL",
                },
                "extensions": {
                    "attack_id": event.get("threat.technique.id"),
                    "scenario": event.get("scenario"),
                    "raw_event": event,
                },
            }
            for event in events
        ]
    }


def send_splunk_hec(
    url: str,
    token: str,
    events: list[dict[str, Any]],
    *,
    index: str = "apt_simulator",
    allow_external: bool = False,
    timeout_seconds: float = 10.0,
) -> dict[str, Any]:
    _require_lab_url(url, allow_external=allow_external)
    payload = "\n".join(
        json.dumps(item, sort_keys=True, separators=(",", ":"))
        for item in splunk_hec_payload(events, index=index)
    ).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Authorization": f"Splunk {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    return _send(request, timeout_seconds=timeout_seconds, events_sent=len(events))


def send_elastic_bulk(
    url: str,
    api_key: str,
    events: list[dict[str, Any]],
    *,
    index: str = "apt-simulator",
    allow_external: bool = False,
    timeout_seconds: float = 10.0,
) -> dict[str, Any]:
    target = url.rstrip("/") + "/_bulk" if not url.rstrip("/").endswith("_bulk") else url
    _require_lab_url(target, allow_external=allow_external)
    payload = elastic_bulk_payload(events, index=index).encode("utf-8")
    request = urllib.request.Request(
        target,
        data=payload,
        headers={
            "Authorization": f"ApiKey {api_key}",
            "Content-Type": "application/x-ndjson",
        },
        method="POST",
    )
    return _send(request, timeout_seconds=timeout_seconds, events_sent=len(events))


def send_sentinel_data_collector(
    url: str,
    workspace_id: str,
    shared_key: str,
    events: list[dict[str, Any]],
    *,
    log_type: str = "AptSimulator_CL",
    allow_external: bool = False,
    timeout_seconds: float = 10.0,
) -> dict[str, Any]:
    target = (
        url
        or f"https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
    )
    _require_lab_url(target, allow_external=allow_external)
    payload = json.dumps(
        sentinel_data_collector_payload(events),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    request = urllib.request.Request(
        target,
        data=payload,
        headers={
            "Authorization": _sentinel_signature(workspace_id, shared_key, date, len(payload)),
            "Content-Type": "application/json",
            "Log-Type": log_type,
            "x-ms-date": date,
        },
        method="POST",
    )
    return _send(request, timeout_seconds=timeout_seconds, events_sent=len(events))


def send_chronicle_udm(
    url: str,
    bearer_token: str,
    events: list[dict[str, Any]],
    *,
    allow_external: bool = False,
    timeout_seconds: float = 10.0,
) -> dict[str, Any]:
    _require_lab_url(url, allow_external=allow_external)
    payload = json.dumps(
        chronicle_udm_payload(events),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Authorization": f"Bearer {bearer_token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    return _send(request, timeout_seconds=timeout_seconds, events_sent=len(events))


def connector_status() -> dict[str, Any]:
    sample = sample_golden_events(limit=5)
    return {
        "targets": list(SUPPORTED_TARGETS),
        "sample_events": len(sample),
        "default_safety": "localhost/private-network only unless allow_external is explicit",
        "splunk_hec": {
            "method": "POST",
            "content_type": "application/json",
            "auth_header": "Authorization: Splunk <token>",
            "payload_records": len(splunk_hec_payload(sample)),
        },
        "elastic_bulk": {
            "method": "POST",
            "content_type": "application/x-ndjson",
            "auth_header": "Authorization: ApiKey <key>",
            "bulk_lines": len(elastic_bulk_payload(sample).splitlines()),
        },
        "sentinel_data_collector": {
            "method": "POST",
            "content_type": "application/json",
            "auth_header": "Authorization: SharedKey <workspace>:<signature>",
            "payload_records": len(sentinel_data_collector_payload(sample)),
        },
        "chronicle_udm": {
            "method": "POST",
            "content_type": "application/json",
            "auth_header": "Authorization: Bearer <token>",
            "payload_records": len(chronicle_udm_payload(sample)["events"]),
        },
    }


def _send(request: urllib.request.Request, *, timeout_seconds: float, events_sent: int) -> dict[str, Any]:
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        body = response.read().decode("utf-8", errors="replace")
        return {
            "ok": 200 <= int(response.status) < 300,
            "status_code": int(response.status),
            "events_sent": events_sent,
            "response_excerpt": body[:500],
        }


def _require_lab_url(url: str, *, allow_external: bool) -> None:
    if allow_external:
        return
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("SIEM URL must be http(s)")
    host = parsed.hostname
    if host in {"localhost", "127.0.0.1", "::1"}:
        return
    try:
        addresses = {ip_address(info[4][0]) for info in socket.getaddrinfo(host, parsed.port or 443)}
    except socket.gaierror as exc:
        raise ValueError(f"SIEM host cannot resolve: {host}") from exc
    if any(address.is_private or address.is_loopback for address in addresses):
        return
    raise ValueError("SIEM URL is not local/private; set allow_external=true explicitly")


def _sentinel_signature(
    workspace_id: str,
    shared_key: str,
    date: str,
    content_length: int,
) -> str:
    x_headers = f"x-ms-date:{date}"
    string_to_hash = f"POST\n{content_length}\napplication/json\n{x_headers}\n/api/logs"
    decoded_key = base64.b64decode(shared_key)
    digest = hmac.new(decoded_key, string_to_hash.encode("utf-8"), hashlib.sha256).digest()
    encoded_hash = base64.b64encode(digest).decode("utf-8")
    return f"SharedKey {workspace_id}:{encoded_hash}"


def _event_epoch_hint(event: dict[str, Any]) -> float | None:
    value = event.get("@timestamp")
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()
