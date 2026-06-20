from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from orchestrator.siem_connectors import (
    chronicle_udm_payload,
    elastic_bulk_payload,
    sample_golden_events,
    send_elastic_bulk,
    send_chronicle_udm,
    send_sentinel_data_collector,
    send_splunk_hec,
    sentinel_data_collector_payload,
    splunk_hec_payload,
)


class _CaptureHandler(BaseHTTPRequestHandler):
    requests: list[dict[str, Any]] = []

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        self.__class__.requests.append(
            {
                "path": self.path,
                "authorization": self.headers.get("Authorization", ""),
                "content_type": self.headers.get("Content-Type", ""),
                "body": body,
            }
        )
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def log_message(self, _format: str, *_args: object) -> None:
        return


def _server() -> tuple[HTTPServer, str]:
    _CaptureHandler.requests = []
    server = HTTPServer(("127.0.0.1", 0), _CaptureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_port}"


def test_siem_payloads_use_committed_golden_events() -> None:
    events = sample_golden_events(limit=2)
    assert len(events) == 2
    splunk = splunk_hec_payload(events)
    assert len(splunk) == 2
    assert splunk[0]["event"]["scenario"]
    assert splunk[0]["index"] == "apt_simulator"

    bulk = elastic_bulk_payload(events, index="apt-simulator-test")
    lines = bulk.splitlines()
    assert len(lines) == 4
    assert '"_index":"apt-simulator-test"' in lines[0]
    assert '"scenario"' in lines[1]

    sentinel = sentinel_data_collector_payload(events)
    assert len(sentinel) == 2
    assert sentinel[0]["RawEvent"]["scenario"]

    chronicle = chronicle_udm_payload(events)
    assert len(chronicle["events"]) == 2
    assert chronicle["events"][0]["metadata"]["product_name"] == "APT Simulator"


def test_siem_senders_post_to_local_mock() -> None:
    events = sample_golden_events(limit=2)
    server, base_url = _server()
    shared_key = base64.b64encode(b"sentinel-shared-key-32-bytes").decode("ascii")
    try:
        splunk = send_splunk_hec(f"{base_url}/services/collector/event", "splunk-token", events)
        elastic = send_elastic_bulk(base_url, "elastic-key", events)
        sentinel = send_sentinel_data_collector(
            f"{base_url}/api/logs?api-version=2016-04-01",
            "workspace-123",
            shared_key,
            events,
        )
        chronicle = send_chronicle_udm(f"{base_url}/v2/udmevents:batchCreate", "chronicle-token", events)
    finally:
        server.shutdown()

    assert splunk["ok"] is True
    assert splunk["events_sent"] == 2
    assert elastic["ok"] is True
    assert elastic["events_sent"] == 2
    assert sentinel["ok"] is True
    assert sentinel["events_sent"] == 2
    assert chronicle["ok"] is True
    assert chronicle["events_sent"] == 2
    assert len(_CaptureHandler.requests) == 4

    splunk_request = _CaptureHandler.requests[0]
    assert splunk_request["path"] == "/services/collector/event"
    assert splunk_request["authorization"] == "Splunk splunk-token"
    assert splunk_request["body"].count("\n") == 1

    elastic_request = _CaptureHandler.requests[1]
    assert elastic_request["path"] == "/_bulk"
    assert elastic_request["authorization"] == "ApiKey elastic-key"
    assert elastic_request["content_type"] == "application/x-ndjson"
    assert len(elastic_request["body"].splitlines()) == 4

    sentinel_request = _CaptureHandler.requests[2]
    assert sentinel_request["path"] == "/api/logs?api-version=2016-04-01"
    assert sentinel_request["authorization"].startswith("SharedKey workspace-123:")
    assert sentinel_request["content_type"] == "application/json"
    assert len(json.loads(sentinel_request["body"])) == 2

    chronicle_request = _CaptureHandler.requests[3]
    assert chronicle_request["path"] == "/v2/udmevents:batchCreate"
    assert chronicle_request["authorization"] == "Bearer chronicle-token"
    assert len(json.loads(chronicle_request["body"])["events"]) == 2
