from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from orchestrator.siem_connectors import (
    elastic_bulk_payload,
    sample_golden_events,
    send_elastic_bulk,
    send_splunk_hec,
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


def test_siem_senders_post_to_local_mock() -> None:
    events = sample_golden_events(limit=2)
    server, base_url = _server()
    try:
        splunk = send_splunk_hec(f"{base_url}/services/collector/event", "splunk-token", events)
        elastic = send_elastic_bulk(base_url, "elastic-key", events)
    finally:
        server.shutdown()

    assert splunk["ok"] is True
    assert splunk["events_sent"] == 2
    assert elastic["ok"] is True
    assert elastic["events_sent"] == 2
    assert len(_CaptureHandler.requests) == 2

    splunk_request = _CaptureHandler.requests[0]
    assert splunk_request["path"] == "/services/collector/event"
    assert splunk_request["authorization"] == "Splunk splunk-token"
    assert splunk_request["body"].count("\n") == 1

    elastic_request = _CaptureHandler.requests[1]
    assert elastic_request["path"] == "/_bulk"
    assert elastic_request["authorization"] == "ApiKey elastic-key"
    assert elastic_request["content_type"] == "application/x-ndjson"
    assert len(elastic_request["body"].splitlines()) == 4
