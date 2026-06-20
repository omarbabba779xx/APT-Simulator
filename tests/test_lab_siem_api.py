from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from fastapi.testclient import TestClient

from orchestrator.main import build_app


class _MockSIEM(BaseHTTPRequestHandler):
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
        self.wfile.write(b'{"accepted":true}')

    def log_message(self, _format: str, *_args: object) -> None:
        return


def _mock_server() -> tuple[HTTPServer, str]:
    _MockSIEM.requests = []
    server = HTTPServer(("127.0.0.1", 0), _MockSIEM)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_port}"


def test_multi_agent_smoke_and_siem_send_endpoints() -> None:
    client = TestClient(build_app("config/default.yaml"))

    lab = client.post("/labs/multi-agent/smoke")
    assert lab.status_code == 200
    lab_body = lab.json()
    assert lab_body["ok"] is True
    assert lab_body["distinct_assigned_agents"] == 3

    server, base_url = _mock_server()
    try:
        splunk = client.post(
            "/siem/connectors/splunk/hec/send",
            json={
                "url": f"{base_url}/services/collector/event",
                "token": "splunk-token",
                "event_limit": 2,
            },
        )
        elastic = client.post(
            "/siem/connectors/elastic/bulk/send",
            json={
                "url": base_url,
                "api_key": "elastic-key",
                "event_limit": 2,
            },
        )
    finally:
        server.shutdown()

    assert splunk.status_code == 200
    assert splunk.json()["events_sent"] == 2
    assert elastic.status_code == 200
    assert elastic.json()["events_sent"] == 2
    assert _MockSIEM.requests[0]["authorization"] == "Splunk splunk-token"
    assert _MockSIEM.requests[1]["path"] == "/_bulk"
    assert _MockSIEM.requests[1]["authorization"] == "ApiKey elastic-key"
