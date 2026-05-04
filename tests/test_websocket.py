from __future__ import annotations

from fastapi.testclient import TestClient

from orchestrator.main import build_app


def test_ws_hello_then_event() -> None:
    app = build_app("config/default.yaml")
    # `with` is required so lifespan startup runs and EventBus binds to loop.
    with TestClient(app) as client:
        with client.websocket_connect("/ws") as ws:
            hello = ws.receive_json()
            assert hello["event"] == "ws.hello"

            # Trigger an audit event by registering an agent via REST.
            r = client.post("/agents/register", json={"hostname": "lab-vm", "platform": "linux", "pid": 42})
            assert r.status_code == 200

            # Drain heartbeats until the agent.register event lands.
            seen = None
            for _ in range(20):
                ev = ws.receive_json()
                if ev.get("event") == "agent.register":
                    seen = ev
                    break
            assert seen is not None
            assert seen["payload"]["hostname"] == "lab-vm"
