"""Tests for the /runs/{run_id}/steps detail endpoint."""
from __future__ import annotations

from fastapi.testclient import TestClient

from orchestrator.main import build_app


def _client() -> TestClient:
    return TestClient(build_app("config/default.yaml"))


def test_run_steps_not_found() -> None:
    with _client() as c:
        r = c.get("/runs/nonexistent_id/steps")
        assert r.status_code == 404


def test_run_steps_returns_detail() -> None:
    with _client() as c:
        run_resp = c.post("/scenarios/run", json={"name": "basic_recon"})
        assert run_resp.status_code == 200
        run_id = run_resp.json()["id"]
        r = c.get(f"/runs/{run_id}/steps")
        assert r.status_code == 200
        body = r.json()
        assert body["id"] == run_id
        assert body["scenario"] == "basic_recon"
        assert isinstance(body["steps"], list)
        assert len(body["steps"]) > 0
        for step in body["steps"]:
            assert "id" in step
            assert "attack_id" in step
            assert "status" in step
