"""Tests for /metrics and /coverage/navigator endpoints."""
from __future__ import annotations

from fastapi.testclient import TestClient

from orchestrator.main import build_app


def _client() -> TestClient:
    return TestClient(build_app("config/default.yaml"))


def test_metrics_endpoint_structure() -> None:
    with _client() as c:
        r = c.get("/metrics")
        assert r.status_code == 200
        body = r.json()
        assert "runs" in body
        assert "agents" in body
        assert "ttp_stats" in body
        assert isinstance(body["runs"]["total"], int)
        assert isinstance(body["agents"]["total"], int)


def test_metrics_tracks_run() -> None:
    with _client() as c:
        c.post("/scenarios/run", json={"name": "basic_recon"})
        r = c.get("/metrics")
        body = r.json()
        assert body["runs"]["total"] >= 1


def test_metrics_killswitch_field() -> None:
    with _client() as c:
        r = c.get("/metrics")
        assert "killswitch_active" in r.json()


def test_agent_run_local_dry_run() -> None:
    """Smoke-test the run-local --dry-run command."""
    from typer.testing import CliRunner
    from agent.main import cli
    runner = CliRunner()
    result = runner.invoke(cli, [
        "run-local",
        "scenarios/basic_recon.yaml",
        "--dry-run",
        "--skip-safety",
    ])
    assert result.exit_code == 0, result.output
    assert "basic_recon" in result.output or "step" in result.output.lower()
