"""Lightweight structural checks for Docker + CI artifacts.

Confirms the files exist, parse, and reference the right entrypoints. We do
NOT actually build images or run docker — those happen in CI.
"""
from __future__ import annotations

from pathlib import Path

import yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_dockerfile_orchestrator_exists() -> None:
    p = PROJECT_ROOT / "Dockerfile.orchestrator"
    assert p.exists()
    body = p.read_text(encoding="utf-8")
    assert "FROM python" in body
    assert "orchestrator.main" in body
    assert "EXPOSE 8765" in body


def test_dockerfile_agent_excludes_server_deps() -> None:
    p = PROJECT_ROOT / "Dockerfile.agent"
    assert p.exists()
    body = p.read_text(encoding="utf-8")
    assert "agent.main" in body
    # Agent image must NOT install the FastAPI server stack — only pip install
    # lines count; comments are allowed to reference the excluded names.
    install_lines = [
        ln.strip()
        for ln in body.splitlines()
        if "pip install" in ln.lower() and not ln.lstrip().startswith("#")
    ]
    install_block = " ".join(install_lines).lower()
    for forbidden in ("fastapi", "uvicorn", "sqlmodel", "starlette"):
        assert forbidden not in install_block, f"Dockerfile.agent must not install {forbidden}"


def test_compose_references_both_services() -> None:
    p = PROJECT_ROOT / "docker-compose.yml"
    assert p.exists()
    cfg = yaml.safe_load(p.read_text(encoding="utf-8"))
    assert "services" in cfg
    assert {"orchestrator", "agent"} <= set(cfg["services"].keys())
    orch = cfg["services"]["orchestrator"]
    assert orch["build"]["dockerfile"] == "Dockerfile.orchestrator"
    agent = cfg["services"]["agent"]
    assert agent["build"]["dockerfile"] == "Dockerfile.agent"
    assert agent["depends_on"]["orchestrator"]["condition"] == "service_healthy"


def test_ci_workflow_runs_pytest() -> None:
    p = PROJECT_ROOT / ".github" / "workflows" / "ci.yml"
    assert p.exists()
    body = p.read_text(encoding="utf-8")
    cfg = yaml.safe_load(body)
    # GitHub-Actions YAML reuses 'on' as a key; PyYAML reads it as Python True.
    assert "jobs" in cfg
    assert "test" in cfg["jobs"]
    assert "smoke-e2e" in cfg["jobs"]
    # Ensure pytest and sigma export are part of the workflow.
    assert "pytest" in body
    assert "sigma_export" in body
    assert "verify-audit" in body


def test_dockerignore_strips_local_state() -> None:
    p = PROJECT_ROOT / ".dockerignore"
    assert p.exists()
    body = p.read_text(encoding="utf-8")
    for entry in [".venv/", "data/", "keys/", "tests/", "*.log"]:
        assert entry in body
