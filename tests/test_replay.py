from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from orchestrator.core.audit import AuditLog
from orchestrator.replay import app


def _build_audit(p: Path) -> str:
    log = AuditLog(p)
    log.append("run.start", {"run_id": "r1", "scenario": "demo"})
    log.append("task.dispatch", {"run_id": "r1", "step_id": "s1", "attack_id": "T1033", "agent_id": "a1"})
    log.append("task.result", {"run_id": "r1", "step_id": "s1", "ok": True, "output_excerpt": "user=alice"})
    log.append("task.dispatch", {"run_id": "r1", "step_id": "s2", "attack_id": "T1083", "agent_id": "a1"})
    log.append("task.result", {"run_id": "r1", "step_id": "s2", "ok": False, "output_excerpt": "", "error": "boom"})
    return "r1"


def test_show_run_renders_timeline(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    run_id = _build_audit(audit_path)
    runner = CliRunner()
    result = runner.invoke(app, ["show", run_id, "--audit-path", str(audit_path)])
    assert result.exit_code == 0, result.stdout
    assert "audit chain valid" in result.stdout
    assert "RUN START" in result.stdout
    assert "DISPATCH" in result.stdout
    assert "FAIL" in result.stdout
    assert "boom" in result.stdout


def test_list_runs_enumerates(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    _build_audit(audit_path)
    runner = CliRunner()
    result = runner.invoke(app, ["list-runs", "--audit-path", str(audit_path)])
    assert result.exit_code == 0
    assert "r1" in result.stdout
    assert "demo" in result.stdout


def test_show_aborts_on_broken_chain(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    _build_audit(audit_path)
    # Tamper with line 2.
    lines = audit_path.read_text().splitlines()
    lines[1] = lines[1].replace('"step_id":"s1"', '"step_id":"sX"')
    audit_path.write_text("\n".join(lines) + "\n")
    runner = CliRunner()
    result = runner.invoke(app, ["show", "r1", "--audit-path", str(audit_path)])
    assert result.exit_code == 2
    assert "BROKEN" in result.stdout or "BROKEN" in (result.stderr or "")
