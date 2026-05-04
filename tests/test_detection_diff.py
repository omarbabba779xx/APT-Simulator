from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from orchestrator.core.audit import AuditLog
from orchestrator.detection_diff import app


def _build_audit(p: Path, run_id: str = "r1") -> str:
    log = AuditLog(p)
    log.append("run.start", {"run_id": run_id, "scenario": "demo"})
    log.append("task.dispatch", {"run_id": run_id, "step_id": "s1", "attack_id": "T1033", "agent_id": "a1"})
    log.append("task.result", {"run_id": run_id, "step_id": "s1", "ok": True, "output_excerpt": ""})
    log.append("task.dispatch", {"run_id": run_id, "step_id": "s2", "attack_id": "T1083", "agent_id": "a1"})
    log.append("task.result", {"run_id": run_id, "step_id": "s2", "ok": True, "output_excerpt": ""})
    return run_id


def test_verify_run_covered(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    rid = _build_audit(audit)
    runner = CliRunner()
    result = runner.invoke(app, ["verify", rid, "--audit-path", str(audit)])
    assert result.exit_code == 0, result.stdout
    assert "COVERED" in result.stdout
    assert "Covered: 2/2" in result.stdout


def test_verify_unknown_run_fails(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    _build_audit(audit)
    runner = CliRunner()
    result = runner.invoke(app, ["verify", "not_a_run", "--audit-path", str(audit)])
    assert result.exit_code != 0


def test_report_emits_json(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    rid = _build_audit(audit, run_id="r2")
    runner = CliRunner()
    out = tmp_path / "report.json"
    result = runner.invoke(app, ["report", "--audit-path", str(audit), "--out", str(out)])
    assert result.exit_code == 0, result.stdout
    data = json.loads(out.read_text(encoding="utf-8"))
    assert rid in data
    assert all(s["verdict"] in {"COVERED", "GAP", "NO-EVENTS", "NO-RULE"} for s in data[rid])
