from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from orchestrator.coverage_report import app


def test_coverage_report_renders(tmp_path: Path) -> None:
    runner = CliRunner()
    out = tmp_path / "report.html"
    result = runner.invoke(app, ["generate", "--out", str(out), "--db-path", str(tmp_path / "missing.db")])
    assert result.exit_code == 0, result.stdout
    assert out.exists()
    body = out.read_text(encoding="utf-8")
    assert "APT Simulator" in body
    assert "T1033" in body
    assert "T1071.001" in body
