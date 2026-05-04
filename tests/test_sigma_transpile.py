from __future__ import annotations

from pathlib import Path

import yaml
from typer.testing import CliRunner

from orchestrator.sigma_transpile import _try_import_backends, app


def test_transpile_clean_error_when_libs_missing(tmp_path: Path) -> None:
    SigmaCollection, splunk, lucene, err = _try_import_backends()
    if err is None:
        # Libs are installed; run real transpile and verify outputs exist for at least one rule.
        sigma_dir = tmp_path / "sigma"
        sigma_dir.mkdir()
        rule = {
            "title": "Test rule",
            "id": "11111111-1111-1111-1111-111111111111",
            "status": "experimental",
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {"selection": {"Image|endswith": ["\\whoami.exe"]}, "condition": "selection"},
            "level": "low",
        }
        (sigma_dir / "test.yml").write_text(yaml.safe_dump(rule), encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(app, ["transpile", "--sigma-dir", str(sigma_dir), "--out-dir", str(tmp_path / "out")])
        assert result.exit_code == 0, result.stdout
        assert (tmp_path / "out" / "splunk").exists()
    else:
        # Libs missing — CLI must exit non-zero with helpful error.
        runner = CliRunner()
        result = runner.invoke(app, ["transpile", "--sigma-dir", "detection/sigma", "--out-dir", str(tmp_path)])
        assert result.exit_code != 0
        # message routed to stderr but mixed with stdout in CliRunner; check both.
        combined = (result.stdout or "") + (result.stderr or "")
        assert "transpile backends missing" in combined or "Install with" in combined
