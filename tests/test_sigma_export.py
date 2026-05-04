from __future__ import annotations

import json
from pathlib import Path

import yaml
from typer.testing import CliRunner

from orchestrator.sigma_export import app


def test_sigma_export_writes_rules(tmp_path: Path) -> None:
    runner = CliRunner()
    out_dir = tmp_path / "sigma"
    result = runner.invoke(app, ["export", "--out-dir", str(out_dir)])
    assert result.exit_code == 0, result.stdout

    files = sorted(out_dir.glob("*.yml"))
    assert len(files) >= 10  # at least our 10 TTPs

    # Every YAML is parseable and has required Sigma fields.
    for f in files:
        rule = yaml.safe_load(f.read_text(encoding="utf-8"))
        assert rule.get("title")
        assert rule.get("detection")
        assert rule.get("tags")
        assert any(t.startswith("attack.") for t in rule["tags"])

    coverage_path = out_dir / "coverage.json"
    assert coverage_path.exists()
    coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
    exported_ids = {k for k, v in coverage.items() if v.get("status") == "exported"}
    # All registered TTPs in Phase 2 should have rules.
    for tid in ["T1033", "T1083", "T1059", "T1547.001", "T1057", "T1071.001", "T1003", "T1027", "T1112", "T1070.004"]:
        assert tid in exported_ids
