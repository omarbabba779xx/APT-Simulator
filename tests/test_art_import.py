from __future__ import annotations

from pathlib import Path

import yaml
from typer.testing import CliRunner

from orchestrator.art_import import app


ART_FIXTURE = """\
attack_technique: T1033
display_name: System Owner/User Discovery
atomic_tests:
  - name: System Owner/User Discovery (whoami)
    auto_generated_guid: 0000-aaaa
    description: example
    supported_platforms:
      - windows
      - linux
    executor:
      name: sh
      command: whoami
"""

ART_UNMATCHED = """\
attack_technique: T9999
display_name: Imaginary Technique
atomic_tests:
  - name: nope
    auto_generated_guid: 0000-bbbb
    description: example
    supported_platforms: [windows]
    executor:
      name: sh
      command: 'echo nope'
"""


def _write_fixtures(root: Path) -> None:
    (root / "T1033").mkdir()
    (root / "T1033" / "T1033.yaml").write_text(ART_FIXTURE, encoding="utf-8")
    (root / "T9999").mkdir()
    (root / "T9999" / "T9999.yaml").write_text(ART_UNMATCHED, encoding="utf-8")


def test_scan_reports_match(tmp_path: Path) -> None:
    _write_fixtures(tmp_path)
    runner = CliRunner()
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "T1033" in result.stdout
    assert "matched 1" in result.stdout
    assert "unmatched: 1" in result.stdout


def test_convert_emits_scenario(tmp_path: Path) -> None:
    _write_fixtures(tmp_path)
    runner = CliRunner()
    out_file = tmp_path / "out.yaml"
    result = runner.invoke(app, ["convert", str(tmp_path), "--out", str(out_file), "--name", "art_test_walk"])
    assert result.exit_code == 0
    scenario = yaml.safe_load(out_file.read_text(encoding="utf-8"))
    assert scenario["name"] == "art_test_walk"
    step_attacks = {s["ttp"] for s in scenario["steps"]}
    assert "T1033" in step_attacks
    assert "T9999" not in step_attacks
