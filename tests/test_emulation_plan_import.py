from __future__ import annotations

from pathlib import Path

import yaml

from orchestrator.emulation_plan_import import build_scenarios, scan_plans


def test_emulation_plan_scan_resolves_safe_local_ttps(tmp_path: Path) -> None:
    actor_dir = tmp_path / "Enterprise" / "aptx" / "Emulation_Plan" / "yaml"
    actor_dir.mkdir(parents=True)
    plan = [
        {"emulation_plan_details": {"adversary_name": "APTX"}},
        {"procedure_step": "1", "technique": {"attack_id": "T1033"}, "executors": [{"command": "ignored"}]},
        {"procedure_step": "2", "technique": {"attack_id": "T9999"}},
    ]
    (actor_dir / "plan.yaml").write_text(yaml.safe_dump(plan, sort_keys=False), encoding="utf-8")

    plans = scan_plans(tmp_path / "Enterprise")
    assert len(plans) == 1
    assert plans[0]["actor_slug"] == "aptx"
    assert plans[0]["matched"] == 1
    assert plans[0]["unmatched"] == 1


def test_emulation_plan_builds_metadata_only_scenario(tmp_path: Path) -> None:
    actor_dir = tmp_path / "Enterprise" / "aptx" / "Emulation_Plan"
    actor_dir.mkdir(parents=True)
    (actor_dir / "plan.yaml").write_text(
        yaml.safe_dump(
            [
                {"emulation_plan_details": {"adversary_name": "APTX"}},
                {"procedure_step": "1", "technique": {"attack_id": "T1033"}, "executors": [{"command": "ignored"}]},
            ],
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    scenarios = build_scenarios(tmp_path / "Enterprise")
    assert len(scenarios) == 1
    step = scenarios[0]["steps"][0]
    assert step["ttp"] == "T1033"
    assert step["params"]["dry_run"] is True
    assert step["params"]["source_attack_id"] == "T1033"
    assert "command" not in yaml.safe_dump(scenarios[0]).lower()
