from __future__ import annotations

import json
from pathlib import Path

import ttps  # noqa: F401
from agent.runtime import execute
from orchestrator.core.safety_policy import SafetyPolicy
from ttps.base import registry
from ttps.catalog import catalog_summary


def test_catalog_packs_registered() -> None:
    summary = catalog_summary()
    assert summary["items"] >= 25
    for pack in ["windows", "linux", "cloud", "identity", "saas"]:
        assert summary["packs"][pack] >= 5


def test_catalog_ttp_runs_marker_only(tmp_path: Path) -> None:
    ttp = registry.get("T1059.001:WINDOWS_POWERSHELL_ENCODED")
    assert ttp is not None
    res = ttp.run({"marker_dir": str(tmp_path), "command": "Get-Service"})
    assert res.ok
    marker = Path(res.artifacts[0])
    data = json.loads(marker.read_text(encoding="utf-8"))
    assert data["_sim"] == "APT_SIM_CATALOG_TTP"
    assert data["attack_id"] == "T1059.001"
    assert data["pack"] == "windows"
    assert "Get-Service" in json.dumps(data)


def test_catalog_sigma_matches_synthetic() -> None:
    from orchestrator.detection import evaluate

    ttp = registry.get("T1530:AWS_S3_OBJECT_BURST")
    assert ttp is not None
    rule = ttp.sigma_rule()
    events = ttp.synthetic_events({}, None)
    assert rule is not None
    assert any(evaluate(rule, event) for event in events)


def test_safety_policy_blocks_live_mode_by_default() -> None:
    ttp = registry.get("T1059.001:WINDOWS_POWERSHELL_ENCODED")
    assert ttp is not None
    verdict = SafetyPolicy.from_env().validate(ttp, {"live_mode": True})
    assert not verdict.allowed


def test_runtime_applies_safety_policy() -> None:
    res = execute("T1059.001:WINDOWS_POWERSHELL_ENCODED", {"live_mode": True})
    assert not res.ok
    assert "safety policy blocked" in (res.error or "")
