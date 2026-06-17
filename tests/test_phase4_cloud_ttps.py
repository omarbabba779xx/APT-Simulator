from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

import ttps  # noqa: F401
from orchestrator.detection import evaluate
from orchestrator.dsl.schema import Scenario
from ttps.base import registry


def _jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_t1078_004_registered() -> None:
    assert registry.get("T1078.004") is not None


def test_t1078_004_writes_cloudtrail_marker(tmp_path: Path) -> None:
    ttp = registry.get("T1078.004")
    assert ttp is not None
    res = ttp.run({"marker_dir": str(tmp_path), "event_names": ["GetCallerIdentity", "AssumeRole"]})
    assert res.ok
    marker = tmp_path / "t1078_004_cloud_account_abuse.jsonl"
    assert marker.exists()
    events = _jsonl(marker)
    assert [event["eventName"] for event in events] == ["GetCallerIdentity", "AssumeRole"]
    assert all(event["_sim"] == "APT_SIM_INITIAL_ACCESS_T1078_004" for event in events)
    assert res.extra["event_count"] == 2


def test_t1078_004_rejects_unknown_provider(tmp_path: Path) -> None:
    ttp = registry.get("T1078.004")
    assert ttp is not None
    res = ttp.run({"provider": "fictional", "marker_dir": str(tmp_path)})
    assert not res.ok
    assert "unsupported provider" in (res.error or "")


def test_t1078_004_cleanup(tmp_path: Path) -> None:
    ttp = registry.get("T1078.004")
    assert ttp is not None
    ttp.run({"marker_dir": str(tmp_path)})
    marker = tmp_path / "t1078_004_cloud_account_abuse.jsonl"
    assert marker.exists()
    res = ttp.cleanup({"marker_dir": str(tmp_path)})
    assert res.ok
    assert not marker.exists()


def test_t1078_004_sigma_matches_synthetic() -> None:
    ttp = registry.get("T1078.004")
    assert ttp is not None
    rule = ttp.sigma_rule()
    events = ttp.synthetic_events({}, None)
    assert any(evaluate(rule, event) for event in events)


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp"])
def test_t1530_writes_provider_markers(tmp_path: Path, provider: str) -> None:
    ttp = registry.get("T1530")
    assert ttp is not None
    res = ttp.run({"provider": provider, "marker_dir": str(tmp_path), "object_count": 2})
    assert res.ok
    marker = tmp_path / "t1530_cloud_storage_access.jsonl"
    assert marker.exists()
    events = _jsonl(marker)
    assert events
    assert all(event["_sim"] == "APT_SIM_COLLECTION_T1530" for event in events)
    assert res.extra["provider"] == provider
    assert res.extra["object_count"] == 2


def test_t1530_caps_object_count(tmp_path: Path) -> None:
    ttp = registry.get("T1530")
    assert ttp is not None
    res = ttp.run({"marker_dir": str(tmp_path), "object_count": 999})
    assert res.ok
    assert res.extra["object_count"] == 100


def test_t1530_rejects_unknown_provider(tmp_path: Path) -> None:
    ttp = registry.get("T1530")
    assert ttp is not None
    res = ttp.run({"provider": "fictional", "marker_dir": str(tmp_path)})
    assert not res.ok
    assert "unsupported provider" in (res.error or "")


def test_t1530_cleanup(tmp_path: Path) -> None:
    ttp = registry.get("T1530")
    assert ttp is not None
    ttp.run({"marker_dir": str(tmp_path)})
    marker = tmp_path / "t1530_cloud_storage_access.jsonl"
    assert marker.exists()
    res = ttp.cleanup({"marker_dir": str(tmp_path)})
    assert res.ok
    assert not marker.exists()


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp"])
def test_t1530_sigma_matches_synthetic(provider: str) -> None:
    ttp = registry.get("T1530")
    assert ttp is not None
    rule = ttp.sigma_rule()
    events = ttp.synthetic_events({"provider": provider}, None)
    assert any(evaluate(rule, event) for event in events)


def test_cloud_account_storage_scenario_validates() -> None:
    scenario_path = Path(__file__).parent.parent / "scenarios" / "cloud_account_storage_sim.yaml"
    scenario = Scenario(**yaml.safe_load(scenario_path.read_text(encoding="utf-8")))
    scenario.validate_dag()
    assert [step.ttp for step in scenario.steps] == ["T1078.004", "T1530", "T1048"]
