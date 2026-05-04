"""Tests for Phase 2 TTPs: T1016, T1049, T1053.005, T1105, T1486."""
from __future__ import annotations

import platform
from pathlib import Path

import ttps  # noqa: F401
from ttps.base import registry


# ---------------------------------------------------------------------------
# T1016 — Network Config Discovery
# ---------------------------------------------------------------------------

def test_t1016_registered() -> None:
    assert registry.get("T1016") is not None


def test_t1016_runs_successfully() -> None:
    ttp = registry.get("T1016")
    res = ttp.run({})
    # Should succeed on all platforms; if binary missing it returns ok=False with an error.
    assert res.output or res.error


def test_t1016_sigma_matches_synthetic() -> None:
    from orchestrator.detection import evaluate
    ttp = registry.get("T1016")
    rule = ttp.sigma_rule()
    events = ttp.synthetic_events({}, None)
    assert any(evaluate(rule, ev) for ev in events), "T1016 synthetic events must match Sigma rule"


# ---------------------------------------------------------------------------
# T1049 — Network Connections Discovery
# ---------------------------------------------------------------------------

def test_t1049_registered() -> None:
    assert registry.get("T1049") is not None


def test_t1049_runs_successfully() -> None:
    ttp = registry.get("T1049")
    res = ttp.run({})
    assert res.output or res.error


def test_t1049_sigma_matches_synthetic() -> None:
    from orchestrator.detection import evaluate
    ttp = registry.get("T1049")
    rule = ttp.sigma_rule()
    events = ttp.synthetic_events({}, None)
    assert any(evaluate(rule, ev) for ev in events), "T1049 synthetic events must match Sigma rule"


# ---------------------------------------------------------------------------
# T1053.005 — Scheduled Task (Windows-only)
# ---------------------------------------------------------------------------

def test_t1053_registered() -> None:
    assert registry.get("T1053.005") is not None


def test_t1053_refuses_on_non_windows() -> None:
    if platform.system().lower() != "windows":
        ttp = registry.get("T1053.005")
        res = ttp.run({})
        assert not res.ok
        assert "windows-only" in (res.error or "")


def test_t1053_sigma_matches_synthetic() -> None:
    from orchestrator.detection import evaluate
    ttp = registry.get("T1053.005")
    rule = ttp.sigma_rule()
    events = ttp.synthetic_events({}, None)
    assert any(evaluate(rule, ev) for ev in events), "T1053.005 synthetic events must match Sigma rule"


# ---------------------------------------------------------------------------
# T1105 — Ingress Tool Transfer
# ---------------------------------------------------------------------------

def test_t1105_registered() -> None:
    assert registry.get("T1105") is not None


def test_t1105_drops_marker(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("APT_SIM_MARKER_DIR", str(tmp_path))
    import importlib
    from ttps.command_and_control import t1105_ingress_tool_transfer as mod
    importlib.reload(mod)
    ttp = mod.T1105IngressToolTransfer()
    res = ttp.run({"extension": ".exe", "seed": 42})
    assert res.ok
    assert res.artifacts
    dest = Path(res.artifacts[0])
    assert dest.exists()
    assert dest.suffix == ".exe"
    cleanup = ttp.cleanup({})
    assert cleanup.ok
    assert not dest.exists()


def test_t1105_sigma_matches_synthetic() -> None:
    from orchestrator.detection import evaluate
    ttp = registry.get("T1105")
    rule = ttp.sigma_rule()
    events = ttp.synthetic_events({}, None)
    assert any(evaluate(rule, ev) for ev in events), "T1105 synthetic events must match Sigma rule"


# ---------------------------------------------------------------------------
# T1486 — Data Encrypted for Impact (sim)
# ---------------------------------------------------------------------------

def test_t1486_registered() -> None:
    assert registry.get("T1486") is not None


def test_t1486_writes_encrypted_markers(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("APT_SIM_MARKER_DIR", str(tmp_path))
    import importlib
    from ttps.impact import t1486_data_encrypted_sim as mod
    importlib.reload(mod)
    ttp = mod.T1486DataEncryptedSim()
    res = ttp.run({"file_count": 3})
    assert res.ok
    assert len(res.artifacts) == 3
    for p in res.artifacts:
        assert Path(p).exists()
        assert p.endswith(".encrypted")
    cleanup = ttp.cleanup({})
    assert cleanup.ok
    for p in res.artifacts:
        assert not Path(p).exists()


def test_t1486_clamps_file_count(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("APT_SIM_MARKER_DIR", str(tmp_path))
    import importlib
    from ttps.impact import t1486_data_encrypted_sim as mod
    importlib.reload(mod)
    ttp = mod.T1486DataEncryptedSim()
    res = ttp.run({"file_count": 999})
    assert res.ok
    assert len(res.artifacts) <= 50


def test_t1486_sigma_matches_synthetic() -> None:
    from orchestrator.detection import evaluate
    ttp = registry.get("T1486")
    rule = ttp.sigma_rule()
    events = ttp.synthetic_events({}, None)
    assert any(evaluate(rule, ev) for ev in events), "T1486 synthetic events must match Sigma rule"


# ---------------------------------------------------------------------------
# Fuzz pool includes new cross-platform TTPs
# ---------------------------------------------------------------------------

def test_fuzz_pool_includes_new_ttps() -> None:
    from orchestrator.fuzz import _candidate_pool
    pool = _candidate_pool(include_windows=False, include_cloud=False)
    assert "T1016" in pool
    assert "T1049" in pool
    assert "T1105" in pool
    assert "T1486" in pool
    assert "T1053.005" not in pool  # Windows-only, excluded


def test_fuzz_pool_includes_t1053_when_windows_flagged() -> None:
    from orchestrator.fuzz import _candidate_pool
    pool = _candidate_pool(include_windows=True, include_cloud=False)
    assert "T1053.005" in pool


# ---------------------------------------------------------------------------
# New scenarios parse and validate
# ---------------------------------------------------------------------------

def test_lazarus_scenario_validates() -> None:
    import yaml
    from orchestrator.dsl.schema import Scenario
    p = Path(__file__).parent.parent / "scenarios" / "lazarus_style_full_chain.yaml"
    sc = Scenario(**yaml.safe_load(p.read_text(encoding="utf-8")))
    sc.validate_dag()
    assert len(sc.steps) > 0
    assert sc.actor is not None


def test_cross_platform_scenario_validates() -> None:
    import yaml
    from orchestrator.dsl.schema import Scenario
    p = Path(__file__).parent.parent / "scenarios" / "cross_platform_full_chain.yaml"
    sc = Scenario(**yaml.safe_load(p.read_text(encoding="utf-8")))
    sc.validate_dag()
    assert "linux" in sc.target_platforms or "any" in sc.target_platforms
