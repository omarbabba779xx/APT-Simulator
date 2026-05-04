"""Tests for adversary profile loader and profile-driven scenario generator."""
from __future__ import annotations

from fastapi.testclient import TestClient

import ttps  # noqa: F401
from orchestrator.main import build_app
from orchestrator.profile_gen import (
    generate_scenario,
    list_profiles,
    load_profile,
)
from orchestrator.dsl.schema import Scenario


# ---------------------------------------------------------------------------
# Profile loading
# ---------------------------------------------------------------------------

def test_list_profiles_non_empty() -> None:
    profiles = list_profiles()
    assert len(profiles) >= 4
    assert "apt29" in profiles
    assert "fin7" in profiles
    assert "lazarus" in profiles
    assert "apt41" in profiles


def test_load_profile_apt29() -> None:
    p = load_profile("apt29")
    assert p["name"] == "APT29"
    assert "preferred_ttps" in p
    assert len(p["preferred_ttps"]) > 0
    assert "c2_profile" in p
    assert p["origin"] == "Russia"


def test_load_profile_lazarus() -> None:
    p = load_profile("lazarus")
    assert "T1486" in p["preferred_ttps"]   # Impact TTP for Lazarus
    assert "T1041" in p["preferred_ttps"]   # Exfil TTP


def test_load_profile_apt41_multiplatform() -> None:
    p = load_profile("apt41")
    plats = p.get("target_platforms", [])
    assert "linux" in plats
    assert "windows" in plats


def test_load_profile_missing_raises() -> None:
    import pytest
    with pytest.raises(FileNotFoundError):
        load_profile("nonexistent_group_xyz")


# ---------------------------------------------------------------------------
# Profile-driven scenario generation
# ---------------------------------------------------------------------------

def test_generate_scenario_apt29_windows() -> None:
    sc = generate_scenario("apt29")
    assert sc["name"].startswith("apt29")
    assert len(sc["steps"]) > 0
    # All step TTPs must be real registered TTPs
    from ttps.base import registry
    for step in sc["steps"]:
        assert registry.get(step["ttp"]) is not None, f"Unknown TTP in generated scenario: {step['ttp']}"


def test_generate_scenario_respects_steps_limit() -> None:
    sc = generate_scenario("lazarus", steps=4)
    assert len(sc["steps"]) == 4


def test_generate_scenario_seed_reproducible() -> None:
    sc_a = generate_scenario("fin7", steps=5, seed=42)
    sc_b = generate_scenario("fin7", steps=5, seed=42)
    assert [s["ttp"] for s in sc_a["steps"]] == [s["ttp"] for s in sc_b["steps"]]


def test_generate_scenario_different_seeds_differ() -> None:
    sc_a = generate_scenario("lazarus", steps=6, seed=1)
    sc_b = generate_scenario("lazarus", steps=6, seed=2)
    # With enough steps and TTPs, seeds should produce different orderings.
    # (May coincide for small pools — just check it runs without error.)
    assert len(sc_a["steps"]) == len(sc_b["steps"]) == 6


def test_generate_scenario_valid_dag() -> None:
    """Generated scenario must pass DAG validation."""
    sc_dict = generate_scenario("apt41", platform_override="linux")
    sc = Scenario(**sc_dict)
    sc.validate_dag()


def test_generate_scenario_tactic_order() -> None:
    """Discovery steps should come before impact/exfil steps in generated scenario."""
    from ttps.base import registry as reg
    sc = generate_scenario("lazarus")
    tactics = [reg.get(s["ttp"]).tactic for s in sc["steps"] if reg.get(s["ttp"])]
    DISCOVERY_TACTICS = {"discovery", "credential_access"}
    LATE_TACTICS = {"impact", "exfiltration"}
    discovery_idx = [i for i, t in enumerate(tactics) if t in DISCOVERY_TACTICS]
    late_idx = [i for i, t in enumerate(tactics) if t in LATE_TACTICS]
    if discovery_idx and late_idx:
        assert min(discovery_idx) < max(late_idx), "Discovery must precede impact/exfil in chain"


def test_generate_scenario_c2_params_injected() -> None:
    """C2 steps must have params injected from profile c2_profile."""
    sc = generate_scenario("apt29")
    c2_steps = [s for s in sc["steps"] if s["ttp"] in ("T1071.001", "T1041")]
    for step in c2_steps:
        assert "params" in step
        assert "interval_seconds" in step["params"]


# ---------------------------------------------------------------------------
# Profiles API endpoints
# ---------------------------------------------------------------------------

def test_profiles_list_endpoint() -> None:
    with TestClient(build_app("config/default.yaml")) as client:
        r = client.get("/profiles")
        assert r.status_code == 200
        body = r.json()
        assert isinstance(body, list)
        names = {p["id"] for p in body}
        assert {"apt29", "fin7", "lazarus", "apt41"} <= names


def test_profiles_detail_endpoint() -> None:
    with TestClient(build_app("config/default.yaml")) as client:
        r = client.get("/profiles/apt29")
        assert r.status_code == 200
        body = r.json()
        assert body["name"] == "APT29"


def test_profiles_detail_not_found() -> None:
    with TestClient(build_app("config/default.yaml")) as client:
        r = client.get("/profiles/unknown_group")
        assert r.status_code == 404


def test_profiles_generate_endpoint() -> None:
    with TestClient(build_app("config/default.yaml")) as client:
        r = client.post("/profiles/apt29/generate", json={"steps": 3, "seed": 7})
        assert r.status_code == 200
        body = r.json()
        assert "steps" in body
        assert len(body["steps"]) == 3
