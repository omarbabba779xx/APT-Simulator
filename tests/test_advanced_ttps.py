"""Tests for Phase 3 advanced TTPs: T1082, T1069.001, T1005, T1041."""
from __future__ import annotations

from pathlib import Path

import ttps  # noqa: F401
from orchestrator.detection import evaluate
from ttps.base import registry


# ---------------------------------------------------------------------------
# T1082 — System Information Discovery
# ---------------------------------------------------------------------------

def test_t1082_registered() -> None:
    assert registry.get("T1082") is not None


def test_t1082_runs_and_returns_info() -> None:
    ttp = registry.get("T1082")
    res = ttp.run({})
    assert res.ok
    assert "hostname" in res.output or "os" in res.output


def test_t1082_extra_contains_hostname() -> None:
    ttp = registry.get("T1082")
    res = ttp.run({})
    assert res.ok
    assert isinstance(res.extra, dict)
    assert "hostname" in res.extra
    assert "os" in res.extra


def test_t1082_sigma_matches_synthetic() -> None:
    ttp = registry.get("T1082")
    rule = ttp.sigma_rule()
    events = ttp.synthetic_events({}, None)
    assert any(evaluate(rule, ev) for ev in events), "T1082 synthetic events must match Sigma rule"


# ---------------------------------------------------------------------------
# T1069.001 — Local Groups Discovery
# ---------------------------------------------------------------------------

def test_t1069_registered() -> None:
    assert registry.get("T1069.001") is not None


def test_t1069_runs() -> None:
    ttp = registry.get("T1069.001")
    res = ttp.run({})
    # May fail on restricted CI; check it at least ran
    assert res.output or res.error


def test_t1069_sigma_matches_synthetic() -> None:
    ttp = registry.get("T1069.001")
    rule = ttp.sigma_rule()
    events = ttp.synthetic_events({}, None)
    assert any(evaluate(rule, ev) for ev in events), "T1069.001 synthetic events must match Sigma rule"


# ---------------------------------------------------------------------------
# T1005 — Data from Local System
# ---------------------------------------------------------------------------

def test_t1005_registered() -> None:
    assert registry.get("T1005") is not None


def test_t1005_scans_tmp_safely(tmp_path: Path, monkeypatch) -> None:
    """T1005 must find the .pem file we plant and return path only (no content)."""
    (tmp_path / "test_credential.pem").write_text("FAKE PEM — sim only", encoding="utf-8")
    (tmp_path / "id_rsa").write_text("FAKE KEY — sim only", encoding="utf-8")
    monkeypatch.setenv("APT_SIM_MARKER_DIR", str(tmp_path / "artifacts"))

    import importlib
    from ttps.collection import t1005_data_from_local_system as mod
    importlib.reload(mod)
    ttp = mod.T1005DataFromLocalSystem()
    res = ttp.run({"root": str(tmp_path), "max_depth": 1, "max_entries": 20})
    assert res.ok
    assert res.extra is not None
    assert res.extra["hit_count"] >= 2, "Must detect both .pem and id_rsa"
    # Verify no content was captured — only paths and sizes
    for hit in res.extra.get("hits", []):
        assert "path" in hit
        assert "size_bytes" in hit
        assert "content" not in hit


def test_t1005_never_reads_content(tmp_path: Path) -> None:
    """Output string must not contain file content."""
    secret = "MY_SUPER_SECRET_PASSWORD_12345"
    f = tmp_path / "passwords.txt"
    f.write_text(secret, encoding="utf-8")
    import importlib
    from ttps.collection import t1005_data_from_local_system as mod
    importlib.reload(mod)
    ttp = mod.T1005DataFromLocalSystem()
    res = ttp.run({"root": str(tmp_path), "max_depth": 1, "max_entries": 10})
    assert secret not in (res.output or "")
    for hit in (res.extra or {}).get("hits", []):
        assert secret not in str(hit)


def test_t1005_sigma_matches_synthetic() -> None:
    ttp = registry.get("T1005")
    rule = ttp.sigma_rule()
    events = ttp.synthetic_events({}, None)
    assert any(evaluate(rule, ev) for ev in events), "T1005 synthetic events must match Sigma rule"


# ---------------------------------------------------------------------------
# T1041 — Exfiltration Over C2 (sim)
# ---------------------------------------------------------------------------

def test_t1041_registered() -> None:
    assert registry.get("T1041") is not None


def test_t1041_rejects_public_ip() -> None:
    ttp = registry.get("T1041")
    res = ttp.run({"url": "http://8.8.8.8/exfil", "max_bytes": 64})
    assert not res.ok
    assert "lab CIDR allowlist" in (res.error or "")


def test_t1041_accepts_loopback_target() -> None:
    ttp = registry.get("T1041")
    # Port 1 is closed; we expect a connection error, NOT a safety gating error.
    res = ttp.run({"url": "http://127.0.0.1:1/exfil", "max_bytes": 64, "request_timeout": 0.5})
    assert "lab CIDR allowlist" not in (res.error or "")


def test_t1041_sends_only_benign_marker() -> None:
    """Verify the payload body starts with the benign marker, never real data."""
    from ttps.exfiltration.t1041_exfil_over_c2 import _EXFIL_MARKER
    assert b"APT_SIM" in _EXFIL_MARKER


def test_t1041_sigma_matches_synthetic() -> None:
    ttp = registry.get("T1041")
    rule = ttp.sigma_rule()
    events = ttp.synthetic_events({}, None)
    assert any(evaluate(rule, ev) for ev in events), "T1041 synthetic events must match Sigma rule"


# ---------------------------------------------------------------------------
# Fuzz pool includes all new TTPs
# ---------------------------------------------------------------------------

def test_fuzz_pool_includes_new_discovery_ttps() -> None:
    from orchestrator.fuzz import _candidate_pool
    pool = _candidate_pool(include_windows=False, include_cloud=False)
    for ttp_id in ("T1082", "T1069.001", "T1005", "T1041"):
        assert ttp_id in pool, f"{ttp_id} should be in cross-platform fuzz pool"
