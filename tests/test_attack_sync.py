from __future__ import annotations

from orchestrator.attack_sync import drift_status, load_snapshot, official_tactic_for


def test_attack_snapshot_is_current_enterprise_shape() -> None:
    snapshot = load_snapshot()
    assert snapshot["tactic_count"] == 15
    assert snapshot["active_count"] == 696
    assert "stealth" in snapshot["tactics"]
    assert "defense_impairment" in snapshot["tactics"]


def test_registry_is_synced_to_snapshot() -> None:
    status = drift_status()
    assert status["coverage_label"] == "15/15"
    assert status["status"] == "synced"
    assert status["missing_count"] == 0
    assert status["extra_count"] == 0
    assert status["deprecated_present_count"] == 0
    assert status["revoked_present_count"] == 0


def test_official_tactic_mapping_uses_snapshot() -> None:
    assert official_tactic_for("T1070.004", "defense_evasion") == "stealth"
    assert official_tactic_for("T1666", "discovery") == "defense_impairment"
