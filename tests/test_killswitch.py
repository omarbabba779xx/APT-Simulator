from __future__ import annotations

from pathlib import Path

from orchestrator.core.killswitch import KillSwitch


def test_flag_file_triggers(tmp_path: Path) -> None:
    ks = KillSwitch(tmp_path / "STOP")
    assert not ks.is_active()
    ks.engage("test")
    assert ks.is_active()
    ks.disengage()
    assert not ks.is_active()


def test_env_var_triggers(tmp_path: Path, monkeypatch) -> None:
    ks = KillSwitch(tmp_path / "STOP")
    monkeypatch.setenv("APT_SIM_STOP", "1")
    assert ks.is_active()
    monkeypatch.delenv("APT_SIM_STOP")
    assert not ks.is_active()
