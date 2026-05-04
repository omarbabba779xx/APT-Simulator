from __future__ import annotations

import platform

import ttps  # noqa: F401
from ttps.base import registry


def test_t1098_registered() -> None:
    assert registry.get("T1098.004") is not None


def test_t1543_registered() -> None:
    assert registry.get("T1543.002") is not None


def test_t1098_refuses_on_windows() -> None:
    if platform.system().lower() == "windows":
        ttp = registry.get("T1098.004")
        res = ttp.run({})
        assert not res.ok
        assert "linux/darwin only" in (res.error or "")


def test_t1543_refuses_on_windows() -> None:
    if platform.system().lower() == "windows":
        ttp = registry.get("T1543.002")
        res = ttp.run({})
        assert not res.ok
        assert "linux-only" in (res.error or "")


def test_t1098_isolated_filename() -> None:
    """Module must use a sandboxed filename, never the real authorized_keys."""
    from ttps.persistence import t1098_004_ssh_authorized_keys as mod
    assert mod.SAFE_FILENAME == "apt_sim_test_authorized_keys"
    assert mod.SAFE_FILENAME != "authorized_keys"


def test_t1543_unit_body_is_noop() -> None:
    """The systemd unit's ExecStart must be a no-op."""
    from ttps.persistence import t1543_002_systemd_service as mod
    assert "ExecStart=/bin/true" in mod.UNIT_BODY
    assert "Type=oneshot" in mod.UNIT_BODY
