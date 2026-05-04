from __future__ import annotations

import platform
from pathlib import Path

import ttps  # noqa: F401
from ttps.base import registry


def test_t1057_process_discovery() -> None:
    ttp = registry.get("T1057")
    assert ttp is not None
    res = ttp.run({})
    assert res.ok
    assert "process rows" in res.output


def test_t1003_target_enum_safe() -> None:
    ttp = registry.get("T1003")
    assert ttp is not None
    res = ttp.run({})
    assert res.ok
    # Always succeeds — even when no targets are running, output is informative.
    assert "credential-store target" in res.output


def test_t1027_obfuscation_writes_marker(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("APT_SIM_MARKER_DIR", str(tmp_path))
    # Reload module so SIM_MARKER_DIR picks up the env var.
    import importlib

    from ttps.defense_evasion import t1027_obfuscation

    importlib.reload(t1027_obfuscation)
    ttp = t1027_obfuscation.T1027Obfuscation()
    res = ttp.run({"size_bytes": 256})
    assert res.ok
    assert res.artifacts
    artifact = Path(res.artifacts[0])
    assert artifact.exists()
    cleanup_res = ttp.cleanup({})
    assert cleanup_res.ok
    assert not artifact.exists()


def test_t1070_refuses_outside_marker_dir() -> None:
    ttp = registry.get("T1070.004")
    assert ttp is not None
    res = ttp.run({"path": "/etc/hosts" if platform.system() != "Windows" else "C:/Windows/System32/cmd.exe"})
    assert not res.ok
    assert "outside marker dir" in (res.error or "")


def test_t1071_rejects_public_target() -> None:
    ttp = registry.get("T1071.001")
    assert ttp is not None
    res = ttp.run({"url": "http://8.8.8.8/", "beacons": 1, "interval_seconds": 0, "jitter_seconds": 0})
    assert not res.ok
    assert "lab CIDR allowlist" in (res.error or "")


def test_t1071_accepts_loopback() -> None:
    ttp = registry.get("T1071.001")
    assert ttp is not None
    # No server expected; we just verify it gets past the gate to the request stage.
    res = ttp.run({"url": "http://127.0.0.1:1/", "beacons": 1, "interval_seconds": 0, "jitter_seconds": 0, "request_timeout": 0.5})
    # ok=False expected (port 1 closed) but error is connection-related, NOT lab gating.
    assert "lab CIDR allowlist" not in (res.error or "")
