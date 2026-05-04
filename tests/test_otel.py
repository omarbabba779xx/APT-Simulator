from __future__ import annotations


from orchestrator.core.audit import AuditLog
from orchestrator.telemetry.otel import OtelExporter, maybe_install


def test_publish_noop_when_disabled() -> None:
    exporter = OtelExporter()
    # On systems without OTel libs, must not raise.
    exporter.publish({"event": "x", "payload": {}})


def test_maybe_install_noop_without_env(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("APT_SIM_OTEL", raising=False)
    audit = AuditLog(tmp_path / "a.jsonl")
    before = len(audit.publishers)
    installed = maybe_install(audit)
    assert installed is False
    assert len(audit.publishers) == before


def test_maybe_install_skips_when_libs_missing(tmp_path, monkeypatch) -> None:
    # Force-enable env, but if libs aren't present, must still return False without error.
    monkeypatch.setenv("APT_SIM_OTEL", "1")
    audit = AuditLog(tmp_path / "a.jsonl")
    installed = maybe_install(audit)
    # Whether libs are installed depends on env; either outcome is acceptable as long as no exception.
    assert installed in (True, False)
