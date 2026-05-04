from __future__ import annotations

from pathlib import Path

from orchestrator.core.audit import AuditLog


def test_chain_valid(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "a.jsonl")
    log.append("e1", {"k": 1})
    log.append("e2", {"k": 2})
    log.append("e3", {"k": 3})
    ok, broken = log.verify()
    assert ok
    assert broken is None


def test_tamper_detected(tmp_path: Path) -> None:
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    log.append("e1", {"k": 1})
    log.append("e2", {"k": 2})
    lines = p.read_text().splitlines()
    # Tamper with the second line's payload.
    lines[1] = lines[1].replace('"k":2', '"k":99')
    p.write_text("\n".join(lines) + "\n")
    log2 = AuditLog(p)
    ok, broken = log2.verify()
    assert not ok
    assert broken == 2
