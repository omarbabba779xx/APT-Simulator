from __future__ import annotations

import ttps  # noqa: F401  (forces registration)
from ttps.base import registry


def test_t1033_runs() -> None:
    ttp = registry.get("T1033")
    assert ttp is not None
    res = ttp.run({})
    assert res.ok
    assert "user=" in res.output


def test_t1083_runs() -> None:
    ttp = registry.get("T1083")
    assert ttp is not None
    res = ttp.run({"max_entries": 10, "max_depth": 1})
    assert res.ok


def test_t1059_rejects_arbitrary() -> None:
    ttp = registry.get("T1059")
    assert ttp is not None
    res = ttp.run({"command": "rm -rf /"})
    assert not res.ok
    assert "allowlist" in (res.error or "")


def test_t1059_allows_whoami() -> None:
    ttp = registry.get("T1059")
    assert ttp is not None
    res = ttp.run({"command": "whoami"})
    assert res.ok
