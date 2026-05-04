from __future__ import annotations

import ttps  # noqa: F401
from ttps.base import registry


def test_gcp_provider_routes() -> None:
    ttp = registry.get("T1580")
    assert ttp is not None
    res = ttp.run({"provider": "gcp"})
    assert not res.ok
    # Either lib missing or creds missing — both acceptable failure modes.
    assert res.error is not None


def test_unknown_provider_lists_all_three() -> None:
    ttp = registry.get("T1580")
    assert ttp is not None
    res = ttp.run({"provider": "ibm"})
    assert not res.ok
    assert "aws|azure|gcp" in (res.error or "")
