from __future__ import annotations

import ttps  # noqa: F401
from ttps.base import registry


def test_t1580_unknown_provider_rejected() -> None:
    ttp = registry.get("T1580")
    assert ttp is not None
    res = ttp.run({"provider": "fictional"})
    assert not res.ok
    assert "unsupported provider" in (res.error or "")


def test_t1580_aws_without_boto3_or_creds_fails_cleanly() -> None:
    ttp = registry.get("T1580")
    assert ttp is not None
    res = ttp.run({"provider": "aws", "region": "us-east-1"})
    # On a test runner without AWS creds, this must fail with a clean error,
    # NOT raise. Boto3 may or may not be installed.
    assert not res.ok
    assert res.error is not None


def test_t1580_azure_without_sdk_or_creds_fails_cleanly() -> None:
    ttp = registry.get("T1580")
    assert ttp is not None
    res = ttp.run({"provider": "azure"})
    assert not res.ok
    assert res.error is not None
