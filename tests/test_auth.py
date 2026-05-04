from __future__ import annotations

import time

import jwt
import pytest

from orchestrator.core.auth import (
    ROLES,
    decode_token,
    has_role,
    issue_token,
    load_or_generate_secret,
)


def test_role_ordering() -> None:
    assert has_role("admin", "viewer")
    assert has_role("admin", "operator")
    assert has_role("admin", "admin")
    assert has_role("operator", "viewer")
    assert not has_role("viewer", "operator")
    assert not has_role("viewer", "admin")
    assert not has_role("operator", "admin")


def test_issue_decode_roundtrip(tmp_path) -> None:
    secret = load_or_generate_secret(tmp_path / "s.bin")
    tok = issue_token(secret, role="operator", subject="alice")
    claims = decode_token(tok, secret)
    assert claims["role"] == "operator"
    assert claims["sub"] == "alice"
    assert claims["iss"] == "apt-simulator"


def test_unknown_role_rejected(tmp_path) -> None:
    secret = load_or_generate_secret(tmp_path / "s.bin")
    with pytest.raises(ValueError, match="unknown role"):
        issue_token(secret, role="superuser", subject="x")


def test_expired_token_rejected(tmp_path) -> None:
    secret = load_or_generate_secret(tmp_path / "s.bin")
    tok = issue_token(secret, role="viewer", subject="x", ttl_seconds=-1)
    with pytest.raises(jwt.ExpiredSignatureError):
        decode_token(tok, secret)


def test_secret_persisted(tmp_path) -> None:
    p = tmp_path / "s.bin"
    s1 = load_or_generate_secret(p)
    s2 = load_or_generate_secret(p)
    assert s1 == s2
    assert len(s1) >= 32


def test_roles_constant() -> None:
    assert ROLES == ("viewer", "operator", "admin")
