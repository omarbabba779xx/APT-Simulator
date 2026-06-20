from __future__ import annotations


import json

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from orchestrator.core.auth import (
    ROLES,
    decode_token,
    decode_oidc_token,
    has_role,
    issue_token,
    load_or_generate_secret,
)
from orchestrator.core.config import SecurityConfig


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


def test_secret_env_override(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("APT_SIM_TEST_SECRET", "from-env")
    assert load_or_generate_secret(tmp_path / "s.bin", env_var="APT_SIM_TEST_SECRET") == b"from-env"
    assert not (tmp_path / "s.bin").exists()


def test_oidc_jwks_role_mapping(tmp_path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    public_jwk["kid"] = "test-key"
    jwks_path = tmp_path / "jwks.json"
    jwks_path.write_text(json.dumps({"keys": [public_jwk]}), encoding="utf-8")

    token = jwt.encode(
        {
            "sub": "analyst@example.com",
            "iss": "https://idp.example.test/",
            "aud": "apt-simulator",
            "groups": ["soc-operators"],
        },
        key,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )
    claims = decode_oidc_token(
        token,
        SecurityConfig(
            sso_enabled=True,
            oidc_issuer="https://idp.example.test/",
            oidc_audience="apt-simulator",
            oidc_jwks_path=str(jwks_path),
            rbac_role_claim="groups",
            rbac_role_map={"soc-operators": "operator"},
        ),
    )
    assert claims["sub"] == "analyst@example.com"
    assert claims["role"] == "operator"


def test_roles_constant() -> None:
    assert ROLES == ("viewer", "operator", "admin")
