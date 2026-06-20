"""JWT-based RBAC.

Three roles, ordered by privilege:

    viewer  < operator < admin

Endpoints declare the minimum role they require via Depends(require_role(...)).
When `security.require_auth=False` (default), the gate is a no-op.

Token issuance:
    python -m orchestrator.auth_cli issue --role admin --subject alice
"""
from __future__ import annotations

import secrets
import time
import os
import json
from pathlib import Path
from typing import Any

import jwt
from fastapi import Depends, HTTPException, Request
from jwt import PyJWKClient
from jwt.algorithms import RSAAlgorithm

from .config import SecurityConfig


ROLES = ("viewer", "operator", "admin")
_RANK = {r: i for i, r in enumerate(ROLES)}


def has_role(actual: str, required: str) -> bool:
    return _RANK.get(actual, -1) >= _RANK.get(required, 99)


def load_or_generate_secret(path: str | Path, env_var: str | None = None) -> bytes:
    if env_var:
        value = os.environ.get(env_var)
        if value:
            return value.encode("utf-8")
    p = Path(path)
    if p.exists():
        return p.read_bytes()
    p.parent.mkdir(parents=True, exist_ok=True)
    secret = secrets.token_bytes(48)
    p.write_bytes(secret)
    return secret


def issue_token(
    secret: bytes,
    *,
    role: str,
    subject: str,
    ttl_seconds: int = 3600,
    algorithm: str = "HS256",
) -> str:
    if role not in ROLES:
        raise ValueError(f"unknown role '{role}', expected one of {ROLES}")
    now = int(time.time())
    payload = {
        "sub": subject,
        "role": role,
        "iat": now,
        "exp": now + ttl_seconds,
        "iss": "apt-simulator",
    }
    return jwt.encode(payload, secret, algorithm=algorithm)


def decode_token(token: str, secret: bytes, algorithm: str = "HS256") -> dict[str, Any]:
    return jwt.decode(token, secret, algorithms=[algorithm], issuer="apt-simulator")


def decode_oidc_token(token: str, config: SecurityConfig) -> dict[str, Any]:
    if not config.oidc_issuer or not config.oidc_audience:
        raise jwt.InvalidTokenError("OIDC issuer and audience must be configured")
    key = _oidc_signing_key(token, config)
    claims = jwt.decode(
        token,
        key=key,
        algorithms=["RS256"],
        audience=config.oidc_audience,
        issuer=config.oidc_issuer,
    )
    role = _map_role_claim(claims, config)
    claims["role"] = role
    return claims


def _oidc_signing_key(token: str, config: SecurityConfig) -> Any:
    if config.oidc_jwks_path:
        return _oidc_signing_key_from_file(token, Path(config.oidc_jwks_path))
    if config.oidc_jwks_url:
        return PyJWKClient(config.oidc_jwks_url).get_signing_key_from_jwt(token).key
    raise jwt.InvalidTokenError("OIDC JWKS URL or local JWKS path must be configured")


def _oidc_signing_key_from_file(token: str, path: Path) -> Any:
    if not path.exists():
        raise jwt.InvalidTokenError(f"OIDC JWKS file does not exist: {path}")
    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    jwks = json.loads(path.read_text(encoding="utf-8"))
    for key_data in jwks.get("keys", []):
        if key_data.get("kid") == kid:
            return RSAAlgorithm.from_jwk(json.dumps(key_data))
    raise jwt.InvalidTokenError(f"OIDC signing key not found for kid: {kid}")


def _map_role_claim(claims: dict[str, Any], config: SecurityConfig) -> str:
    value = claims.get(config.rbac_role_claim)
    values = value if isinstance(value, list) else [value]
    for item in values:
        if not item:
            continue
        role = config.rbac_role_map.get(str(item), str(item))
        if role in ROLES:
            return role
    raise jwt.InvalidTokenError(f"no valid RBAC role in claim '{config.rbac_role_claim}'")


def _extract_token(request: Request) -> str | None:
    header = request.headers.get("authorization") or request.headers.get("Authorization")
    if not header or not header.lower().startswith("bearer "):
        return None
    return header.split(None, 1)[1].strip()


def require_role(min_role: str):
    """FastAPI dependency factory enforcing min_role unless auth is disabled."""
    if min_role not in ROLES:
        raise ValueError(f"unknown role '{min_role}'")

    def dep(request: Request) -> dict[str, Any]:
        # Lazy import to avoid circular dep with state at module import time.
        from ..api.state import get_state

        s = get_state()
        if not s.config.security.require_auth:
            return {"role": "admin", "sub": "auth-disabled"}
        token = _extract_token(request)
        if not token:
            raise HTTPException(401, "missing bearer token")
        if s.config.security.sso_enabled:
            try:
                claims = decode_oidc_token(token, s.config.security)
            except jwt.ExpiredSignatureError:
                raise HTTPException(401, "token expired")
            except jwt.InvalidTokenError as exc:
                raise HTTPException(401, f"invalid token: {exc}")
        elif s.jwt_secret is None:
            raise HTTPException(500, "auth misconfigured: no secret loaded")
        else:
            try:
                claims = decode_token(token, s.jwt_secret, algorithm=s.config.security.jwt_algorithm)
            except jwt.ExpiredSignatureError:
                raise HTTPException(401, "token expired")
            except jwt.InvalidTokenError as exc:
                raise HTTPException(401, f"invalid token: {exc}")
        actual = claims.get("role", "")
        if not has_role(actual, min_role):
            raise HTTPException(
                403, f"role '{actual}' insufficient; need '{min_role}' or higher"
            )
        return claims

    return Depends(dep)
