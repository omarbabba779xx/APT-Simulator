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
from pathlib import Path
from typing import Any

import jwt
from fastapi import Depends, HTTPException, Request


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
        if s.jwt_secret is None:
            raise HTTPException(500, "auth misconfigured: no secret loaded")
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
