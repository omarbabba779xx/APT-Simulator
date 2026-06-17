"""Shared application state holder for FastAPI dependency injection."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..core.audit import AuditLog
from ..core.bus import EventBus
from ..core.config import AppConfig
from ..core.killswitch import KillSwitch
from ..core.planner import Planner
from ..dsl.schema import Scenario
from ..storage.db import Repository


@dataclass
class AppState:
    config: AppConfig
    killswitch: KillSwitch
    audit: AuditLog
    planner: Planner
    repo: Repository | None = None
    bus: EventBus | None = None
    signing_key: Ed25519PrivateKey | None = None
    public_key_pem: str | None = None
    jwt_secret: bytes | None = None
    scenarios: dict[str, Scenario] = field(default_factory=dict)
    agents: dict[str, dict[str, Any]] = field(default_factory=dict)
    campaigns: dict[str, dict[str, Any]] = field(default_factory=dict)


_state: AppState | None = None


def set_state(s: AppState) -> None:
    global _state
    _state = s


def get_state() -> AppState:
    if _state is None:
        raise RuntimeError("AppState not initialized")
    return _state
