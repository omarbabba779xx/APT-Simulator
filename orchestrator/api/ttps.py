"""TTP discovery endpoint."""
from __future__ import annotations

from fastapi import APIRouter

import ttps  # noqa: F401  (triggers TTP self-registration)
from ttps.base import registry

from ..attack_sync import official_tactic_for
from ..core.auth import require_role
from .schemas import TTPDescriptor


router = APIRouter(prefix="/ttps", tags=["ttps"])


@router.get("", response_model=list[TTPDescriptor])
def list_ttps(_claims=require_role("viewer")) -> list[TTPDescriptor]:
    return [
        TTPDescriptor(
            attack_id=t.attack_id,
            name=t.name,
            tactic=official_tactic_for(getattr(t, "base_attack_id", t.attack_id), t.tactic),
            description=t.description,
            supported_platforms=list(t.supported_platforms),
            pack=getattr(t, "pack", "core"),
            safety_tier=getattr(t, "safety_tier", "lab-write"),
            base_attack_id=getattr(t, "base_attack_id", t.attack_id),
        )
        for t in registry.all().values()
    ]
