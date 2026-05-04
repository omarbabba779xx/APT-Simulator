"""Adversary profiles API endpoints."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..core.auth import require_role
from ..profile_gen import generate_scenario, list_profiles, load_profile


router = APIRouter(prefix="/profiles", tags=["profiles"])


class ProfileGenerateRequest(BaseModel):
    steps: int = 0
    seed: int | None = None
    platform: str | None = None


@router.get("")
def list_all_profiles(_claims=require_role("viewer")) -> list[dict[str, Any]]:
    """List available adversary profiles (name, origin, motivation, TTP count)."""
    result = []
    for name in list_profiles():
        try:
            p = load_profile(name)
            result.append({
                "id": name,
                "name": p.get("name", name),
                "aliases": p.get("aliases", []),
                "origin": p.get("origin", "unknown"),
                "motivation": p.get("motivation", "unknown"),
                "active_since": p.get("active_since"),
                "preferred_ttp_count": len(p.get("preferred_ttps", [])),
                "target_platforms": p.get("target_platforms", []),
                "tags": p.get("tags", []),
            })
        except Exception as exc:
            result.append({"id": name, "error": str(exc)})
    return result


@router.get("/{profile_id}")
def get_profile(profile_id: str, _claims=require_role("viewer")) -> dict[str, Any]:
    """Return the full profile document for a named threat actor."""
    try:
        return load_profile(profile_id)
    except FileNotFoundError:
        raise HTTPException(404, f"Profile '{profile_id}' not found")


@router.post("/{profile_id}/generate")
def generate_from_profile(
    profile_id: str,
    req: ProfileGenerateRequest,
    _claims=require_role("operator"),
) -> dict[str, Any]:
    """Generate a scenario YAML dict from the named adversary profile."""
    try:
        return generate_scenario(
            profile_id,
            steps=req.steps,
            seed=req.seed,
            platform_override=req.platform,
        )
    except FileNotFoundError:
        raise HTTPException(404, f"Profile '{profile_id}' not found")
    except ValueError as exc:
        raise HTTPException(400, str(exc))
