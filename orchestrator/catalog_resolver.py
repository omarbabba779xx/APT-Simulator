"""Helpers for resolving ATT&CK technique IDs to registered simulator TTPs."""
from __future__ import annotations

from typing import Any

import ttps  # noqa: F401
from ttps.base import registry


PREFERRED_PACKS = (
    "core",
    "windows",
    "linux",
    "cloud",
    "identity",
    "saas",
    "ad_enterprise_lab",
    "cloud_k8s_lab",
    "attack_enterprise",
    "attack_variants",
    "attack_scale_variants",
)


def base_attack_id(value: str) -> str:
    return value.strip().upper().split(":", 1)[0]


def ttp_base_id(ttp: Any) -> str:
    return str(getattr(ttp, "base_attack_id", getattr(ttp, "attack_id", ""))).upper()


def resolve_ttp(attack_id: str, preferred_packs: tuple[str, ...] = PREFERRED_PACKS) -> Any | None:
    """Return the best registered TTP for an ATT&CK technique or sub-technique ID."""
    wanted = base_attack_id(attack_id)
    exact = registry.get(wanted)
    if exact is not None:
        return exact

    candidates = [ttp for ttp in registry.all().values() if ttp_base_id(ttp) == wanted]
    if not candidates:
        return None

    def rank(ttp: Any) -> tuple[int, str]:
        pack = str(getattr(ttp, "pack", "core"))
        try:
            pack_rank = preferred_packs.index(pack)
        except ValueError:
            pack_rank = len(preferred_packs)
        return pack_rank, str(getattr(ttp, "attack_id", ""))

    return sorted(candidates, key=rank)[0]


def resolve_attack_id(attack_id: str) -> str | None:
    ttp = resolve_ttp(attack_id)
    return str(ttp.attack_id) if ttp is not None else None


def registered_base_ids() -> set[str]:
    return {ttp_base_id(ttp) for ttp in registry.all().values()}
