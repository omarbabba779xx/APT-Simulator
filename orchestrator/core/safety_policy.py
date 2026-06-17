"""Central safety policy for TTP execution."""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any


MARKER_ONLY = "marker-only"
READ_ONLY = "read-only"
LAB_WRITE = "lab-write"
NETWORK_LAB_ONLY = "network-lab-only"
KNOWN_TIERS = {MARKER_ONLY, READ_ONLY, LAB_WRITE, NETWORK_LAB_ONLY}


@dataclass(frozen=True)
class SafetyVerdict:
    allowed: bool
    tier: str
    reason: str = ""


class SafetyPolicy:
    """Runtime guardrail for lab-safe execution.

    Normal marker/read-only/lab-write simulations are allowed. Explicit
    ``live_mode`` requires an environment opt-in plus an optional token match.
    """

    def __init__(self, live_enabled: bool = False, live_token: str | None = None) -> None:
        self.live_enabled = live_enabled
        self.live_token = live_token

    @classmethod
    def from_env(cls) -> "SafetyPolicy":
        return cls(
            live_enabled=os.environ.get("APT_SIM_LIVE_MODE", "").lower() == "authorized",
            live_token=os.environ.get("APT_SIM_SAFETY_TOKEN"),
        )

    def validate(self, ttp: Any, params: dict[str, Any]) -> SafetyVerdict:
        tier = str(getattr(ttp, "safety_tier", LAB_WRITE))
        if tier not in KNOWN_TIERS:
            return SafetyVerdict(False, tier, f"unknown safety tier: {tier}")

        if not params.get("live_mode"):
            return SafetyVerdict(True, tier)

        if not self.live_enabled:
            return SafetyVerdict(False, tier, "live_mode requires APT_SIM_LIVE_MODE=authorized")

        if self.live_token and params.get("safety_token") != self.live_token:
            return SafetyVerdict(False, tier, "live_mode safety token mismatch")

        return SafetyVerdict(True, tier)


def describe_ttp_safety(ttp: Any) -> dict[str, str]:
    tier = str(getattr(ttp, "safety_tier", LAB_WRITE))
    dry_run_default = "true" if tier in {MARKER_ONLY, READ_ONLY} else "false"
    return {
        "safety_tier": tier,
        "dry_run_default": dry_run_default,
        "live_mode": "requires APT_SIM_LIVE_MODE=authorized",
    }
