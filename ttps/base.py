"""TTP plugin base class + global registry.

Every TTP module registers a class instance on import. Agents look up by ATT&CK ID.

All TTPs MUST be simulation-only:
  - read-only system queries OK
  - writes only to clearly-marked test artifacts inside an allow-listed location
  - no real destructive impact, no network exfil to non-lab targets
  - cleanup() must restore state where applicable
"""
from __future__ import annotations

import platform
import time
from dataclasses import dataclass, field
from typing import Any, ClassVar


@dataclass
class TTPResult:
    ok: bool
    output: str = ""
    artifacts: list[str] = field(default_factory=list)
    error: str | None = None
    started_at: float = 0.0
    finished_at: float = 0.0
    extra: dict[str, Any] = field(default_factory=dict)


class TTP:
    attack_id: ClassVar[str] = ""
    name: ClassVar[str] = ""
    description: ClassVar[str] = ""
    supported_platforms: ClassVar[tuple[str, ...]] = ("windows", "linux", "darwin")
    tactic: ClassVar[str] = ""

    def supports(self, plat: str | None = None) -> bool:
        plat = plat or platform.system().lower()
        return plat in self.supported_platforms

    def run(self, params: dict[str, Any]) -> TTPResult:  # pragma: no cover
        raise NotImplementedError

    def cleanup(self, params: dict[str, Any]) -> TTPResult:
        return TTPResult(ok=True, output="no cleanup required", started_at=time.time(), finished_at=time.time())

    def sigma_rule(self) -> dict[str, Any] | None:
        """Return a Sigma rule dict that detects this TTP's telemetry.

        Override in subclasses. Return None to skip rule generation.
        """
        return None

    def synthetic_events(
        self, params: dict[str, Any], result: TTPResult | None = None
    ) -> list[dict[str, Any]]:
        """Return SIEM-shaped events that running this TTP would produce.

        Used by the detection-diff tool to validate that the TTP's own Sigma
        rule actually matches its own telemetry. Override in subclasses.
        """
        return []


class _Registry:
    def __init__(self) -> None:
        self._items: dict[str, TTP] = {}

    def register(self, ttp: TTP) -> None:
        if not ttp.attack_id:
            raise ValueError(f"TTP {type(ttp).__name__} missing attack_id")
        self._items[ttp.attack_id.upper()] = ttp

    def get(self, attack_id: str) -> TTP | None:
        return self._items.get(attack_id.upper())

    def all(self) -> dict[str, TTP]:
        return dict(self._items)


registry = _Registry()
