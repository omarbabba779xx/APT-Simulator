"""Scenario DSL — pydantic models.

A scenario is a named ATT&CK kill-chain expressed as ordered/parallel TTP steps.

Example YAML:
    name: basic_recon
    description: Demo reconnaissance chain
    target_platforms: [windows, linux]
    steps:
      - id: discover_user
        ttp: T1033
        params: {}
      - id: discover_files
        ttp: T1083
        params:
          paths: ["%USERPROFILE%/Documents"]
        depends_on: [discover_user]
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


Platform = Literal["windows", "linux", "darwin", "any"]


class ScenarioStep(BaseModel):
    id: str
    ttp: str  # MITRE ATT&CK technique ID like "T1033", "T1083", "T1547.001"
    params: dict[str, Any] = Field(default_factory=dict)
    depends_on: list[str] = Field(default_factory=list)
    timeout_seconds: int = 60
    abort_on_fail: bool = False

    @field_validator("ttp")
    @classmethod
    def _ttp_format(cls, v: str) -> str:
        v = v.strip().upper()
        if not v.startswith("T") or not v[1:].split(".")[0].isdigit():
            raise ValueError(f"invalid ATT&CK ID format: {v}")
        return v


class Scenario(BaseModel):
    name: str
    description: str = ""
    target_platforms: list[Platform] = Field(default_factory=lambda: ["any"])
    steps: list[ScenarioStep]
    tags: list[str] = Field(default_factory=list)
    actor: str | None = None  # APT group emulated, optional. Informational only.

    @field_validator("steps")
    @classmethod
    def _unique_step_ids(cls, v: list[ScenarioStep]) -> list[ScenarioStep]:
        ids = [s.id for s in v]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate step ids in scenario")
        return v

    def validate_dag(self) -> None:
        """Confirm depends_on references exist and graph is acyclic."""
        ids = {s.id for s in self.steps}
        for s in self.steps:
            for dep in s.depends_on:
                if dep not in ids:
                    raise ValueError(f"step '{s.id}' depends on unknown step '{dep}'")
        # Topological sort to detect cycles.
        graph = {s.id: set(s.depends_on) for s in self.steps}
        ordered: list[str] = []
        while graph:
            roots = [n for n, deps in graph.items() if not deps]
            if not roots:
                raise ValueError("cycle detected in scenario steps")
            for n in roots:
                ordered.append(n)
                del graph[n]
            for deps in graph.values():
                deps.difference_update(roots)
