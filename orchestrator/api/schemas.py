"""Wire schemas for HTTP API."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class AgentRegister(BaseModel):
    hostname: str
    platform: str
    pid: int


class AgentRegistered(BaseModel):
    agent_id: str
    server_time: float
    public_key_pem: str | None = None


class BeaconRequest(BaseModel):
    agent_id: str
    platform: str


class BeaconTask(BaseModel):
    run_id: str
    step_id: str
    attack_id: str
    params: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = 60
    payload_signature: str | None = None  # base64 ed25519 signature


class BeaconResponse(BaseModel):
    killswitch: bool
    task: BeaconTask | None = None
    note: str | None = None


class TaskResultIn(BaseModel):
    agent_id: str
    run_id: str
    step_id: str
    ok: bool
    output: str = ""
    error: str | None = None


class ScenarioRunRequest(BaseModel):
    """Either provide name (resolves from scenarios dir) or full scenario body."""

    name: str | None = None
    inline: dict[str, Any] | None = None


class RunSummary(BaseModel):
    id: str
    scenario: str
    status: str
    started_at: float
    finished_at: float
    step_summary: dict[str, str]


class TTPDescriptor(BaseModel):
    attack_id: str
    name: str
    tactic: str
    description: str
    supported_platforms: list[str]
    pack: str | None = None
    safety_tier: str | None = None
    base_attack_id: str | None = None


class KillswitchStatus(BaseModel):
    active: bool
    reason: str | None = None


class StepDetail(BaseModel):
    id: str
    attack_id: str
    status: str
    agent_id: str | None = None
    started_at: float | None = None
    finished_at: float | None = None
    output: str | None = None
    error: str | None = None


class RunDetail(BaseModel):
    id: str
    scenario: str
    status: str
    started_at: float
    steps: list[StepDetail]
