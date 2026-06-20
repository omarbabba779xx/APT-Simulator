"""Wire schemas for HTTP API."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class AgentRegister(BaseModel):
    hostname: str
    platform: str
    pid: int
    agent_version: str = "unknown"
    install_id: str = ""
    capabilities: list[str] = Field(default_factory=list)
    certificate_subject: str = ""


class AgentRegistered(BaseModel):
    agent_id: str
    server_time: float
    public_key_pem: str | None = None


class BeaconRequest(BaseModel):
    agent_id: str
    platform: str
    agent_version: str = "unknown"
    capabilities: list[str] = Field(default_factory=list)
    certificate_subject: str = ""


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


class CampaignRunRequest(BaseModel):
    count: int = Field(default=10, ge=1, le=100)
    scenario_names: list[str] | None = None
    actor: str | None = None
    difficulty: str | None = None
    platform: str | None = None
    source: str | None = None
    min_steps: int | None = Field(default=None, ge=1)
    max_steps: int | None = Field(default=None, ge=1)
    scheduled_at: float | None = None
    repeat_interval_seconds: int | None = Field(default=None, ge=1)
    repeat_count: int = Field(default=1, ge=1, le=50)


class CampaignSummary(BaseModel):
    id: str
    status: str
    created_at: float
    updated_at: float
    total_runs: int
    progress_percent: float
    run_statuses: dict[str, int]
    scenario_names: list[str]
    run_ids: list[str]
    scheduled_at: float | None = None
    repeat_interval_seconds: int | None = None
    repeat_remaining: int = 0


class SIEMSendRequest(BaseModel):
    url: str
    token: str = ""
    api_key: str = ""
    workspace_id: str = ""
    shared_key: str = ""
    log_type: str = "AptSimulator_CL"
    bearer_token: str = ""
    index: str = "apt-simulator"
    event_limit: int = Field(default=10, ge=1, le=500)
    allow_external: bool = False
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=60.0)
