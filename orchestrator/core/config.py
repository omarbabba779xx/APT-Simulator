"""Config loader. Reads YAML and merges with overrides."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field


class OrchestratorConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8000
    audit_dir: str = "data/audit"
    scenarios_dir: str = "scenarios"
    db_path: str = "data/apt_sim.db"
    killswitch_file: str = "data/STOP"


class AgentConfig(BaseModel):
    beacon_interval_seconds: int = 5
    beacon_jitter_seconds: int = 2
    ttl_seconds: int = 14400
    max_consecutive_failures: int = 5


class SecurityConfig(BaseModel):
    require_signed_payloads: bool = True
    signing_key_path: str = "keys/ed25519_private.pem"
    signing_pub_path: str = "keys/ed25519_public.pem"
    enforce_lab_whitelist: bool = True
    require_auth: bool = False
    jwt_secret_path: str = "keys/jwt_secret.bin"
    jwt_algorithm: str = "HS256"


class LoggingConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    level: str = "INFO"
    json_output: bool = Field(default=True, alias="json")
    file: str = "data/logs/apt_sim.jsonl"


class AppConfig(BaseModel):
    orchestrator: OrchestratorConfig = Field(default_factory=OrchestratorConfig)
    agent: AgentConfig = Field(default_factory=AgentConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)


class LabWhitelist(BaseModel):
    hostnames: list[str] = Field(default_factory=list)
    cidrs: list[str] = Field(default_factory=list)
    allow_any: bool = False


def load_config(path: str | Path = "config/default.yaml") -> AppConfig:
    p = Path(path)
    if not p.exists():
        return AppConfig()
    raw: dict[str, Any] = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return AppConfig(**raw)


def load_whitelist(path: str | Path = "config/lab_whitelist.yaml") -> LabWhitelist:
    p = Path(path)
    if not p.exists():
        return LabWhitelist()
    raw: dict[str, Any] = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return LabWhitelist(**raw)
