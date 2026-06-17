"""SQLite storage via SQLModel. Tracks agents, runs, step instances."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlmodel import Field, Session, SQLModel, col, create_engine, select


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Agent(SQLModel, table=True):
    id: str = Field(primary_key=True)
    hostname: str
    platform: str
    pid: int
    registered_at: datetime = Field(default_factory=_now)
    last_seen: datetime = Field(default_factory=_now)
    status: str = "active"


class Run(SQLModel, table=True):
    id: str = Field(primary_key=True)
    scenario_name: str
    started_at: datetime = Field(default_factory=_now)
    finished_at: Optional[datetime] = None
    status: str = "running"


class StepInstance(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    run_id: str = Field(foreign_key="run.id", index=True)
    step_id: str
    attack_id: str
    agent_id: Optional[str] = Field(default=None, foreign_key="agent.id")
    status: str = "queued"
    created_at: datetime = Field(default_factory=_now)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    output: Optional[str] = None
    error: Optional[str] = None


def init_engine(db_path: str | Path):
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{db_path}", echo=False)
    SQLModel.metadata.create_all(engine)
    return engine


class Repository:
    def __init__(self, engine) -> None:
        self.engine = engine

    # --- agents ---
    def upsert_agent(self, agent_id: str, hostname: str, platform: str, pid: int) -> None:
        with Session(self.engine) as s:
            existing = s.get(Agent, agent_id)
            if existing:
                existing.hostname = hostname
                existing.platform = platform
                existing.pid = pid
                existing.last_seen = _now()
                existing.status = "active"
                s.add(existing)
            else:
                s.add(Agent(id=agent_id, hostname=hostname, platform=platform, pid=pid))
            s.commit()

    def touch_agent(self, agent_id: str) -> None:
        with Session(self.engine) as s:
            a = s.get(Agent, agent_id)
            if a:
                a.last_seen = _now()
                s.add(a)
                s.commit()

    def list_agents(self) -> list[Agent]:
        with Session(self.engine) as s:
            return list(s.exec(select(Agent)).all())

    # --- runs ---
    def create_run(self, run_id: str, scenario_name: str, steps: list[tuple[str, str]]) -> None:
        with Session(self.engine) as s:
            s.add(Run(id=run_id, scenario_name=scenario_name, status="running"))
            for step_id, attack_id in steps:
                s.add(StepInstance(run_id=run_id, step_id=step_id, attack_id=attack_id, status="queued"))
            s.commit()

    def update_run_status(self, run_id: str, status: str, finished: bool = False) -> None:
        with Session(self.engine) as s:
            r = s.get(Run, run_id)
            if not r:
                return
            r.status = status
            if finished:
                r.finished_at = _now()
            s.add(r)
            s.commit()

    def update_step(
        self,
        run_id: str,
        step_id: str,
        status: str,
        agent_id: str | None = None,
        output: str | None = None,
        error: str | None = None,
        mark_started: bool = False,
        mark_finished: bool = False,
    ) -> None:
        with Session(self.engine) as s:
            stmt = select(StepInstance).where(
                StepInstance.run_id == run_id, StepInstance.step_id == step_id
            )
            row = s.exec(stmt).first()
            if not row:
                return
            row.status = status
            if agent_id:
                row.agent_id = agent_id
            if output is not None:
                row.output = output[:4000] if output else output
            if error is not None:
                row.error = error
            if mark_started and row.started_at is None:
                row.started_at = _now()
            if mark_finished:
                row.finished_at = _now()
            s.add(row)
            s.commit()

    def list_runs(self) -> list[Run]:
        with Session(self.engine) as s:
            return list(s.exec(select(Run).order_by(col(Run.started_at).desc())).all())

    def get_run(self, run_id: str) -> Run | None:
        with Session(self.engine) as s:
            return s.get(Run, run_id)

    def steps_for_run(self, run_id: str) -> list[StepInstance]:
        with Session(self.engine) as s:
            stmt = select(StepInstance).where(StepInstance.run_id == run_id).order_by(col(StepInstance.id))
            return list(s.exec(stmt).all())
