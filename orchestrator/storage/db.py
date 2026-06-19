"""SQLite storage via SQLModel. Tracks agents, runs, step instances."""
from __future__ import annotations

import json
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


class QueueEntry(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    run_id: str = Field(foreign_key="run.id", index=True)
    step_id: str
    attack_id: str
    status: str = Field(default="queued", index=True)
    assigned_agent: Optional[str] = Field(default=None, foreign_key="agent.id")
    target_platforms_json: str = "[]"
    attempt: int = 0
    max_attempts: int = 1
    cleanup_required: bool = True
    cleanup_status: str = "pending"
    created_at: datetime = Field(default_factory=_now)
    updated_at: datetime = Field(default_factory=_now)
    next_attempt_at: Optional[datetime] = None
    last_error: Optional[str] = None


class RunLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    run_id: str = Field(foreign_key="run.id", index=True)
    step_id: Optional[str] = None
    level: str = "info"
    event: str
    message: str
    created_at: datetime = Field(default_factory=_now)


class RunArtifact(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    run_id: str = Field(foreign_key="run.id", index=True)
    kind: str
    name: str
    path: str
    metadata_json: str = "{}"
    created_at: datetime = Field(default_factory=_now)


class CampaignRecord(SQLModel, table=True):
    id: str = Field(primary_key=True)
    status: str = Field(index=True)
    created_at: datetime = Field(default_factory=_now)
    updated_at: datetime = Field(default_factory=_now)
    scenario_names_json: str = "[]"
    run_ids_json: str = "[]"
    scheduled_at: Optional[datetime] = None
    repeat_interval_seconds: Optional[int] = None
    repeat_remaining: int = 0


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
    def create_run(
        self,
        run_id: str,
        scenario_name: str,
        steps: list[tuple[str, str]],
        *,
        target_platforms: list[str] | None = None,
        max_attempts: int = 1,
    ) -> None:
        with Session(self.engine) as s:
            s.add(Run(id=run_id, scenario_name=scenario_name, status="running"))
            for step_id, attack_id in steps:
                s.add(StepInstance(run_id=run_id, step_id=step_id, attack_id=attack_id, status="queued"))
                s.add(
                    QueueEntry(
                        run_id=run_id,
                        step_id=step_id,
                        attack_id=attack_id,
                        target_platforms_json=json.dumps(target_platforms or ["any"]),
                        max_attempts=max(max_attempts, 1),
                    )
                )
            s.add(
                RunArtifact(
                    run_id=run_id,
                    kind="report",
                    name="run-report-json",
                    path=f"/reports/runs/{run_id}.json",
                    metadata_json=json.dumps({"format": "json"}),
                )
            )
            s.add(
                RunArtifact(
                    run_id=run_id,
                    kind="bundle",
                    name="run-artifact-zip",
                    path=f"/execution/artifacts/{run_id}.zip",
                    metadata_json=json.dumps({"format": "zip"}),
                )
            )
            s.add(RunLog(run_id=run_id, event="run.created", message=f"run {run_id} queued"))
            s.commit()

    def update_run_status(self, run_id: str, status: str, finished: bool = False) -> None:
        with Session(self.engine) as s:
            r = s.get(Run, run_id)
            if not r:
                return
            r.status = status
            if finished:
                r.finished_at = _now()
                self._mark_cleanup_complete(s, run_id)
            s.add(r)
            s.add(RunLog(run_id=run_id, event="run.status", message=f"run status set to {status}"))
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
            q = s.exec(
                select(QueueEntry).where(QueueEntry.run_id == run_id, QueueEntry.step_id == step_id)
            ).first()
            if q:
                q.status = status
                q.updated_at = _now()
                if agent_id:
                    q.assigned_agent = agent_id
                if mark_started:
                    q.attempt += 1
                if error:
                    q.last_error = error
                if status == "success":
                    q.cleanup_status = "not_required"
                elif status in {"failed", "aborted", "skipped"}:
                    q.cleanup_status = "pending"
                s.add(q)
            message = error or output or f"step status set to {status}"
            s.add(
                RunLog(
                    run_id=run_id,
                    step_id=step_id,
                    level="error" if status == "failed" else "info",
                    event=f"step.{status}",
                    message=message[:1000],
                )
            )
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

    def queue_entries(self, run_id: str | None = None) -> list[QueueEntry]:
        with Session(self.engine) as s:
            stmt = select(QueueEntry)
            if run_id:
                stmt = stmt.where(QueueEntry.run_id == run_id)
            stmt = stmt.order_by(col(QueueEntry.id))
            return list(s.exec(stmt).all())

    def logs_for_run(self, run_id: str) -> list[RunLog]:
        with Session(self.engine) as s:
            stmt = select(RunLog).where(RunLog.run_id == run_id).order_by(col(RunLog.id))
            return list(s.exec(stmt).all())

    def artifacts_for_run(self, run_id: str) -> list[RunArtifact]:
        with Session(self.engine) as s:
            stmt = select(RunArtifact).where(RunArtifact.run_id == run_id).order_by(col(RunArtifact.id))
            return list(s.exec(stmt).all())

    def retry_failed_steps(self, run_id: str) -> int:
        retryable = {"failed", "skipped", "aborted"}
        changed = 0
        with Session(self.engine) as s:
            run = s.get(Run, run_id)
            if not run:
                return 0
            for row in s.exec(select(StepInstance).where(StepInstance.run_id == run_id)).all():
                if row.status not in retryable:
                    continue
                row.status = "queued"
                row.agent_id = None
                row.started_at = None
                row.finished_at = None
                row.output = None
                row.error = None
                s.add(row)
                changed += 1
            for entry in s.exec(select(QueueEntry).where(QueueEntry.run_id == run_id)).all():
                if entry.status not in retryable:
                    continue
                entry.status = "queued"
                entry.assigned_agent = None
                entry.cleanup_status = "pending"
                entry.last_error = None
                entry.next_attempt_at = None
                entry.updated_at = _now()
                s.add(entry)
            if changed:
                run.status = "running"
                run.finished_at = None
                s.add(run)
                s.add(
                    RunLog(
                        run_id=run_id,
                        event="run.retry_failed",
                        message=f"requeued {changed} failed step(s)",
                    )
                )
            s.commit()
        return changed

    def mark_cleanup_complete(self, run_id: str) -> int:
        with Session(self.engine) as s:
            entries = s.exec(select(QueueEntry).where(QueueEntry.run_id == run_id)).all()
            changed = 0
            for entry in entries:
                if entry.cleanup_required and entry.cleanup_status != "complete":
                    entry.cleanup_status = "complete"
                    entry.updated_at = _now()
                    s.add(entry)
                    changed += 1
            if entries:
                s.add(
                    RunLog(
                        run_id=run_id,
                        event="run.cleanup",
                        message=f"marked {changed} cleanup item(s) complete",
                    )
                )
            s.commit()
        return changed

    def create_campaign(
        self,
        campaign_id: str,
        status: str,
        scenario_names: list[str],
        run_ids: list[str],
        *,
        scheduled_at: datetime | None = None,
        repeat_interval_seconds: int | None = None,
        repeat_remaining: int = 0,
    ) -> None:
        with Session(self.engine) as s:
            s.add(
                CampaignRecord(
                    id=campaign_id,
                    status=status,
                    scenario_names_json=json.dumps(scenario_names),
                    run_ids_json=json.dumps(run_ids),
                    scheduled_at=scheduled_at,
                    repeat_interval_seconds=repeat_interval_seconds,
                    repeat_remaining=repeat_remaining,
                )
            )
            s.commit()

    def update_campaign(
        self,
        campaign_id: str,
        *,
        status: str | None = None,
        run_ids: list[str] | None = None,
        scenario_names: list[str] | None = None,
        scheduled_at: datetime | None = None,
        repeat_remaining: int | None = None,
    ) -> None:
        with Session(self.engine) as s:
            record = s.get(CampaignRecord, campaign_id)
            if not record:
                return
            if status is not None:
                record.status = status
            if run_ids is not None:
                record.run_ids_json = json.dumps(run_ids)
            if scenario_names is not None:
                record.scenario_names_json = json.dumps(scenario_names)
            if scheduled_at is not None:
                record.scheduled_at = scheduled_at
            if repeat_remaining is not None:
                record.repeat_remaining = repeat_remaining
            record.updated_at = _now()
            s.add(record)
            s.commit()

    def list_campaigns(self) -> list[CampaignRecord]:
        with Session(self.engine) as s:
            return list(s.exec(select(CampaignRecord).order_by(col(CampaignRecord.created_at).desc())).all())

    @staticmethod
    def _mark_cleanup_complete(session: Session, run_id: str) -> None:
        entries = session.exec(select(QueueEntry).where(QueueEntry.run_id == run_id)).all()
        for entry in entries:
            if entry.cleanup_status == "pending":
                entry.cleanup_status = "complete"
                entry.updated_at = _now()
                session.add(entry)
