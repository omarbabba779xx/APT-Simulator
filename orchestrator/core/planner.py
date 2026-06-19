"""In-memory scenario planner.

A Run wraps one execution of a Scenario. Steps are dispatched to agents
respecting the dependency DAG. Killswitch aborts every active run within one
beacon cycle.
"""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

from ..dsl.schema import Scenario, ScenarioStep


STATUS_QUEUED = "queued"
STATUS_DISPATCHED = "dispatched"
STATUS_RUNNING = "running"
STATUS_SUCCESS = "success"
STATUS_FAILED = "failed"
STATUS_SKIPPED = "skipped"
STATUS_ABORTED = "aborted"


@dataclass
class StepState:
    step: ScenarioStep
    status: str = STATUS_QUEUED
    assigned_agent: Optional[str] = None
    output: str = ""
    error: Optional[str] = None
    started_at: float = 0.0
    finished_at: float = 0.0


@dataclass
class Run:
    id: str
    scenario: Scenario
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    status: str = "running"  # running, completed, failed, aborted
    steps: dict[str, StepState] = field(default_factory=dict)

    def is_step_ready(self, step_id: str) -> bool:
        st = self.steps[step_id]
        if st.status != STATUS_QUEUED:
            return False
        for dep in st.step.depends_on:
            dep_state = self.steps[dep].status
            if dep_state == STATUS_FAILED and st.step.abort_on_fail:
                return False
            if dep_state not in (STATUS_SUCCESS, STATUS_SKIPPED):
                return False
        return True

    def all_terminal(self) -> bool:
        terminal = {STATUS_SUCCESS, STATUS_FAILED, STATUS_SKIPPED, STATUS_ABORTED}
        return all(s.status in terminal for s in self.steps.values())

    def has_failure(self) -> bool:
        return any(s.status == STATUS_FAILED for s in self.steps.values())


class Planner:
    def __init__(self) -> None:
        self._runs: dict[str, Run] = {}
        self._lock = threading.Lock()

    def start_run(self, scenario: Scenario) -> Run:
        scenario.validate_dag()
        run = Run(
            id=uuid.uuid4().hex[:12],
            scenario=scenario,
            steps={s.id: StepState(step=s) for s in scenario.steps},
        )
        with self._lock:
            self._runs[run.id] = run
        return run

    def get_run(self, run_id: str) -> Run | None:
        with self._lock:
            return self._runs.get(run_id)

    def list_runs(self) -> list[Run]:
        with self._lock:
            return list(self._runs.values())

    def pause_runs(self, run_ids: list[str]) -> int:
        changed = 0
        with self._lock:
            for run_id in run_ids:
                run = self._runs.get(run_id)
                if run and run.status == "running":
                    run.status = "paused"
                    changed += 1
        return changed

    def resume_runs(self, run_ids: list[str]) -> int:
        changed = 0
        with self._lock:
            for run_id in run_ids:
                run = self._runs.get(run_id)
                if run and run.status == "paused":
                    run.status = "running"
                    changed += 1
        return changed

    def retry_failed_steps(self, run_id: str) -> int:
        """Reset failed/skipped/aborted steps so a lab operator can retry a run."""
        changed = 0
        retryable = {STATUS_FAILED, STATUS_SKIPPED, STATUS_ABORTED}
        with self._lock:
            run = self._runs.get(run_id)
            if not run:
                return 0
            for state in run.steps.values():
                if state.status not in retryable:
                    continue
                state.status = STATUS_QUEUED
                state.assigned_agent = None
                state.output = ""
                state.error = None
                state.started_at = 0.0
                state.finished_at = 0.0
                changed += 1
            if changed:
                run.status = "running"
                run.finished_at = 0.0
        return changed

    def next_task_for_agent(self, agent_id: str, agent_platform: str) -> tuple[Run, StepState] | None:
        """Return the next ready step for this agent, or None."""
        platform = agent_platform.lower()
        with self._lock:
            for run in self._runs.values():
                if run.status != "running":
                    continue
                if "any" not in run.scenario.target_platforms and platform not in run.scenario.target_platforms:
                    continue
                for step_id, state in run.steps.items():
                    if not run.is_step_ready(step_id):
                        continue
                    state.status = STATUS_DISPATCHED
                    state.assigned_agent = agent_id
                    state.started_at = time.time()
                    return run, state
        return None

    def report_result(
        self,
        run_id: str,
        step_id: str,
        ok: bool,
        output: str,
        error: str | None,
    ) -> None:
        with self._lock:
            run = self._runs.get(run_id)
            if not run:
                return
            state = run.steps.get(step_id)
            if not state:
                return
            state.status = STATUS_SUCCESS if ok else STATUS_FAILED
            state.output = output
            state.error = error
            state.finished_at = time.time()
            # Cascade abort if abort_on_fail.
            if not ok and state.step.abort_on_fail:
                for s in run.steps.values():
                    if s.status == STATUS_QUEUED:
                        s.status = STATUS_SKIPPED
            if run.all_terminal():
                run.status = "failed" if run.has_failure() else "completed"
                run.finished_at = time.time()

    def abort_all(self, reason: str = "killswitch") -> int:
        n = 0
        with self._lock:
            for run in self._runs.values():
                if run.status == "running":
                    run.status = "aborted"
                    run.finished_at = time.time()
                    for s in run.steps.values():
                        if s.status in (STATUS_QUEUED, STATUS_DISPATCHED, STATUS_RUNNING):
                            s.status = STATUS_ABORTED
                            s.error = reason
                            s.finished_at = time.time()
                    n += 1
        return n
