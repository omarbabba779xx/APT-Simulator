from __future__ import annotations

from pathlib import Path

from orchestrator.storage.db import Repository, init_engine


def test_repository_round_trip(tmp_path: Path) -> None:
    engine = init_engine(tmp_path / "test.db")
    repo = Repository(engine)

    repo.upsert_agent("a1", "host1", "linux", 1234)
    agents = repo.list_agents()
    assert len(agents) == 1
    assert agents[0].id == "a1"

    repo.create_run("r1", "demo_scenario", [("s1", "T1033"), ("s2", "T1083")])
    runs = repo.list_runs()
    assert len(runs) == 1
    assert runs[0].id == "r1"

    repo.update_step("r1", "s1", "dispatched", agent_id="a1", mark_started=True)
    repo.update_step("r1", "s1", "success", output="ok", mark_finished=True)
    repo.update_step("r1", "s2", "failed", error="boom", mark_finished=True)
    repo.update_run_status("r1", "failed", finished=True)

    steps = repo.steps_for_run("r1")
    statuses = {s.step_id: s.status for s in steps}
    assert statuses == {"s1": "success", "s2": "failed"}
    assert next(s for s in steps if s.step_id == "s1").started_at is not None
    assert next(s for s in steps if s.step_id == "s2").error == "boom"


def test_upsert_agent_idempotent(tmp_path: Path) -> None:
    engine = init_engine(tmp_path / "test.db")
    repo = Repository(engine)
    repo.upsert_agent("a1", "host1", "linux", 1)
    repo.upsert_agent("a1", "host1-renamed", "linux", 2)
    agents = repo.list_agents()
    assert len(agents) == 1
    assert agents[0].hostname == "host1-renamed"
    assert agents[0].pid == 2
