from __future__ import annotations

from orchestrator.core.planner import (
    STATUS_FAILED,
    STATUS_SKIPPED,
    STATUS_SUCCESS,
    Planner,
)
from orchestrator.dsl.schema import Scenario, ScenarioStep


def make_scenario() -> Scenario:
    return Scenario(
        name="t",
        steps=[
            ScenarioStep(id="a", ttp="T1033"),
            ScenarioStep(id="b", ttp="T1083", depends_on=["a"]),
            ScenarioStep(id="c", ttp="T1059", depends_on=["a"]),
        ],
    )


def test_dag_dispatch_order() -> None:
    p = Planner()
    run = p.start_run(make_scenario())

    first = p.next_task_for_agent("agent1", "linux")
    assert first is not None
    assert first[1].step.id == "a"

    # Before 'a' completes, b and c should not be dispatched.
    second = p.next_task_for_agent("agent1", "linux")
    assert second is None

    p.report_result(run.id, "a", ok=True, output="", error=None)
    next1 = p.next_task_for_agent("agent1", "linux")
    next2 = p.next_task_for_agent("agent1", "linux")
    assert {next1[1].step.id, next2[1].step.id} == {"b", "c"}


def test_abort_on_fail_skips_dependents() -> None:
    p = Planner()
    sc = Scenario(
        name="t",
        steps=[
            ScenarioStep(id="a", ttp="T1033", abort_on_fail=True),
            ScenarioStep(id="b", ttp="T1083", depends_on=["a"], abort_on_fail=True),
        ],
    )
    run = p.start_run(sc)
    p.next_task_for_agent("agent1", "linux")
    p.report_result(run.id, "a", ok=False, output="", error="boom")
    assert run.steps["a"].status == STATUS_FAILED
    assert run.steps["b"].status == STATUS_SKIPPED


def test_killswitch_aborts_runs() -> None:
    p = Planner()
    p.start_run(make_scenario())
    p.start_run(make_scenario())
    n = p.abort_all(reason="test")
    assert n == 2
    for run in p.list_runs():
        assert run.status == "aborted"
        assert all(s.status != STATUS_SUCCESS for s in run.steps.values())
