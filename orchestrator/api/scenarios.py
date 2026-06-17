"""Scenario endpoints: list, run, get run status."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from ..core.auth import require_role
from ..dsl.schema import Scenario
from ..scenario_builder import build_scenario, build_scenario_batch, scenario_variant_space
from .schemas import RunDetail, RunSummary, ScenarioRunRequest, StepDetail
from .state import get_state


router = APIRouter(tags=["scenarios"])


@router.get("/scenarios")
def list_scenarios(_claims=require_role("viewer")) -> dict[str, dict]:
    s = get_state()
    return {
        name: {
            "name": sc.name,
            "description": sc.description,
            "actor": sc.actor,
            "steps": [{"id": st.id, "ttp": st.ttp} for st in sc.steps],
            "tags": sc.tags,
        }
        for name, sc in s.scenarios.items()
    }


@router.get("/scenario-builder/preview")
def preview_scenario(
    actor: str = Query("cloud-intrusion"),
    difficulty: str = Query("realistic"),
    steps: int = Query(12, ge=1, le=80),
    seed: int = Query(1, ge=0, le=1_000_000),
    platforms: str = Query("windows,linux,darwin"),
    _claims=require_role("viewer"),
) -> dict[str, object]:
    selected_platforms = [item.strip().lower() for item in platforms.split(",") if item.strip()]
    if not selected_platforms:
        raise HTTPException(400, "provide at least one platform")
    try:
        scenario = build_scenario(
            actor=actor,
            difficulty=difficulty,
            steps=steps,
            seed=seed,
            platforms=selected_platforms,
        )
        Scenario(**scenario).validate_dag()
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return scenario


@router.get("/scenario-builder/space")
def scenario_builder_space(_claims=require_role("viewer")) -> dict[str, object]:
    return scenario_variant_space()


@router.get("/scenario-builder/batch-preview")
def preview_scenario_batch(
    count: int = Query(25, ge=1, le=200),
    offset: int = Query(0, ge=0),
    stride: int = Query(1, ge=1),
    _claims=require_role("viewer"),
) -> dict[str, object]:
    try:
        scenarios = build_scenario_batch(count=count, offset=offset, stride=stride, max_count=200)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    for scenario in scenarios:
        Scenario(**scenario).validate_dag()
    return {
        "offset": offset,
        "stride": stride,
        "count": len(scenarios),
        "space": scenario_variant_space(),
        "scenarios": scenarios,
    }


@router.post("/scenarios/run", response_model=RunSummary)
def run_scenario(req: ScenarioRunRequest, _claims=require_role("operator")) -> RunSummary:
    s = get_state()
    if s.killswitch.is_active():
        raise HTTPException(409, f"killswitch active: {s.killswitch.reason()}")
    if req.name:
        scenario = s.scenarios.get(req.name)
        if not scenario:
            raise HTTPException(404, f"scenario '{req.name}' not found")
    elif req.inline:
        scenario = Scenario(**req.inline)
        scenario.validate_dag()
    else:
        raise HTTPException(400, "provide either 'name' or 'inline'")

    run = s.planner.start_run(scenario)
    if s.repo:
        s.repo.create_run(
            run_id=run.id,
            scenario_name=scenario.name,
            steps=[(st.id, st.ttp) for st in scenario.steps],
        )
    s.audit.append("run.start", {"run_id": run.id, "scenario": scenario.name})
    return _summarize(run)


@router.get("/runs")
def list_runs(_claims=require_role("viewer")) -> list[RunSummary]:
    return [_summarize(r) for r in get_state().planner.list_runs()]


@router.get("/runs/{run_id}", response_model=RunSummary)
def get_run(run_id: str, _claims=require_role("viewer")) -> RunSummary:
    run = get_state().planner.get_run(run_id)
    if not run:
        raise HTTPException(404, "run not found")
    return _summarize(run)


@router.get("/runs/{run_id}/steps", response_model=RunDetail)
def get_run_steps(run_id: str, _claims=require_role("viewer")) -> RunDetail:
    """Return full per-step detail for a run (status, output, error, timing)."""
    run = get_state().planner.get_run(run_id)
    if not run:
        raise HTTPException(404, "run not found")
    steps = [
        StepDetail(
            id=sid,
            attack_id=st.step.ttp,
            status=st.status,
            agent_id=st.assigned_agent,
            started_at=st.started_at,
            finished_at=st.finished_at,
            output=st.output,
            error=st.error,
        )
        for sid, st in run.steps.items()
    ]
    return RunDetail(
        id=run.id,
        scenario=run.scenario.name,
        status=run.status,
        started_at=run.started_at,
        steps=steps,
    )


def _summarize(run) -> RunSummary:
    return RunSummary(
        id=run.id,
        scenario=run.scenario.name,
        status=run.status,
        started_at=run.started_at,
        finished_at=run.finished_at,
        step_summary={sid: st.status for sid, st in run.steps.items()},
    )
