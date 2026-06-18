"""Scenario endpoints: list, run, get run status."""
from __future__ import annotations

import html
import io
import json
import time
import uuid
import zipfile
from datetime import datetime, timezone
from typing import Any, cast

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse, Response

from ..core.auth import require_role
from ..dsl.schema import Scenario
from ..scenario_builder import (
    DIFFICULTY_STEPS,
    build_scenario,
    build_scenario_batch,
    scenario_variant_space,
)
from .schemas import (
    CampaignRunRequest,
    CampaignSummary,
    RunDetail,
    RunSummary,
    ScenarioRunRequest,
    StepDetail,
)
from .state import get_state


router = APIRouter(tags=["scenarios"])


def _scenario_library_entry(name: str, scenario: Scenario) -> dict[str, object]:
    tags = list(scenario.tags or [])
    tag_set = set(tags)
    if "validated" in tag_set:
        kind = "validated actor-chain"
        source = "validated YAML"
    elif "variant" in tag_set:
        kind = "generated variant"
        source = "generated YAML"
    elif "ael_import" in tag_set or "source_ael" in tag_set:
        kind = "emulation plan"
        source = "emulation library"
    else:
        kind = "static"
        source = "static"
    difficulty = next((tag for tag in tags if tag in DIFFICULTY_STEPS), None)
    ttps = sorted({step.ttp for step in scenario.steps})
    return {
        "name": name,
        "description": scenario.description,
        "actor": scenario.actor or "",
        "difficulty": difficulty or "",
        "platforms": list(scenario.target_platforms),
        "step_count": len(scenario.steps),
        "source": source,
        "kind": kind,
        "tags": tags,
        "ttps": ttps,
    }


def _scenario_library_items() -> list[dict[str, object]]:
    s = get_state()
    return [
        _scenario_library_entry(name, scenario)
        for name, scenario in sorted(s.scenarios.items(), key=lambda item: item[0])
    ]


def _matches_filter(
    item: dict[str, object],
    *,
    actor: str | None = None,
    difficulty: str | None = None,
    platform: str | None = None,
    source: str | None = None,
    min_steps: int | None = None,
    max_steps: int | None = None,
) -> bool:
    if actor and item["actor"] != actor:
        return False
    if difficulty and item["difficulty"] != difficulty:
        return False
    platforms = cast(list[str], item["platforms"])
    if platform and platform not in platforms:
        return False
    if source:
        selected = source.lower()
        item_source = str(item["source"]).lower()
        item_kind = str(item["kind"]).lower()
        if selected in {"generated", "generated variant"}:
            if item["kind"] != "generated variant":
                return False
        elif selected in {"validated", "validated actor-chain"}:
            if item["kind"] != "validated actor-chain":
                return False
        elif selected not in {item_source, item_kind}:
            return False
    step_count = cast(int, item["step_count"])
    if min_steps is not None and step_count < min_steps:
        return False
    if max_steps is not None and step_count > max_steps:
        return False
    return True


def _library_counts(items: list[dict[str, object]]) -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = {
        "actors": {},
        "difficulties": {},
        "platforms": {},
        "sources": {},
        "kinds": {},
    }
    for item in items:
        for key, bucket in [("actor", "actors"), ("difficulty", "difficulties")]:
            value = str(item[key] or "unknown")
            counts[bucket][value] = counts[bucket].get(value, 0) + 1
        for platform in cast(list[str], item["platforms"]):
            value = str(platform)
            counts["platforms"][value] = counts["platforms"].get(value, 0) + 1
        for key, bucket in [("source", "sources"), ("kind", "kinds")]:
            value = str(item[key])
            counts[bucket][value] = counts[bucket].get(value, 0) + 1
    return counts


def _start_run(s, scenario: Scenario) -> Any:
    run = s.planner.start_run(scenario)
    if s.repo:
        s.repo.create_run(
            run_id=run.id,
            scenario_name=scenario.name,
            steps=[(st.id, st.ttp) for st in scenario.steps],
            target_platforms=list(scenario.target_platforms),
        )
    s.audit.append("run.start", {"run_id": run.id, "scenario": scenario.name})
    return run


def _select_campaign_names(req: CampaignRunRequest) -> list[str]:
    s = get_state()
    if req.scenario_names:
        names = [name for name in req.scenario_names if name in s.scenarios]
    else:
        names = [
            str(item["name"])
            for item in _scenario_library_items()
            if _matches_filter(
                item,
                actor=req.actor,
                difficulty=req.difficulty,
                platform=req.platform,
                source=req.source,
                min_steps=req.min_steps,
                max_steps=req.max_steps,
            )
        ]
    return names[: req.count]


def _launch_campaign_runs(record: dict[str, Any]) -> list[str]:
    s = get_state()
    launched = [_start_run(s, s.scenarios[name]).id for name in record["scenario_names"] if name in s.scenarios]
    record["run_ids"].extend(launched)
    record["status"] = "running"
    record["updated_at"] = time.time()
    if int(record.get("repeat_remaining", 0)) > 0:
        record["repeat_remaining"] = int(record["repeat_remaining"]) - 1
    if s.repo:
        s.repo.update_campaign(
            str(record["id"]),
            status=str(record["status"]),
            run_ids=[str(run_id) for run_id in record["run_ids"]],
            scenario_names=[str(name) for name in record["scenario_names"]],
            repeat_remaining=int(record.get("repeat_remaining", 0)),
        )
    s.audit.append("campaign.launch", {"campaign_id": record["id"], "runs": len(launched)})
    return launched


def tick_scheduled_campaigns() -> None:
    """Start due scheduled campaigns and requeue repeat campaigns."""
    s = get_state()
    now = time.time()
    for record in list(s.campaigns.values()):
        status = str(record.get("status"))
        if status == "scheduled" and float(record.get("scheduled_at") or 0) <= now:
            _launch_campaign_runs(record)
            continue
        if status != "running":
            continue
        interval = record.get("repeat_interval_seconds")
        if not interval or int(record.get("repeat_remaining", 0)) <= 0:
            continue
        runs = [s.planner.get_run(str(run_id)) for run_id in record["run_ids"]]
        if runs and all(run and run.status in {"completed", "failed", "aborted"} for run in runs):
            record["status"] = "scheduled"
            record["scheduled_at"] = now + int(interval)
            record["updated_at"] = now
            s.audit.append(
                "campaign.repeat_scheduled",
                {"campaign_id": record["id"], "scheduled_at": record["scheduled_at"]},
            )


@router.get("/scenarios")
def list_scenarios(_claims=require_role("viewer")) -> dict[str, dict]:
    s = get_state()
    return {
        name: {
            "name": sc.name,
            "description": sc.description,
            "actor": sc.actor,
            "difficulty": _scenario_library_entry(name, sc)["difficulty"],
            "platforms": list(sc.target_platforms),
            "step_count": len(sc.steps),
            "source": _scenario_library_entry(name, sc)["source"],
            "kind": _scenario_library_entry(name, sc)["kind"],
            "steps": [{"id": st.id, "ttp": st.ttp} for st in sc.steps],
            "tags": sc.tags,
        }
        for name, sc in s.scenarios.items()
    }


@router.get("/scenario-library")
def scenario_library(
    actor: str | None = None,
    difficulty: str | None = None,
    platform: str | None = None,
    source: str | None = None,
    min_steps: int | None = Query(None, ge=1),
    max_steps: int | None = Query(None, ge=1),
    _claims=require_role("viewer"),
) -> dict[str, object]:
    items = _scenario_library_items()
    filtered = [
        item
        for item in items
        if _matches_filter(
            item,
            actor=actor,
            difficulty=difficulty,
            platform=platform,
            source=source,
            min_steps=min_steps,
            max_steps=max_steps,
        )
    ]
    return {
        "total": len(items),
        "filtered": len(filtered),
        "counts": _library_counts(items),
        "items": filtered,
    }


@router.get("/reports/scenarios/{scenario_name}.json")
def scenario_report_json(scenario_name: str, _claims=require_role("viewer")) -> dict[str, object]:
    s = get_state()
    scenario = s.scenarios.get(scenario_name)
    if not scenario:
        raise HTTPException(404, "scenario not found")
    from ..scenario_maturity import (
        load_evidence,
        load_golden_events,
        scenario_evidence,
        scenario_maturity_item,
    )

    evidence_by_name = load_evidence()
    golden_events_by_name = load_golden_events()
    return {
        "scenario": scenario.model_dump(),
        "maturity": scenario_maturity_item(
            scenario_name,
            scenario,
            evidence_by_name=evidence_by_name,
            golden_events_by_name=golden_events_by_name,
        ),
        "evidence": scenario_evidence(scenario_name),
    }


@router.get("/reports/scenarios/{scenario_name}.html", response_class=HTMLResponse)
def scenario_report_html(scenario_name: str, _claims=require_role("viewer")) -> HTMLResponse:
    return HTMLResponse(_report_html(scenario_report_json(scenario_name), f"Scenario {scenario_name}"))


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

    run = _start_run(s, scenario)
    return _summarize(run)


@router.post("/campaigns/run", response_model=CampaignSummary)
def run_campaign(req: CampaignRunRequest, _claims=require_role("operator")) -> CampaignSummary:
    s = get_state()
    if s.killswitch.is_active():
        raise HTTPException(409, f"killswitch active: {s.killswitch.reason()}")
    selected = _select_campaign_names(req)
    if not selected:
        raise HTTPException(404, "no scenarios matched campaign request")

    now = time.time()
    campaign_id = uuid.uuid4().hex[:12]
    scheduled_at = req.scheduled_at if req.scheduled_at and req.scheduled_at > now else None
    record: dict[str, Any] = {
        "id": campaign_id,
        "status": "scheduled" if scheduled_at else "running",
        "created_at": now,
        "updated_at": now,
        "scenario_names": selected,
        "run_ids": [],
        "scheduled_at": scheduled_at,
        "repeat_interval_seconds": req.repeat_interval_seconds,
        "repeat_remaining": req.repeat_count,
    }
    s.campaigns[campaign_id] = record
    if scheduled_at:
        s.audit.append("campaign.schedule", {"campaign_id": campaign_id, "scheduled_at": scheduled_at})
    else:
        _launch_campaign_runs(record)
        s.audit.append("campaign.start", {"campaign_id": campaign_id, "runs": len(record["run_ids"])})
    if s.repo:
        s.repo.create_campaign(
            campaign_id,
            str(record["status"]),
            [str(name) for name in record["scenario_names"]],
            [str(run_id) for run_id in record["run_ids"]],
            scheduled_at=_datetime_from_ts(scheduled_at),
            repeat_interval_seconds=req.repeat_interval_seconds,
            repeat_remaining=int(record.get("repeat_remaining", 0)),
        )
    return _campaign_summary(record)


@router.get("/campaigns", response_model=list[CampaignSummary])
def list_campaigns(_claims=require_role("viewer")) -> list[CampaignSummary]:
    tick_scheduled_campaigns()
    return [_campaign_summary(record) for record in get_state().campaigns.values()]


@router.get("/campaigns/{campaign_id}", response_model=CampaignSummary)
def get_campaign(campaign_id: str, _claims=require_role("viewer")) -> CampaignSummary:
    tick_scheduled_campaigns()
    return _campaign_summary(_campaign_record(campaign_id))


@router.post("/campaigns/{campaign_id}/pause", response_model=CampaignSummary)
def pause_campaign(campaign_id: str, _claims=require_role("operator")) -> CampaignSummary:
    s = get_state()
    record = _campaign_record(campaign_id)
    s.planner.pause_runs(list(record["run_ids"]))
    record["status"] = "paused"
    record["updated_at"] = time.time()
    if s.repo:
        s.repo.update_campaign(campaign_id, status="paused")
    s.audit.append("campaign.pause", {"campaign_id": campaign_id})
    return _campaign_summary(record)


@router.post("/campaigns/{campaign_id}/resume", response_model=CampaignSummary)
def resume_campaign(campaign_id: str, _claims=require_role("operator")) -> CampaignSummary:
    s = get_state()
    record = _campaign_record(campaign_id)
    s.planner.resume_runs(list(record["run_ids"]))
    record["status"] = "scheduled" if record.get("scheduled_at") else "running"
    record["updated_at"] = time.time()
    if s.repo:
        s.repo.update_campaign(campaign_id, status=str(record["status"]))
    s.audit.append("campaign.resume", {"campaign_id": campaign_id})
    return _campaign_summary(record)


@router.post("/campaigns/{campaign_id}/retry-failed", response_model=CampaignSummary)
def retry_failed_campaign(campaign_id: str, _claims=require_role("operator")) -> CampaignSummary:
    s = get_state()
    record = _campaign_record(campaign_id)
    added = []
    for run_id in list(record["run_ids"]):
        run = s.planner.get_run(str(run_id))
        if run and run.status == "failed":
            retry = _start_run(s, run.scenario)
            added.append(retry.id)
            record["scenario_names"].append(run.scenario.name)
    record["run_ids"].extend(added)
    record["status"] = "running" if added else record["status"]
    record["updated_at"] = time.time()
    if s.repo:
        s.repo.update_campaign(
            campaign_id,
            status=str(record["status"]),
            run_ids=[str(run_id) for run_id in record["run_ids"]],
            scenario_names=[str(name) for name in record["scenario_names"]],
        )
    s.audit.append("campaign.retry_failed", {"campaign_id": campaign_id, "added_runs": len(added)})
    return _campaign_summary(record)


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


@router.get("/reports/runs/{run_id}.json")
def run_report_json(run_id: str, _claims=require_role("viewer")) -> dict[str, object]:
    s = get_state()
    run = s.planner.get_run(run_id)
    if run:
        return _run_report(run)
    if s.repo and s.repo.get_run(run_id):
        return _stored_run_report(run_id)
    raise HTTPException(404, "run not found")


@router.get("/reports/runs/{run_id}.zip")
def run_report_zip(run_id: str, _claims=require_role("viewer")) -> Response:
    report = run_report_json(run_id)
    bundle = io.BytesIO()
    with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("report.json", json.dumps(report, indent=2, sort_keys=True))
        archive.writestr("report.html", _report_html(report, f"Run {run_id}"))
        archive.writestr("cleanup.json", json.dumps(cleanup_plan(run_id), indent=2, sort_keys=True))
        if get_state().repo:
            archive.writestr("history.json", json.dumps(run_history_detail(run_id), indent=2, sort_keys=True))
    return Response(
        bundle.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{run_id}-artifacts.zip"'},
    )


@router.get("/history/runs")
def run_history(_claims=require_role("viewer")) -> dict[str, object]:
    s = get_state()
    if not s.repo:
        return {"total": 0, "items": []}
    items = []
    for run in s.repo.list_runs():
        steps = s.repo.steps_for_run(run.id)
        artifacts = s.repo.artifacts_for_run(run.id)
        logs = s.repo.logs_for_run(run.id)
        items.append(
            {
                "id": run.id,
                "scenario": run.scenario_name,
                "status": run.status,
                "started_at": _timestamp(run.started_at),
                "finished_at": _timestamp(run.finished_at),
                "step_count": len(steps),
                "artifact_count": len(artifacts),
                "log_count": len(logs),
            }
        )
    return {"total": len(items), "items": items}


@router.get("/history/runs/{run_id}")
def run_history_detail(run_id: str, _claims=require_role("viewer")) -> dict[str, object]:
    s = get_state()
    if not s.repo:
        raise HTTPException(404, "history store unavailable")
    run = s.repo.get_run(run_id)
    if not run:
        raise HTTPException(404, "run not found")
    steps = [
        {
            "step_id": step.step_id,
            "attack_id": step.attack_id,
            "agent_id": step.agent_id,
            "status": step.status,
            "created_at": _timestamp(step.created_at),
            "started_at": _timestamp(step.started_at),
            "finished_at": _timestamp(step.finished_at),
            "output": step.output,
            "error": step.error,
        }
        for step in s.repo.steps_for_run(run_id)
    ]
    logs = [
        {
            "id": log.id,
            "step_id": log.step_id,
            "level": log.level,
            "event": log.event,
            "message": log.message,
            "created_at": _timestamp(log.created_at),
        }
        for log in s.repo.logs_for_run(run_id)
    ]
    artifacts = [
        {
            "kind": artifact.kind,
            "name": artifact.name,
            "path": artifact.path,
            "metadata": json.loads(artifact.metadata_json or "{}"),
            "created_at": _timestamp(artifact.created_at),
        }
        for artifact in s.repo.artifacts_for_run(run_id)
    ]
    queue = [_queue_entry(item) for item in s.repo.queue_entries(run_id)]
    return {
        "id": run.id,
        "scenario": run.scenario_name,
        "status": run.status,
        "started_at": _timestamp(run.started_at),
        "finished_at": _timestamp(run.finished_at),
        "steps": steps,
        "queue": queue,
        "logs": logs,
        "artifacts": artifacts,
    }


@router.get("/execution/queue")
def execution_queue(run_id: str | None = None, _claims=require_role("viewer")) -> dict[str, object]:
    s = get_state()
    if not s.repo:
        return {"total": 0, "items": []}
    items = [_queue_entry(item) for item in s.repo.queue_entries(run_id)]
    return {"total": len(items), "items": items}


@router.get("/execution/artifacts/{run_id}.zip")
def execution_artifact_zip(run_id: str, _claims=require_role("viewer")) -> Response:
    return run_report_zip(run_id)


@router.get("/runs/{run_id}/cleanup-plan")
def cleanup_plan(run_id: str, _claims=require_role("viewer")) -> dict[str, object]:
    s = get_state()
    if not s.repo or not s.repo.get_run(run_id):
        if not s.planner.get_run(run_id):
            raise HTTPException(404, "run not found")
        return {"run_id": run_id, "policy": "memory-run", "items": []}
    items = [
        {
            "step_id": item.step_id,
            "attack_id": item.attack_id,
            "cleanup_required": item.cleanup_required,
            "cleanup_status": item.cleanup_status,
            "status": item.status,
            "attempt": item.attempt,
        }
        for item in s.repo.queue_entries(run_id)
    ]
    pending = [item for item in items if item["cleanup_required"] and item["cleanup_status"] == "pending"]
    return {
        "run_id": run_id,
        "policy": "record-and-close-terminal-steps",
        "status": "pending" if pending else "complete",
        "pending_count": len(pending),
        "items": items,
    }


@router.get("/reports/runs/{run_id}.html", response_class=HTMLResponse)
def run_report_html(run_id: str, _claims=require_role("viewer")) -> HTMLResponse:
    return HTMLResponse(_report_html(run_report_json(run_id), f"Run {run_id}"))


@router.get("/reports/campaigns/{campaign_id}.json")
def campaign_report_json(campaign_id: str, _claims=require_role("viewer")) -> dict[str, object]:
    record = _campaign_record(campaign_id)
    runs = [
        run for run_id in record["run_ids"]
        if (run := get_state().planner.get_run(str(run_id))) is not None
    ]
    run_reports = [_run_report(run) for run in runs]
    all_ttps_set: set[str] = set()
    touched_set: set[str] = set()
    gaps_set: set[str] = set()
    for report in run_reports:
        all_ttps_set.update(cast(list[str], report["ttps_covered"]))
        touched_set.update(cast(list[str], report["detections_touched"]))
        gaps_set.update(cast(list[str], report["detection_gaps"]))
    all_ttps = sorted(all_ttps_set)
    touched = sorted(touched_set)
    gaps = sorted(gaps_set)
    statuses: dict[str, int] = {}
    for run in runs:
        statuses[run.status] = statuses.get(run.status, 0) + 1
    return {
        "campaign": _campaign_summary(record).model_dump(),
        "scenarios_total": len(record["scenario_names"]),
        "run_statuses": statuses,
        "ttps_covered_count": len(all_ttps),
        "ttps_covered": all_ttps,
        "detections_touched_count": len(touched),
        "detections_touched": touched,
        "detection_gaps": gaps,
        "runs": run_reports,
    }


@router.get("/reports/campaigns/{campaign_id}.html", response_class=HTMLResponse)
def campaign_report_html(campaign_id: str, _claims=require_role("viewer")) -> HTMLResponse:
    return HTMLResponse(_report_html(campaign_report_json(campaign_id), f"Campaign {campaign_id}"))


def _campaign_record(campaign_id: str) -> dict[str, Any]:
    record = get_state().campaigns.get(campaign_id)
    if not record:
        raise HTTPException(404, "campaign not found")
    return record


def _campaign_summary(record: dict[str, Any]) -> CampaignSummary:
    planner = get_state().planner
    run_statuses: dict[str, int] = {}
    terminal = 0
    for run_id in record["run_ids"]:
        run = planner.get_run(str(run_id))
        status = run.status if run else "missing"
        run_statuses[status] = run_statuses.get(status, 0) + 1
        if status in {"completed", "failed", "aborted"}:
            terminal += 1
    total = len(record["run_ids"])
    status = str(record["status"])
    if status == "scheduled" and not total:
        total = len(record["scenario_names"])
    if status not in {"paused", "scheduled"} and total and terminal == total:
        status = "failed" if run_statuses.get("failed") else "completed"
        record["status"] = status
    return CampaignSummary(
        id=str(record["id"]),
        status=status,
        created_at=float(record["created_at"]),
        updated_at=float(record["updated_at"]),
        total_runs=total,
        progress_percent=round((terminal / total) * 100, 2) if total else 0,
        run_statuses=run_statuses,
        scenario_names=[str(name) for name in record["scenario_names"]],
        run_ids=[str(run_id) for run_id in record["run_ids"]],
        scheduled_at=record.get("scheduled_at"),
        repeat_interval_seconds=record.get("repeat_interval_seconds"),
        repeat_remaining=int(record.get("repeat_remaining", 0)),
    )


def _stored_run_report(run_id: str) -> dict[str, object]:
    s = get_state()
    if not s.repo:
        raise HTTPException(404, "history store unavailable")
    run = s.repo.get_run(run_id)
    if not run:
        raise HTTPException(404, "run not found")
    steps = s.repo.steps_for_run(run_id)
    covered = sorted({step.attack_id for step in steps})
    touched = []
    gaps = []
    import ttps  # noqa: F401
    from ttps.base import registry

    for attack_id in covered:
        ttp = registry.get(attack_id) or registry.get(attack_id.split(":", 1)[0])
        if ttp and ttp.sigma_rule() is not None:
            touched.append(attack_id)
        else:
            gaps.append(attack_id)
    step_statuses: dict[str, int] = {}
    for step in steps:
        step_statuses[step.status] = step_statuses.get(step.status, 0) + 1
    return {
        "run_id": run.id,
        "scenario": run.scenario_name,
        "status": run.status,
        "started_at": _timestamp(run.started_at),
        "finished_at": _timestamp(run.finished_at),
        "step_statuses": step_statuses,
        "steps_total": len(steps),
        "ttps_covered_count": len(covered),
        "ttps_covered": covered,
        "detections_touched_count": len(touched),
        "detections_touched": touched,
        "detection_gaps": gaps,
        "artifacts": [artifact.path for artifact in s.repo.artifacts_for_run(run_id)],
        "cleanup": cleanup_plan(run_id),
    }


def _run_report(run) -> dict[str, object]:
    import ttps  # noqa: F401
    from ttps.base import registry

    step_statuses: dict[str, int] = {}
    covered = sorted({state.step.ttp for state in run.steps.values()})
    touched = []
    gaps = []
    for attack_id in covered:
        ttp = registry.get(attack_id)
        if ttp and ttp.sigma_rule() is not None:
            touched.append(attack_id)
        else:
            gaps.append(attack_id)
    for state in run.steps.values():
        step_statuses[state.status] = step_statuses.get(state.status, 0) + 1
    return {
        "run_id": run.id,
        "scenario": run.scenario.name,
        "status": run.status,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "step_statuses": step_statuses,
        "steps_total": len(run.steps),
        "ttps_covered_count": len(covered),
        "ttps_covered": covered,
        "detections_touched_count": len(touched),
        "detections_touched": touched,
        "detection_gaps": gaps,
        "cleanup": cleanup_plan(run.id),
    }


def _report_html(data: dict[str, object], title: str) -> str:
    rows = []
    for key, value in data.items():
        if isinstance(value, (dict, list)):
            rendered = html.escape(str(value))
        else:
            rendered = html.escape(str(value))
        rows.append(f"<tr><th>{html.escape(str(key))}</th><td>{rendered}</td></tr>")
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        f"<title>{html.escape(title)}</title>"
        "<style>body{font-family:system-ui;margin:24px;}"
        "table{border-collapse:collapse;width:100%;}"
        "th,td{border:1px solid #ddd;padding:8px;text-align:left;vertical-align:top;}"
        "th{width:220px;background:#f5f5f5;}</style></head><body>"
        f"<h1>{html.escape(title)}</h1><table>{''.join(rows)}</table></body></html>"
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


def _timestamp(value: datetime | None) -> float | None:
    if value is None:
        return None
    return value.timestamp()


def _datetime_from_ts(value: float | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromtimestamp(value, tz=timezone.utc)


def _queue_entry(item) -> dict[str, object]:
    return {
        "run_id": item.run_id,
        "step_id": item.step_id,
        "attack_id": item.attack_id,
        "status": item.status,
        "assigned_agent": item.assigned_agent,
        "target_platforms": json.loads(item.target_platforms_json or "[]"),
        "attempt": item.attempt,
        "max_attempts": item.max_attempts,
        "cleanup_required": item.cleanup_required,
        "cleanup_status": item.cleanup_status,
        "created_at": _timestamp(item.created_at),
        "updated_at": _timestamp(item.updated_at),
        "next_attempt_at": _timestamp(item.next_attempt_at),
        "last_error": item.last_error,
    }
