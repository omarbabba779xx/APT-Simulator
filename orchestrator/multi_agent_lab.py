"""Reproducible local multi-agent lab smoke."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from .api.state import AppState
from .dsl.schema import Platform, Scenario, ScenarioStep


LAB_AGENTS: tuple[tuple[Platform, str], ...] = (
    ("windows", "lab-win-01"),
    ("linux", "lab-linux-01"),
    ("darwin", "lab-mac-01"),
)


def build_multi_agent_smoke_scenario() -> Scenario:
    return Scenario(
        name="multi_agent_dispatch_smoke",
        description="Local lab smoke that proves multiple agents can receive independent DAG steps.",
        target_platforms=["windows", "linux", "darwin"],
        actor="lab-validation",
        tags=["multi_agent_lab", "smoke", "validated"],
        steps=[
            ScenarioStep(id="windows_identity", ttp="T1033", params={"dry_run": True}, abort_on_fail=False),
            ScenarioStep(id="linux_files", ttp="T1083", params={"dry_run": True}, abort_on_fail=False),
            ScenarioStep(id="darwin_process", ttp="T1057", params={"dry_run": True}, abort_on_fail=False),
        ],
    )


def run_multi_agent_smoke(state: AppState) -> dict[str, Any]:
    scenario = build_multi_agent_smoke_scenario()
    scenario.validate_dag()
    run = state.planner.start_run(scenario)
    if state.repo:
        state.repo.create_run(
            run.id,
            scenario.name,
            [(step.id, step.ttp) for step in scenario.steps],
            target_platforms=list(scenario.target_platforms),
        )

    registered_agents = []
    dispatches = []
    for platform, hostname in LAB_AGENTS:
        agent_id = f"lab-{platform}-{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc).isoformat()
        state.agents[agent_id] = {
            "hostname": hostname,
            "platform": platform,
            "pid": 0,
            "registered_at": now,
            "last_seen": now,
            "lab_smoke": True,
        }
        if state.repo:
            state.repo.upsert_agent(agent_id, hostname, platform, 0)
        registered_agents.append({"agent_id": agent_id, "hostname": hostname, "platform": platform})

        task = state.planner.next_task_for_agent(agent_id, platform)
        if not task:
            dispatches.append({"agent_id": agent_id, "platform": platform, "task": None})
            continue
        assigned_run, step_state = task
        if state.repo:
            state.repo.update_step(
                assigned_run.id,
                step_state.step.id,
                "dispatched",
                agent_id=agent_id,
                mark_started=True,
            )
        output = f"lab smoke completed by {agent_id} on {platform}"
        state.planner.report_result(assigned_run.id, step_state.step.id, True, output, None)
        if state.repo:
            state.repo.update_step(
                assigned_run.id,
                step_state.step.id,
                "success",
                agent_id=agent_id,
                output=output,
                mark_finished=True,
            )
        dispatches.append(
            {
                "agent_id": agent_id,
                "platform": platform,
                "run_id": assigned_run.id,
                "step_id": step_state.step.id,
                "attack_id": step_state.step.ttp,
                "status": "success",
            }
        )

    if state.repo and run.status != "running":
        state.repo.update_run_status(run.id, run.status, finished=True)
    assigned_agent_ids = sorted(
        {
            str(item["agent_id"])
            for item in dispatches
            if item.get("status") == "success" and item.get("agent_id")
        }
    )
    state.audit.append(
        "multi_agent_lab.smoke",
        {
            "run_id": run.id,
            "agents": len(registered_agents),
            "dispatches": len([item for item in dispatches if item.get("status") == "success"]),
            "status": run.status,
        },
    )
    return {
        "ok": run.status == "completed" and len(assigned_agent_ids) >= 3,
        "run_id": run.id,
        "scenario": scenario.name,
        "status": run.status,
        "agents_registered": len(registered_agents),
        "platforms": [agent["platform"] for agent in registered_agents],
        "distinct_assigned_agents": len(assigned_agent_ids),
        "dispatches": dispatches,
        "stored_history": bool(state.repo and state.repo.get_run(run.id)),
    }
