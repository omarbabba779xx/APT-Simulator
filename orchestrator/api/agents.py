"""Agent endpoints: register, beacon, result."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException

from ..core import signer as signer_mod
from ..core.auth import require_role
from .schemas import (
    AgentRegister,
    AgentRegistered,
    BeaconRequest,
    BeaconResponse,
    BeaconTask,
    TaskResultIn,
)
from .state import get_state


router = APIRouter(prefix="/agents", tags=["agents"])


@router.post("/register", response_model=AgentRegistered)
def register(req: AgentRegister, _claims=require_role("operator")) -> AgentRegistered:
    s = get_state()
    agent_id = uuid.uuid4().hex[:12]
    s.agents[agent_id] = {
        "hostname": req.hostname,
        "platform": req.platform,
        "pid": req.pid,
        "agent_version": req.agent_version,
        "install_id": req.install_id,
        "capabilities": req.capabilities,
        "certificate_subject": req.certificate_subject,
        "registered_at": datetime.now(timezone.utc).isoformat(),
        "last_seen": datetime.now(timezone.utc).isoformat(),
    }
    if s.repo:
        s.repo.upsert_agent(agent_id, req.hostname, req.platform, req.pid)
    s.audit.append("agent.register", {"agent_id": agent_id, **req.model_dump()})
    return AgentRegistered(
        agent_id=agent_id,
        server_time=datetime.now(timezone.utc).timestamp(),
        public_key_pem=s.public_key_pem,
    )


@router.get("")
def list_agents(_claims=require_role("viewer")) -> dict[str, dict]:
    return get_state().agents


@router.post("/beacon", response_model=BeaconResponse)
def beacon(req: BeaconRequest, _claims=require_role("operator")) -> BeaconResponse:
    s = get_state()
    if req.agent_id not in s.agents:
        raise HTTPException(404, "unknown agent")
    s.agents[req.agent_id]["last_seen"] = datetime.now(timezone.utc).isoformat()
    s.agents[req.agent_id]["agent_version"] = req.agent_version
    s.agents[req.agent_id]["capabilities"] = req.capabilities
    s.agents[req.agent_id]["certificate_subject"] = req.certificate_subject
    if s.repo:
        s.repo.touch_agent(req.agent_id)

    if s.killswitch.is_active():
        s.planner.abort_all(reason=s.killswitch.reason() or "killswitch")
        return BeaconResponse(killswitch=True, note=s.killswitch.reason())

    nxt = s.planner.next_task_for_agent(req.agent_id, req.platform)
    if not nxt:
        return BeaconResponse(killswitch=False, note="idle")
    run, state = nxt

    task = BeaconTask(
        run_id=run.id,
        step_id=state.step.id,
        attack_id=state.step.ttp,
        params=state.step.params,
        timeout_seconds=state.step.timeout_seconds,
    )
    if s.signing_key is not None and s.config.security.require_signed_payloads:
        canonical = json.dumps(
            task.model_dump(exclude={"payload_signature"}),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        task.payload_signature = signer_mod.sign(canonical, s.signing_key)
    if s.repo:
        s.repo.update_step(
            run_id=run.id,
            step_id=state.step.id,
            status="dispatched",
            agent_id=req.agent_id,
            mark_started=True,
        )
    s.audit.append(
        "task.dispatch",
        {"agent_id": req.agent_id, "run_id": run.id, "step_id": state.step.id, "attack_id": state.step.ttp},
    )
    return BeaconResponse(killswitch=False, task=task)


@router.post("/result")
def report_result(res: TaskResultIn, _claims=require_role("operator")) -> dict[str, str]:
    s = get_state()
    if res.agent_id not in s.agents:
        raise HTTPException(404, "unknown agent")
    s.planner.report_result(res.run_id, res.step_id, res.ok, res.output, res.error)
    if s.repo:
        s.repo.update_step(
            run_id=res.run_id,
            step_id=res.step_id,
            status="success" if res.ok else "failed",
            output=res.output,
            error=res.error,
            mark_finished=True,
        )
        # Sync run-level status if planner marked it terminal.
        run = s.planner.get_run(res.run_id)
        if run and run.status != "running":
            s.repo.update_run_status(res.run_id, run.status, finished=True)
    s.audit.append(
        "task.result",
        {
            "agent_id": res.agent_id,
            "run_id": res.run_id,
            "step_id": res.step_id,
            "ok": res.ok,
            "output_excerpt": res.output[:400],
            "error": res.error,
        },
    )
    return {"status": "recorded"}
