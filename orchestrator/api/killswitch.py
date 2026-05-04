"""Killswitch endpoints."""
from __future__ import annotations

from fastapi import APIRouter

from ..core.auth import require_role
from .schemas import KillswitchStatus
from .state import get_state


router = APIRouter(prefix="/killswitch", tags=["killswitch"])


@router.get("", response_model=KillswitchStatus)
def status(_claims=require_role("viewer")) -> KillswitchStatus:
    ks = get_state().killswitch
    return KillswitchStatus(active=ks.is_active(), reason=ks.reason())


@router.post("/engage", response_model=KillswitchStatus)
def engage(reason: str = "manual", _claims=require_role("admin")) -> KillswitchStatus:
    s = get_state()
    s.killswitch.engage(reason)
    aborted = s.planner.abort_all(reason=f"killswitch:{reason}")
    if s.repo:
        for run in s.planner.list_runs():
            if run.status == "aborted":
                s.repo.update_run_status(run.id, "aborted", finished=True)
                for st in run.steps.values():
                    if st.status == "aborted":
                        s.repo.update_step(
                            run_id=run.id,
                            step_id=st.step.id,
                            status="aborted",
                            error=st.error,
                            mark_finished=True,
                        )
    s.audit.append("killswitch.engage", {"reason": reason, "aborted_runs": aborted})
    return KillswitchStatus(active=True, reason=reason)


@router.post("/disengage", response_model=KillswitchStatus)
def disengage(_claims=require_role("admin")) -> KillswitchStatus:
    s = get_state()
    s.killswitch.disengage()
    s.audit.append("killswitch.disengage", {})
    return KillswitchStatus(active=False, reason=None)
