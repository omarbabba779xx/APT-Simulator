"""Execution Engine v3 readiness and lab-safe run controls."""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any

from .api.state import AppState


def _ts(value: Any) -> float | None:
    if isinstance(value, datetime):
        return value.timestamp()
    return None


def _status_counts(items: list[Any], attr: str = "status") -> dict[str, int]:
    counts: Counter[str] = Counter()
    for item in items:
        counts[str(getattr(item, attr, "unknown"))] += 1
    return dict(sorted(counts.items()))


def _agent_platform_counts(agents: dict[str, dict[str, Any]]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for agent in agents.values():
        counts[str(agent.get("platform", "unknown")).lower()] += 1
    return dict(sorted(counts.items()))


def _capability(name: str, passed: bool, evidence: str, gap: str = "") -> dict[str, object]:
    return {
        "name": name,
        "passed": passed,
        "status": "ready" if passed else "needs_attention",
        "evidence": evidence,
        "gap": gap,
    }


def build_engine_status(state: AppState) -> dict[str, object]:
    """Return one compact status document for queue, agents, cleanup, and integrity."""
    repo = state.repo
    runs = state.planner.list_runs()
    active_runs = [run for run in runs if run.status in {"running", "paused"}]
    planner_status = Counter(run.status for run in runs)
    queue_entries = repo.queue_entries() if repo else []
    stored_runs = repo.list_runs() if repo else []
    pending_cleanup = [
        item for item in queue_entries
        if bool(getattr(item, "cleanup_required", False)) and getattr(item, "cleanup_status", "") == "pending"
    ]
    retryable = [
        item for item in queue_entries
        if getattr(item, "status", "") in {"failed", "skipped", "aborted"}
        and int(getattr(item, "attempt", 0)) < int(getattr(item, "max_attempts", 1))
    ]
    audit_ok, broken_line = state.audit.verify()
    capabilities = [
        _capability(
            "persistent_queue",
            repo is not None,
            "SQLite stores runs, queue entries, logs, and artifacts.",
            "Configure orchestrator.db_path.",
        ),
        _capability(
            "multi_host_dispatch",
            True,
            "Agents beacon with platform metadata; planner dispatches ready DAG steps by platform.",
        ),
        _capability(
            "pause_resume",
            True,
            "Campaign and run status controls pause and resume queued work.",
        ),
        _capability(
            "retry_failed_steps",
            True,
            "Failed, skipped, and aborted steps can be reset to queued without cloning the scenario.",
        ),
        _capability(
            "cleanup_tracking",
            repo is not None,
            f"{len(pending_cleanup)} cleanup item(s) currently pending.",
        ),
        _capability(
            "per_step_artifacts",
            repo is not None,
            "Run ZIPs include report, history, and cleanup data; DB stores artifact records.",
        ),
        _capability(
            "signed_payloads",
            bool(state.config.security.require_signed_payloads),
            "Agent tasks are Ed25519-signed when signing keys are configured.",
        ),
        _capability(
            "tamper_evident_logs",
            audit_ok,
            "Audit JSONL uses a SHA-256 hash chain.",
            f"Broken audit chain at line {broken_line}." if broken_line else "",
        ),
        _capability(
            "killswitch",
            not state.killswitch.is_active(),
            "Killswitch aborts active planner runs within a beacon cycle.",
            state.killswitch.reason() or "",
        ),
        _capability(
            "lab_allowlist",
            bool(state.config.security.enforce_lab_whitelist),
            "Lab whitelist enforcement is enabled in config/default.yaml.",
            "Enable security.enforce_lab_whitelist for live labs.",
        ),
    ]
    passed = sum(1 for item in capabilities if item["passed"])
    queue_preview = [
        {
            "id": item.id,
            "run_id": item.run_id,
            "step_id": item.step_id,
            "attack_id": item.attack_id,
            "status": item.status,
            "assigned_agent": item.assigned_agent,
            "attempt": item.attempt,
            "max_attempts": item.max_attempts,
            "cleanup_status": item.cleanup_status,
            "updated_at": _ts(item.updated_at),
        }
        for item in queue_entries[:100]
    ]
    return {
        "version": "v3",
        "mode": "lab-safe",
        "readiness_score": round((passed / len(capabilities)) * 100, 2) if capabilities else 0,
        "capabilities": capabilities,
        "agents": {
            "registered": len(state.agents),
            "platforms": _agent_platform_counts(state.agents),
            "items": [
                {
                    "id": agent_id,
                    "hostname": agent.get("hostname", ""),
                    "platform": agent.get("platform", ""),
                    "last_seen": agent.get("last_seen", ""),
                }
                for agent_id, agent in sorted(state.agents.items())
            ],
        },
        "runs": {
            "in_memory": len(runs),
            "stored": len(stored_runs),
            "active": len(active_runs),
            "status_counts": dict(sorted(planner_status.items())),
        },
        "queue": {
            "total": len(queue_entries),
            "status_counts": _status_counts(queue_entries),
            "pending_cleanup": len(pending_cleanup),
            "retryable": len(retryable),
            "preview": queue_preview,
        },
        "integrity": {
            "audit_hash_chain": "valid" if audit_ok else "broken",
            "broken_line": broken_line,
            "signed_payloads_required": state.config.security.require_signed_payloads,
            "signing_key_loaded": state.signing_key is not None,
        },
        "controls": [
            "POST /execution/v3/runs/{run_id}/retry-failed",
            "POST /execution/v3/runs/{run_id}/cleanup",
            "POST /campaigns/{campaign_id}/pause",
            "POST /campaigns/{campaign_id}/resume",
            "POST /campaigns/{campaign_id}/retry-failed",
        ],
    }


def retry_failed_run(state: AppState, run_id: str) -> dict[str, object]:
    planner_changed = state.planner.retry_failed_steps(run_id)
    repo_changed = state.repo.retry_failed_steps(run_id) if state.repo else 0
    state.audit.append(
        "engine_v3.retry_failed",
        {"run_id": run_id, "planner_steps": planner_changed, "stored_steps": repo_changed},
    )
    return {
        "run_id": run_id,
        "planner_steps_requeued": planner_changed,
        "stored_steps_requeued": repo_changed,
    }


def cleanup_run(state: AppState, run_id: str) -> dict[str, object]:
    changed = state.repo.mark_cleanup_complete(run_id) if state.repo else 0
    state.audit.append("engine_v3.cleanup", {"run_id": run_id, "cleanup_items_closed": changed})
    return {"run_id": run_id, "cleanup_items_closed": changed}
