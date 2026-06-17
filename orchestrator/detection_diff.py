"""Detection diff: replays a run and verifies its Sigma rules would match.

For every step in a run, the matching TTP is asked to produce its synthetic
SIEM events. The TTP's Sigma rule is then evaluated against those events.

Output is a per-step verdict:
  COVERED  — at least one synthetic event matched the rule
  GAP      — events generated but no rule matched
  NO-EVENTS — TTP did not produce any synthetic events (rule not assessable)
  NO-RULE  — TTP has no Sigma rule to compare against

This is a coverage check on YOUR rules vs. YOUR own simulator output, NOT a
real-world detection benchmark. Use the SIEM transpiler + ingest pipeline for
that.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer

import ttps  # noqa: F401  (registers TTPs)
from ttps.base import registry

from .detection import evaluate
from .replay import _iter_events  # reuse audit reader


app = typer.Typer(no_args_is_help=True)


@app.callback()
def _root() -> None:
    """Detection diff between Sigma rules and synthetic TTP events."""


def _build_run_steps(audit_path: Path, run_id: str) -> list[dict]:
    """Recover ordered (step_id, attack_id, params) tuples for a run."""
    out: list[dict] = []
    seen_dispatched: dict[str, dict] = {}
    for ev in _iter_events(audit_path):
        payload = ev.get("payload", {})
        if payload.get("run_id") != run_id:
            continue
        if ev.get("event") == "task.dispatch":
            seen_dispatched[payload["step_id"]] = {
                "step_id": payload["step_id"],
                "attack_id": payload["attack_id"],
            }
        if ev.get("event") == "task.result":
            sid = payload["step_id"]
            if sid in seen_dispatched:
                rec = seen_dispatched[sid]
                rec["ok"] = payload.get("ok", False)
                out.append(rec)
    return out


def _rule_fields(rule: dict[str, Any]) -> set[str]:
    fields: set[str] = set()
    detection = rule.get("detection") or {}
    for key, selection in detection.items():
        if key == "condition" or not isinstance(selection, dict):
            continue
        for field in selection:
            fields.add(field.split("|")[0])
    return fields


def score_detection(rule: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any]:
    """Score rule-to-event fit for coverage and field completeness."""
    matches = [evaluate(rule, ev) for ev in events]
    fields = _rule_fields(rule)
    missing = sorted({field for field in fields if not any(field in ev for ev in events)})
    coverage = round((sum(matches) / len(events)) * 100, 2) if events else 0.0
    fp_risk = "high" if len(fields) <= 1 else "medium" if len(fields) <= 3 else "low"
    return {
        "coverage_score": coverage,
        "events_total": len(events),
        "events_matched": sum(matches),
        "missing_fields": missing,
        "false_positive_risk": fp_risk,
    }


@app.command()
def verify(
    run_id: str,
    audit_path: str = "data/audit/audit.jsonl",
) -> None:
    """Evaluate Sigma rules against synthetic events for each step in a run."""
    p = Path(audit_path)
    if not p.exists():
        typer.echo(f"audit log not found: {audit_path}", err=True)
        raise typer.Exit(code=1)

    steps = _build_run_steps(p, run_id)
    if not steps:
        typer.echo(f"no steps found for run {run_id}", err=True)
        raise typer.Exit(code=1)

    results: list[dict] = []
    for step in steps:
        ttp = registry.get(step["attack_id"])
        if ttp is None:
            results.append({**step, "verdict": "UNKNOWN-TTP"})
            continue
        rule = ttp.sigma_rule()
        if rule is None:
            results.append({**step, "verdict": "NO-RULE"})
            continue
        events = ttp.synthetic_events({}, None)
        if not events:
            results.append({**step, "verdict": "NO-EVENTS"})
            continue
        score = score_detection(rule, events)
        verdict = "COVERED" if score["events_matched"] else "GAP"
        results.append({
            **step,
            "verdict": verdict,
            **score,
        })

    covered = sum(1 for r in results if r["verdict"] == "COVERED")
    gaps = [r for r in results if r["verdict"] == "GAP"]
    typer.echo(f"=== Detection Diff for run {run_id} ===")
    for r in results:
        typer.echo(
            f"  [{r['verdict']:11s}] step={r['step_id']:35s} ttp={r['attack_id']}"
            + (f"  events={r.get('events_matched', 0)}/{r.get('events_total', 0)}" if 'events_total' in r else "")
        )
    typer.echo(f"Covered: {covered}/{len(results)}; Gaps: {len(gaps)}")
    if gaps:
        raise typer.Exit(code=1)


@app.command()
def report(
    out: str = "detection/diff_report.json",
    audit_path: str = "data/audit/audit.jsonl",
) -> None:
    """Compute coverage across ALL runs in the audit log; emit JSON."""
    p = Path(audit_path)
    if not p.exists():
        typer.echo(f"audit log not found: {audit_path}", err=True)
        raise typer.Exit(code=1)
    run_ids: set[str] = set()
    for ev in _iter_events(p):
        rid = ev.get("payload", {}).get("run_id")
        if rid:
            run_ids.add(rid)

    out_data: dict[str, list[dict]] = {}
    for rid in sorted(run_ids):
        steps = _build_run_steps(p, rid)
        run_results: list[dict] = []
        for step in steps:
            ttp = registry.get(step["attack_id"])
            if ttp is None:
                run_results.append({**step, "verdict": "NO-RULE"})
                continue
            rule = ttp.sigma_rule()
            if rule is None:
                run_results.append({**step, "verdict": "NO-RULE"})
                continue
            events = ttp.synthetic_events({}, None)
            if not events:
                run_results.append({**step, "verdict": "NO-EVENTS"})
                continue
            score = score_detection(rule, events)
            run_results.append({
                **step,
                "verdict": "COVERED" if score["events_matched"] else "GAP",
                **score,
            })
        out_data[rid] = run_results

    out_path = Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out_data, indent=2), encoding="utf-8")
    typer.echo(f"Wrote diff report ({len(run_ids)} runs) to {out_path}")


if __name__ == "__main__":
    app()
