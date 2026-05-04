"""Replay a run from the hash-chained audit log.

Verifies the chain, then projects every event tagged with the target run_id
into a chronological timeline. Useful for forensic review of past runs even
after the SQLite database is gone.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import typer

from .core.audit import AuditLog


app = typer.Typer(no_args_is_help=True)


@app.callback()
def _root() -> None:
    """Replay a run from the hash-chained audit log."""


def _iter_events(audit_path: Path):
    if not audit_path.exists():
        return
    with audit_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def _ts(ev: dict) -> str:
    return datetime.fromtimestamp(ev.get("ts", 0), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


@app.command()
def show(
    run_id: str,
    audit_path: str = "data/audit/audit.jsonl",
    verify_chain: bool = True,
) -> None:
    """Print the ordered event timeline for a run_id."""
    p = Path(audit_path)
    if not p.exists():
        typer.echo(f"audit log not found: {audit_path}", err=True)
        raise typer.Exit(code=1)

    if verify_chain:
        log = AuditLog(p)
        ok, broken = log.verify()
        if not ok:
            typer.echo(f"AUDIT CHAIN BROKEN at line {broken}; aborting replay", err=True)
            raise typer.Exit(code=2)
        typer.echo(f"audit chain valid ({audit_path})")

    events = []
    for ev in _iter_events(p):
        payload = ev.get("payload", {})
        if payload.get("run_id") == run_id or (ev.get("event") == "run.start" and payload.get("run_id") == run_id):
            events.append(ev)

    if not events:
        typer.echo(f"no events found for run_id={run_id}", err=True)
        raise typer.Exit(code=1)

    typer.echo(f"=== Replay run_id={run_id} ({len(events)} events) ===")
    for ev in events:
        ts = _ts(ev)
        kind = ev.get("event", "?")
        payload = ev.get("payload", {})
        if kind == "run.start":
            typer.echo(f"[{ts}] RUN START scenario={payload.get('scenario')}")
        elif kind == "task.dispatch":
            typer.echo(
                f"[{ts}] DISPATCH step={payload.get('step_id'):<30s} ttp={payload.get('attack_id'):<10s} agent={payload.get('agent_id')}"
            )
        elif kind == "task.result":
            ok = payload.get("ok")
            tag = "  OK   " if ok else "FAIL  "
            err = payload.get("error") or ""
            excerpt = (payload.get("output_excerpt") or "").replace("\n", " ")[:60]
            typer.echo(
                f"[{ts}] {tag}     step={payload.get('step_id'):<30s} {excerpt}{(' err=' + err) if err else ''}"
            )
        else:
            typer.echo(f"[{ts}] {kind} {json.dumps(payload, separators=(',', ':'))[:120]}")


@app.command()
def list_runs(audit_path: str = "data/audit/audit.jsonl") -> None:
    """List all run_ids found in the audit log."""
    p = Path(audit_path)
    if not p.exists():
        typer.echo(f"audit log not found: {audit_path}", err=True)
        raise typer.Exit(code=1)
    seen: dict[str, dict] = {}
    for ev in _iter_events(p):
        payload = ev.get("payload", {})
        rid = payload.get("run_id")
        if not rid:
            continue
        if rid not in seen:
            seen[rid] = {"start": ev.get("ts"), "scenario": payload.get("scenario") or "", "events": 0}
        seen[rid]["events"] += 1
    for rid, info in sorted(seen.items(), key=lambda x: x[1]["start"] or 0):
        ts = datetime.fromtimestamp(info["start"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        typer.echo(f"{rid}  {info['scenario']:30s}  events={info['events']:<3}  start={ts}")


if __name__ == "__main__":
    app()
