"""Campaign utilities for large scenario batches and replay event generation."""
from __future__ import annotations

import json
from pathlib import Path

import typer
import yaml

import ttps  # noqa: F401
from ttps.base import registry

from .scenario_builder import build_scenario


app = typer.Typer(no_args_is_help=True)


@app.command()
def build_queue(
    out: str = "scenarios/campaign_queue.yaml",
    actors: str = "apt29,fin7,lazarus,apt41,ransomware,insider,cloud-intrusion",
    difficulty: str = "realistic",
    steps: int = 12,
    repeats: int = 1,
) -> None:
    """Build a queue file containing many generated scenarios."""
    queue = []
    seed = 1
    for _ in range(repeats):
        for actor in [a.strip() for a in actors.split(",") if a.strip()]:
            queue.append(build_scenario(actor=actor, difficulty=difficulty, steps=steps, seed=seed))
            seed += 1
    out_path = Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(yaml.safe_dump({"campaign": queue}, sort_keys=False), encoding="utf-8")
    typer.echo(f"Wrote {len(queue)} scenario(s) to {out_path}")


@app.command()
def replay_events(out: str = "detection/replay/synthetic_events.jsonl", events: int = 1000) -> None:
    """Write a large JSONL stream by cycling registered TTP synthetic events."""
    ttps_with_events = [ttp for ttp in registry.all().values() if ttp.synthetic_events({}, None)]
    if not ttps_with_events:
        raise typer.Exit(code=1)
    out_path = Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for idx in range(events):
        ttp = ttps_with_events[idx % len(ttps_with_events)]
        event = dict(ttp.synthetic_events({}, None)[0])
        event["_replay_index"] = idx
        event["_replay_ttp"] = ttp.attack_id
        rows.append(json.dumps(event, sort_keys=True))
    out_path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    typer.echo(f"Wrote {events} synthetic replay event(s) to {out_path}")


if __name__ == "__main__":
    app()
