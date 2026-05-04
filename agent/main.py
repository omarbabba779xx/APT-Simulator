"""Agent CLI."""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Optional

import typer

from .beacon import Beacon
from .safety import host_in_whitelist, killswitch_engaged


cli = typer.Typer(no_args_is_help=True)


@cli.callback()
def _root() -> None:
    """APT Simulator agent."""


@cli.command()
def run(
    server: str = "http://127.0.0.1:8000",
    interval: float = 5.0,
    jitter: float = 2.0,
    ttl_seconds: int = 14400,
    max_failures: int = 5,
    auth_token: Optional[str] = typer.Option(
        None,
        "--auth-token",
        help="Bearer token (also reads APT_AGENT_TOKEN env var)",
    ),
) -> None:
    """Start the beacon loop. Refuses to run if outside lab whitelist."""
    Beacon(
        server=server,
        interval=interval,
        jitter=jitter,
        ttl_seconds=ttl_seconds,
        max_failures=max_failures,
        auth_token=auth_token or os.environ.get("APT_AGENT_TOKEN"),
    ).loop()


@cli.command(name="run-local")
def run_local(
    scenario: str = typer.Argument(help="Path to scenario YAML file"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print steps without executing"),
    skip_safety: bool = typer.Option(False, "--skip-safety", help="Skip lab whitelist check (test use only)"),
    pub_key: Optional[str] = typer.Option(None, "--pub-key", help="Ed25519 public key PEM path for sig verification"),
) -> None:
    """Execute a scenario locally without an orchestrator (offline mode).

    Runs every TTP in the scenario sequentially, respecting the dependency
    DAG order. No beacon loop, no HTTP calls to an orchestrator. Useful for
    CI smoke tests and isolated lab validation.
    """
    import yaml
    import ttps  # noqa: F401 (register TTPs)
    from ttps.base import registry
    from orchestrator.dsl.schema import Scenario

    if not skip_safety:
        whitelist_path = Path("config/lab_whitelist.yaml")
        if whitelist_path.exists():
            ok, reason = host_in_whitelist(str(whitelist_path))
            if not ok:
                typer.echo(f"[ABORT] Lab whitelist check failed: {reason}", err=True)
                raise typer.Exit(code=2)

        engaged, _ks_reason = killswitch_engaged()
        if engaged:
            typer.echo("[ABORT] Kill-switch is engaged.", err=True)
            raise typer.Exit(code=3)

    sc_path = Path(scenario)
    if not sc_path.exists():
        typer.echo(f"Scenario file not found: {sc_path}", err=True)
        raise typer.Exit(code=1)

    with open(sc_path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    sc = Scenario(**raw)
    sc.validate_dag()

    typer.echo(f"\n[APT-SIM] Local run — scenario: {sc.name}")
    typer.echo(f"[APT-SIM] Steps: {len(sc.steps)}, platforms: {sc.target_platforms}")

    if dry_run:
        typer.echo("\n[DRY-RUN] Steps that would execute:")
        for step in sc.steps:
            typer.echo(f"  {step.id:30s}  {step.ttp}")
        raise typer.Exit(0)

    # Build topological execution order (simple BFS respecting depends_on).
    completed: set[str] = set()
    remaining = list(sc.steps)
    results: dict[str, bool] = {}
    total = len(remaining)
    idx = 0

    start_ts = time.time()
    while remaining:
        ready = [s for s in remaining if all(d in completed for d in s.depends_on)]
        if not ready:
            typer.echo("[ERROR] DAG deadlock — remaining steps have unresolvable dependencies.", err=True)
            break
        for step in ready:
            idx += 1
            ttp = registry.get(step.ttp)
            if ttp is None:
                typer.echo(f"  [{idx:02d}/{total}] {step.id}: TTP {step.ttp} not registered — SKIP")
                results[step.id] = False
                completed.add(step.id)
                remaining.remove(step)
                continue
            typer.echo(f"  [{idx:02d}/{total}] {step.id} ({step.ttp}) ... ", nl=False)
            t0 = time.time()
            result = ttp.run(step.params or {})
            dur = time.time() - t0
            status = "OK" if result.ok else "FAIL"
            typer.echo(f"{status}  ({dur:.2f}s)")
            if not result.ok and result.error:
                typer.echo(f"           error: {result.error}")
            if result.ok and result.output:
                excerpt = result.output[:120].replace("\n", " ")
                typer.echo(f"           {excerpt}")
            results[step.id] = result.ok
            completed.add(step.id)
            remaining.remove(step)
            if not result.ok and step.abort_on_fail:
                typer.echo(f"\n[ABORT] Step '{step.id}' failed with abort_on_fail=true. Stopping.")
                break

    elapsed = time.time() - start_ts
    ok_count = sum(1 for v in results.values() if v)
    fail_count = len(results) - ok_count
    typer.echo(f"\n[APT-SIM] Local run complete in {elapsed:.1f}s — {ok_count} OK / {fail_count} FAIL")
    if fail_count:
        raise typer.Exit(code=1)


if __name__ == "__main__":
    cli()
