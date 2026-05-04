"""Orchestrator entrypoint — FastAPI app + Typer CLI."""
from __future__ import annotations

from pathlib import Path

import asyncio
import json
from contextlib import asynccontextmanager

import typer
import uvicorn
from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from .api import agents as agents_api
from .api import killswitch as killswitch_api
from .api import profiles as profiles_api
from .api import scenarios as scenarios_api
from .api import ttps as ttps_api
from .api import ws as ws_api
from .api.state import AppState, get_state, set_state
from .core.audit import AuditLog
from .core.bus import EventBus
from .core.config import load_config
from .core.killswitch import KillSwitch
from .core.planner import Planner
from .core.auth import load_or_generate_secret
from .core.signer import load_private
from .dsl.loader import load_scenarios_from_dir
from .storage.db import Repository, init_engine
from .telemetry.otel import maybe_install as maybe_install_otel


def build_app(config_path: str = "config/default.yaml") -> FastAPI:
    cfg = load_config(config_path)

    Path(cfg.orchestrator.audit_dir).mkdir(parents=True, exist_ok=True)
    bus = EventBus()
    audit = AuditLog(Path(cfg.orchestrator.audit_dir) / "audit.jsonl", bus=bus)
    maybe_install_otel(audit)
    killswitch = KillSwitch(cfg.orchestrator.killswitch_file)
    planner = Planner()

    engine = init_engine(cfg.orchestrator.db_path)
    repo = Repository(engine)

    signing_key = None
    public_key_pem: str | None = None
    if cfg.security.require_signed_payloads:
        priv_path = Path(cfg.security.signing_key_path)
        pub_path = Path(cfg.security.signing_pub_path)
        if priv_path.exists() and pub_path.exists():
            signing_key = load_private(priv_path)
            public_key_pem = pub_path.read_text(encoding="utf-8")

    scenarios = load_scenarios_from_dir(cfg.orchestrator.scenarios_dir)

    jwt_secret: bytes | None = None
    if cfg.security.require_auth:
        jwt_secret = load_or_generate_secret(cfg.security.jwt_secret_path)

    state = AppState(
        config=cfg,
        killswitch=killswitch,
        audit=audit,
        planner=planner,
        repo=repo,
        bus=bus,
        signing_key=signing_key,
        public_key_pem=public_key_pem,
        jwt_secret=jwt_secret,
        scenarios=scenarios,
    )
    set_state(state)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        bus.attach_loop(asyncio.get_running_loop())
        yield

    app = FastAPI(title="APT Simulator", version="0.1.0", lifespan=lifespan)

    @app.get("/healthz")
    def healthz() -> dict[str, object]:
        return {
            "status": "ok",
            "killswitch": killswitch.is_active(),
            "scenarios_loaded": len(scenarios),
            "agents_registered": len(state.agents),
        }

    @app.get("/coverage")
    def coverage() -> dict[str, object]:
        coverage_path = Path("detection/sigma/coverage.json")
        if not coverage_path.exists():
            return {}
        return json.loads(coverage_path.read_text(encoding="utf-8"))

    @app.get("/coverage/navigator")
    def coverage_navigator(pretty: bool = False) -> dict[str, object]:
        """ATT&CK Navigator v4 layer JSON for all registered TTPs."""
        from .navigator_export import build_layer
        db = str(cfg.orchestrator.db_path)
        return build_layer(db_path=db)

    @app.get("/metrics")
    def metrics() -> dict[str, object]:
        """Operational statistics: run counts, TTP success rates, agent breakdown."""
        from .api.state import get_state as _gs
        s = _gs()
        runs = s.planner.list_runs()
        total = len(runs)
        completed = sum(1 for r in runs if r.status == "completed")
        failed = sum(1 for r in runs if r.status == "failed")
        aborted = sum(1 for r in runs if r.status == "aborted")
        running = sum(1 for r in runs if r.status == "running")
        # Per-TTP stats
        ttp_stats: dict[str, dict[str, int]] = {}
        for run in runs:
            for sid, st in run.steps.items():
                aid = st.step.ttp
                entry = ttp_stats.setdefault(aid, {"success": 0, "failed": 0, "total": 0})
                entry["total"] += 1
                if st.status == "success":
                    entry["success"] += 1
                elif st.status == "failed":
                    entry["failed"] += 1
        # Average step duration (seconds)
        durations = [
            st.finished_at - st.started_at
            for run in runs
            for st in run.steps.values()
            if st.finished_at > st.started_at > 0
        ]
        avg_step_s = round(sum(durations) / len(durations), 3) if durations else None
        return {
            "runs": {"total": total, "completed": completed, "failed": failed,
                     "aborted": aborted, "running": running},
            "agents": {
                "total": len(s.agents),
                "by_platform": _count_by_platform(s.agents),
            },
            "ttp_stats": ttp_stats,
            "avg_step_duration_seconds": avg_step_s,
            "killswitch_active": s.killswitch.is_active(),
        }

    def _count_by_platform(agents: dict) -> dict[str, int]:
        counts: dict[str, int] = {}
        for a in agents.values():
            p = getattr(a, "platform", "unknown")
            counts[p] = counts.get(p, 0) + 1
        return counts

    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        return RedirectResponse(url="/dashboard/")

    app.include_router(agents_api.router)
    app.include_router(scenarios_api.router)
    app.include_router(ttps_api.router)
    app.include_router(killswitch_api.router)
    app.include_router(ws_api.router)
    app.include_router(profiles_api.router)

    static_dir = Path(__file__).parent / "static"
    if static_dir.exists():
        app.mount("/dashboard", StaticFiles(directory=str(static_dir), html=True), name="dashboard")

    audit.append("orchestrator.start", {"version": "0.1.0", "scenarios": list(scenarios)})
    return app


cli = typer.Typer(no_args_is_help=True)


@cli.command()
def serve(
    config: str = "config/default.yaml",
    host: str | None = None,
    port: int | None = None,
) -> None:
    """Run the orchestrator HTTP server."""
    cfg = load_config(config)
    app = build_app(config)
    uvicorn.run(
        app,
        host=host or cfg.orchestrator.host,
        port=port or cfg.orchestrator.port,
        log_level=cfg.logging.level.lower(),
    )


@cli.command()
def verify_audit(audit_path: str = "data/audit/audit.jsonl") -> None:
    """Verify the integrity of the audit log hash chain."""
    log = AuditLog(audit_path)
    ok, broken = log.verify()
    if ok:
        typer.echo("Audit chain valid.")
    else:
        typer.echo(f"BROKEN at line {broken}", err=True)
        raise typer.Exit(code=1)


if __name__ == "__main__":
    cli()
