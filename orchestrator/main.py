"""Orchestrator entrypoint - FastAPI app and Typer CLI."""
from __future__ import annotations

from pathlib import Path

import asyncio
import json
from contextlib import asynccontextmanager

import typer
import uvicorn
from fastapi import FastAPI
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from .api import agents as agents_api
from .api import killswitch as killswitch_api
from .api import profiles as profiles_api
from .api import scenarios as scenarios_api
from .api import ttps as ttps_api
from .api import ws as ws_api
from .api.state import AppState, set_state
from .core.audit import AuditLog
from .core.auth import load_or_generate_secret
from .core.bus import EventBus
from .core.config import load_config
from .core.killswitch import KillSwitch
from .core.planner import Planner
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
        scheduler_task = asyncio.create_task(_campaign_scheduler_loop())
        try:
            yield
        finally:
            scheduler_task.cancel()
            try:
                await scheduler_task
            except asyncio.CancelledError:
                pass

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

    @app.get("/coverage/matrix")
    def coverage_matrix() -> dict[str, object]:
        """Dynamic coverage matrix grouped by tactic, pack, and safety tier."""
        from .detection_matrix import build_matrix

        return build_matrix()

    @app.get("/attack/sync/status")
    def attack_sync_status() -> dict[str, object]:
        """Local ATT&CK snapshot status and registry drift."""
        from .attack_sync import drift_status

        return drift_status()

    @app.get("/detections/score")
    def detection_score() -> dict[str, object]:
        """Rule-to-synthetic-event score for every registered TTP with events."""
        import ttps  # noqa: F401
        from ttps.base import registry

        from .detection_diff import score_detection

        out: dict[str, object] = {}
        for attack_id, ttp in registry.all().items():
            rule = ttp.sigma_rule()
            events = ttp.synthetic_events({}, None)
            if rule is None or not events:
                continue
            out[attack_id] = score_detection(rule, events)
        return out

    @app.get("/detections/workbench")
    def detection_workbench() -> dict[str, object]:
        """Sigma rule quality, field coverage, and SIEM target status."""
        from .detection_workbench import build_workbench

        return build_workbench(limit_items=300)

    @app.get("/exposure/graph")
    def exposure_graph() -> dict[str, object]:
        """Controlled exposure graph across identity, endpoint, cloud, SaaS, and container domains."""
        from .exposure_graph import build_exposure_graph

        return build_exposure_graph(state.scenarios)

    @app.get("/scenario-maturity")
    def scenario_maturity() -> dict[str, object]:
        """Scenario depth, evidence, and SOC usability scoring."""
        from .scenario_maturity import build_scenario_maturity

        return build_scenario_maturity(state.scenarios, limit_items=500)

    @app.get("/scenario-evidence/{scenario_name}")
    def scenario_evidence_detail(scenario_name: str) -> dict[str, object]:
        """Evidence contract and golden events for one scenario."""
        from .scenario_maturity import scenario_evidence

        return scenario_evidence(scenario_name)

    @app.get("/lab-profiles")
    def lab_profiles() -> list[dict[str, object]]:
        """Recommended lab profiles for scenario testing."""
        from .lab_profiles import list_lab_profiles

        return list_lab_profiles()

    @app.get("/access/rbac")
    def access_rbac() -> dict[str, object]:
        """RBAC role matrix exposed for dashboard and compliance checks."""
        return {
            "enabled": cfg.security.require_auth,
            "roles": ["viewer", "operator", "admin"],
            "matrix": {
                "viewer": ["read catalog", "read scenarios", "read reports", "read history"],
                "operator": ["viewer", "start runs", "start campaigns", "register agents"],
                "admin": ["operator", "engage killswitch", "disengage killswitch"],
            },
            "token_cli": "python -m orchestrator.auth_cli issue --role admin --subject analyst",
        }

    @app.get("/imports/center")
    def imports_center() -> dict[str, object]:
        """Official importer readiness and local imported content status."""
        from .import_center import build_import_center

        return build_import_center(state.scenarios)

    @app.get("/platform/readiness")
    def platform_readiness() -> dict[str, object]:
        """Project-level scorecard across execution, imports, evidence, detection, and reports."""
        from .platform_readiness import build_platform_readiness

        return build_platform_readiness(state)

    @app.get("/reports/benchmark-pack.zip")
    def benchmark_pack_zip() -> Response:
        """Download reproducible public benchmark evidence snapshots."""
        from .benchmark_pack import build_benchmark_zip

        return Response(
            build_benchmark_zip(state),
            media_type="application/zip",
            headers={"Content-Disposition": 'attachment; filename="apt-simulator-benchmark-pack.zip"'},
        )

    @app.get("/runs/{run_id}/timeline")
    def run_timeline(run_id: str) -> dict[str, object]:
        """Timeline view for one in-memory run."""
        from .api.state import get_state as _gs

        run = _gs().planner.get_run(run_id)
        if not run:
            return {"run_id": run_id, "events": []}
        events = []
        for state in run.steps.values():
            events.append(
                {
                    "step_id": state.step.id,
                    "attack_id": state.step.ttp,
                    "status": state.status,
                    "agent_id": state.assigned_agent,
                    "started_at": state.started_at,
                    "finished_at": state.finished_at,
                    "duration_seconds": round(state.finished_at - state.started_at, 3)
                    if state.finished_at and state.started_at
                    else None,
                }
            )
        return {"run_id": run_id, "scenario": run.scenario.name, "events": events}

    @app.get("/runs/compare")
    def compare_runs(ids: str) -> dict[str, object]:
        """Compare high-level status and step counts for comma-separated run IDs."""
        from .api.state import get_state as _gs

        planner = _gs().planner
        rows = []
        for run_id in [item.strip() for item in ids.split(",") if item.strip()]:
            run = planner.get_run(run_id)
            if not run:
                rows.append({"run_id": run_id, "missing": True})
                continue
            counts: dict[str, int] = {}
            for step in run.steps.values():
                counts[step.status] = counts.get(step.status, 0) + 1
            rows.append(
                {
                    "run_id": run_id,
                    "scenario": run.scenario.name,
                    "status": run.status,
                    "step_counts": counts,
                }
            )
        return {"runs": rows}

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
        durations = [
            st.finished_at - st.started_at
            for run in runs
            for st in run.steps.values()
            if st.finished_at > st.started_at > 0
        ]
        avg_step_s = round(sum(durations) / len(durations), 3) if durations else None
        return {
            "runs": {
                "total": total,
                "completed": completed,
                "failed": failed,
                "aborted": aborted,
                "running": running,
            },
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


async def _campaign_scheduler_loop() -> None:
    """Background scheduler for in-memory campaign records."""
    from .api.scenarios import tick_scheduled_campaigns

    while True:
        tick_scheduled_campaigns()
        await asyncio.sleep(2)


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
