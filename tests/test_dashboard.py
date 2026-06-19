from __future__ import annotations

from fastapi.testclient import TestClient

from orchestrator.main import build_app


def _client(tmp_path) -> TestClient:
    # Build app with default config; data/db will land in cwd, fine for test.
    app = build_app("config/default.yaml")
    return TestClient(app)


def test_root_redirects_to_dashboard(tmp_path) -> None:
    client = _client(tmp_path)
    r = client.get("/", follow_redirects=False)
    assert r.status_code in (307, 308)
    assert r.headers["location"] == "/dashboard/"


def test_dashboard_index_served(tmp_path) -> None:
    client = _client(tmp_path)
    r = client.get("/dashboard/")
    assert r.status_code == 200
    assert "APT Simulator" in r.text
    assert "Scenario Builder" in r.text
    assert "Scenario Library" in r.text
    assert "TTP Catalog" in r.text
    assert "Project Boundaries" in r.text
    assert "Not an offensive framework" in r.text
    assert "ATT&CK Sync" in r.text
    assert "Detection Workbench" in r.text
    assert "Exposure Graph" in r.text
    assert "Scenario Maturity" in r.text
    assert "Persistent Run History" in r.text
    assert "Lab Profiles" in r.text
    assert "RBAC" in r.text


def test_coverage_endpoint(tmp_path) -> None:
    client = _client(tmp_path)
    r = client.get("/coverage")
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body, dict)


def test_loaded_scenarios_include_generated_yaml_variants(tmp_path) -> None:
    client = _client(tmp_path)
    health = client.get("/healthz").json()
    assert health["scenarios_loaded"] == 3522
    scenarios = client.get("/scenarios").json()
    assert len(scenarios) == 3522
    assert any(name.startswith("apt29_beginner_") for name in scenarios)
    assert "ael_apt29" in scenarios
    assert "validated_apt29_identity_cloud_chain" in scenarios


def test_scenario_library_filters(tmp_path) -> None:
    client = _client(tmp_path)
    r = client.get("/scenario-library", params={"source": "generated variant", "platform": "windows"})
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 3522
    assert body["filtered"] > 0
    first = body["items"][0]
    assert first["kind"] == "generated variant"
    assert first["source"] == "generated YAML"
    assert "windows" in first["platforms"]

    ael = client.get("/scenario-library", params={"source": "emulation plan"}).json()
    assert ael["filtered"] == 11
    assert ael["items"][0]["kind"] == "emulation plan"

    validated = client.get("/scenario-library", params={"source": "validated actor-chain"}).json()
    assert validated["filtered"] == 1000
    assert validated["items"][0]["kind"] == "validated actor-chain"


def test_ttps_listing(tmp_path) -> None:
    client = _client(tmp_path)
    r = client.get("/ttps")
    assert r.status_code == 200
    ttps = r.json()
    assert len(ttps) == 5064
    ids = {t["attack_id"] for t in ttps}
    assert {"T1033", "T1083", "T1059", "T1547.001", "T1057", "T1071.001", "T1003", "T1027", "T1112", "T1070.004", "T1580"} <= ids


def test_dashboard_new_analysis_endpoints(tmp_path) -> None:
    client = _client(tmp_path)

    sync = client.get("/attack/sync/status").json()
    assert sync["coverage_label"] == "15/15"
    assert sync["status"] == "synced"

    workbench = client.get("/detections/workbench").json()
    assert workbench["total_rules"] == 5064
    assert set(workbench["targets"]) == {"splunk", "elastic", "sentinel", "chronicle"}

    graph = client.get("/exposure/graph").json()
    assert graph["scenario_count"] == 3522
    assert graph["domain_counts"]["cloud"] > 0
    assert graph["domain_counts"]["container"] > 0

    maturity = client.get("/scenario-maturity").json()
    assert maturity["total_scenarios"] == 3522
    assert maturity["validated_scenarios"] == 1000
    assert maturity["fixture_backed_scenarios"] == 1000
    assert maturity["evidence_quality"]["with_siem_fields"] == 1000

    evidence = client.get("/scenario-evidence/validated_apt29_identity_cloud_chain").json()
    assert evidence["found"] is True
    assert len(evidence["golden_events"]) == 2

    labs = client.get("/lab-profiles").json()
    assert len(labs) == 4

    access = client.get("/access/rbac").json()
    assert access["roles"] == ["viewer", "operator", "admin"]


def test_scenario_builder_preview(tmp_path) -> None:
    client = _client(tmp_path)
    r = client.get(
        "/scenario-builder/preview",
        params={
            "actor": "cloud-intrusion",
            "difficulty": "realistic",
            "steps": 10,
            "seed": 7,
            "platforms": "windows,linux,darwin",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["actor"] == "cloud-intrusion"
    assert len(body["steps"]) == 10
    assert all(step["params"]["dry_run"] is True for step in body["steps"])


def test_scenario_builder_space(tmp_path) -> None:
    client = _client(tmp_path)
    r = client.get("/scenario-builder/space")
    assert r.status_code == 200
    body = r.json()
    assert body["total_variants"] == 15_680_015_680
    assert body["platform_combinations"] == 7


def test_scenario_builder_batch_preview(tmp_path) -> None:
    client = _client(tmp_path)
    r = client.get(
        "/scenario-builder/batch-preview",
        params={"count": 3, "offset": 100, "stride": 6272006},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 3
    assert body["offset"] == 100
    assert body["stride"] == 6272006
    assert len(body["scenarios"]) == 3
    assert len({scenario["name"] for scenario in body["scenarios"]}) == 3


def test_campaign_runner_and_reports(tmp_path) -> None:
    client = _client(tmp_path)
    campaign_resp = client.post("/campaigns/run", json={"count": 10, "source": "generated variant"})
    assert campaign_resp.status_code == 200
    campaign = campaign_resp.json()
    assert campaign["total_runs"] == 10
    assert len(campaign["run_ids"]) == 10

    pause = client.post(f"/campaigns/{campaign['id']}/pause")
    assert pause.status_code == 200
    assert pause.json()["status"] == "paused"

    resume = client.post(f"/campaigns/{campaign['id']}/resume")
    assert resume.status_code == 200
    assert resume.json()["status"] == "running"

    report = client.get(f"/reports/campaigns/{campaign['id']}.json")
    assert report.status_code == 200
    body = report.json()
    assert body["scenarios_total"] == 10
    assert body["ttps_covered_count"] > 0

    html = client.get(f"/reports/campaigns/{campaign['id']}.html")
    assert html.status_code == 200
    assert "Campaign" in html.text


def test_persistent_history_queue_and_run_artifact_bundle(tmp_path) -> None:
    client = _client(tmp_path)
    run_resp = client.post("/scenarios/run", json={"name": "validated_saas_lab_token_abuse_chain"})
    assert run_resp.status_code == 200
    run_id = run_resp.json()["id"]

    history = client.get("/history/runs").json()
    assert history["total"] >= 1
    assert any(item["id"] == run_id and item["artifact_count"] >= 2 for item in history["items"])

    detail = client.get(f"/history/runs/{run_id}").json()
    assert detail["id"] == run_id
    assert len(detail["queue"]) == len(detail["steps"])
    assert detail["artifacts"]

    queue = client.get("/execution/queue", params={"run_id": run_id}).json()
    assert queue["total"] == len(detail["steps"])
    assert all(item["cleanup_required"] is True for item in queue["items"])

    cleanup = client.get(f"/runs/{run_id}/cleanup-plan").json()
    assert cleanup["run_id"] == run_id
    assert cleanup["pending_count"] == len(detail["steps"])

    bundle = client.get(f"/reports/runs/{run_id}.zip")
    assert bundle.status_code == 200
    assert bundle.headers["content-type"] == "application/zip"


def test_scheduled_campaign_request(tmp_path) -> None:
    client = _client(tmp_path)
    campaign_resp = client.post(
        "/campaigns/run",
        json={
            "count": 3,
            "source": "generated variant",
            "scheduled_at": 4_102_444_800,
            "repeat_interval_seconds": 3600,
            "repeat_count": 2,
        },
    )
    assert campaign_resp.status_code == 200
    campaign = campaign_resp.json()
    assert campaign["status"] == "scheduled"
    assert campaign["total_runs"] == 3
    assert campaign["run_ids"] == []
    assert campaign["repeat_interval_seconds"] == 3600
    assert campaign["repeat_remaining"] == 2
