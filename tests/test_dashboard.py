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
    assert "TTP Catalog" in r.text


def test_coverage_endpoint(tmp_path) -> None:
    client = _client(tmp_path)
    r = client.get("/coverage")
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body, dict)


def test_ttps_listing(tmp_path) -> None:
    client = _client(tmp_path)
    r = client.get("/ttps")
    assert r.status_code == 200
    ids = {t["attack_id"] for t in r.json()}
    assert {"T1033", "T1083", "T1059", "T1547.001", "T1057", "T1071.001", "T1003", "T1027", "T1112", "T1070.004", "T1580"} <= ids


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
    r = client.get("/scenario-builder/batch-preview", params={"count": 3, "offset": 100})
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 3
    assert body["offset"] == 100
    assert len(body["scenarios"]) == 3
    assert len({scenario["name"] for scenario in body["scenarios"]}) == 3
