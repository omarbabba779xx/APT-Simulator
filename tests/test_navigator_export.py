"""Tests for ATT&CK Navigator layer export."""
from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient
from typer.testing import CliRunner

import ttps  # noqa: F401
from orchestrator.main import build_app
from orchestrator.navigator_export import app as nav_app, build_layer


def test_build_layer_structure() -> None:
    layer = build_layer(db_path=None)
    assert layer["domain"] == "enterprise-attack"
    assert "techniques" in layer
    assert len(layer["techniques"]) > 0
    assert "versions" in layer
    assert layer["versions"]["layer"] == "4.5"


def test_build_layer_all_registered_ttps_present() -> None:
    from ttps.base import registry
    layer = build_layer(db_path=None)
    layer_ids = {t["techniqueID"] for t in layer["techniques"]}
    for attack_id in registry.all():
        assert attack_id in layer_ids, f"{attack_id} missing from Navigator layer"


def test_build_layer_colours_assigned() -> None:
    layer = build_layer(db_path=None)
    for t in layer["techniques"]:
        assert t["color"] in ("#3fb950", "#58a6ff", "#d29922", "#8b949e")
        assert 0 <= t["score"] <= 100


def test_build_layer_tactic_hyphenated() -> None:
    """Tactic names in the layer must use hyphenated form, not underscore."""
    layer = build_layer(db_path=None)
    for t in layer["techniques"]:
        assert "_" not in t.get("tactic", ""), \
            f"Tactic '{t['tactic']}' uses underscores — should be hyphenated"


def test_navigator_export_cli(tmp_path: Path) -> None:
    runner = CliRunner()
    out = tmp_path / "layer.json"
    result = runner.invoke(nav_app, ["export", "--out", str(out), "--db", "nonexistent.db"])
    assert result.exit_code == 0, result.stdout
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["domain"] == "enterprise-attack"
    assert len(data["techniques"]) > 0


def test_navigator_api_endpoint() -> None:
    with TestClient(build_app("config/default.yaml")) as client:
        r = client.get("/coverage/navigator")
        assert r.status_code == 200
        body = r.json()
        assert body["domain"] == "enterprise-attack"
        assert isinstance(body["techniques"], list)
        assert len(body["techniques"]) > 10


def test_navigator_layer_has_legend() -> None:
    layer = build_layer()
    assert len(layer["legendItems"]) >= 3
