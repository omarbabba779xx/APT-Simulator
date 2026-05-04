from __future__ import annotations

from fastapi.testclient import TestClient

from orchestrator.api.state import get_state
from orchestrator.core.auth import issue_token, load_or_generate_secret
from orchestrator.main import build_app


def _build_with_auth(tmp_path):
    app = build_app("config/default.yaml")
    s = get_state()
    s.config.security.require_auth = True
    s.jwt_secret = load_or_generate_secret(tmp_path / "jwt.bin")
    return app, s.jwt_secret


def test_unauthed_request_rejected(tmp_path) -> None:
    app, _ = _build_with_auth(tmp_path)
    with TestClient(app) as client:
        r = client.get("/agents")
        assert r.status_code == 401


def test_viewer_can_list_but_not_run(tmp_path) -> None:
    app, secret = _build_with_auth(tmp_path)
    tok = issue_token(secret, role="viewer", subject="bob")
    headers = {"Authorization": f"Bearer {tok}"}
    with TestClient(app) as client:
        r = client.get("/agents", headers=headers)
        assert r.status_code == 200
        r = client.post(
            "/scenarios/run",
            headers=headers,
            json={"name": "basic_recon"},
        )
        assert r.status_code == 403


def test_operator_can_run_but_not_killswitch(tmp_path) -> None:
    app, secret = _build_with_auth(tmp_path)
    tok = issue_token(secret, role="operator", subject="ops")
    headers = {"Authorization": f"Bearer {tok}"}
    with TestClient(app) as client:
        r = client.post("/killswitch/engage", headers=headers)
        assert r.status_code == 403


def test_admin_can_engage_killswitch(tmp_path) -> None:
    app, secret = _build_with_auth(tmp_path)
    tok = issue_token(secret, role="admin", subject="adm")
    headers = {"Authorization": f"Bearer {tok}"}
    with TestClient(app) as client:
        r = client.post("/killswitch/engage", headers=headers)
        assert r.status_code == 200
        # cleanup
        r = client.post("/killswitch/disengage", headers=headers)
        assert r.status_code == 200


def test_invalid_token_rejected(tmp_path) -> None:
    app, _ = _build_with_auth(tmp_path)
    with TestClient(app) as client:
        r = client.get("/agents", headers={"Authorization": "Bearer not-a-jwt"})
        assert r.status_code == 401
