"""Tests for the browser console endpoints (login, config, status)."""

from __future__ import annotations

import os

import jwt
import pytest
from fastapi.testclient import TestClient
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.main import create_app

KEK = "0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_PASSWORD = "correct-horse-battery-staple"


class FakeAuditStore:
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    def record(self, actor, action, object_type, object_id, detail=None) -> None:  # noqa: ANN001
        self.events.append({
            "actor": actor, "action": action, "object_type": object_type,
            "object_id": object_id, "detail": detail or {},
        })


@pytest.fixture()
def env_file(tmp_path) -> str:  # noqa: ANN001
    path = tmp_path / ".env"
    path.write_text(f"{os.linesep.join(['KP_CONSOLE_PASSWORD=' + CONSOLE_PASSWORD, '']) }", encoding="utf-8")
    return str(path)


def _settings(env_file: str) -> OperatorApiSettings:
    # Pin every value the tokens/endpoints depend on: pydantic-settings still
    # loads the repo .env as a dotenv source, so tests must not inherit
    # whatever is in a developer's local .env.
    return OperatorApiSettings(
        audit_hmac_key=HMAC,
        ciphertext_kek=KEK,
        env_file=env_file,
        oidc_issuer="http://localhost:8443/realms/kingphisher",
        oidc_audience="kp-operator-api",
        console_static_dir="/nonexistent-console-dir",
    )


def _app(env_file: str, *, fake_audit: FakeAuditStore | None = None):
    settings = _settings(env_file)
    app = create_app(settings)
    app.state.audit_store = fake_audit or FakeAuditStore()
    return app


def _login(client: TestClient, password: str = CONSOLE_PASSWORD) -> str:
    resp = client.post("/api/v1/console/session", json={"password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()["token"]


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_console_session_mints_admin_token(env_file: str) -> None:
    app = _app(env_file)
    with TestClient(app) as client:
        token = _login(client)
        claims = jwt.decode(
            token, HMAC.encode().hex(), algorithms=["HS256"],
            audience="kp-operator-api", issuer="http://localhost:8443/realms/kingphisher",
        )
        assert claims["realm_access"]["roles"] == ["administrator"]


def test_console_session_rejects_wrong_password(env_file: str) -> None:
    app = _app(env_file)
    with TestClient(app) as client:
        resp = client.post("/api/v1/console/session", json={"password": "wrong"})
        assert resp.status_code == 401


def test_console_session_requires_configured_password(tmp_path) -> None:  # noqa: ANN001
    env_file = str(tmp_path / ".env")
    with TestClient(_app(env_file)) as client:
        resp = client.post("/api/v1/console/session", json={"password": CONSOLE_PASSWORD})
        assert resp.status_code == 401


def test_console_config_read_masks_secrets(env_file: str) -> None:
    app = _app(env_file)
    with TestClient(app) as client:
        token = _login(client)
        resp = client.get("/api/v1/console/config", headers=_auth(token))
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["masked"]["KP_CONSOLE_PASSWORD"] is True
        assert "correct-horse-battery-staple" not in body["values"]["KP_CONSOLE_PASSWORD"]
        assert "****" in body["values"]["KP_CONSOLE_PASSWORD"]


def test_console_config_write_persists_and_audits(env_file: str) -> None:
    audit = FakeAuditStore()
    app = _app(env_file, fake_audit=audit)
    with TestClient(app) as client:
        token = _login(client)
        resp = client.put("/api/v1/console/config", headers=_auth(token), json={
            "values": {"OPERATOR_API_TRAINING_DOMAINS": "example.com,training.local,demo.example"},
        })
        assert resp.status_code == 200, resp.text
        assert resp.json()["changed"] == ["OPERATOR_API_TRAINING_DOMAINS"]
        assert any(e["action"] == "console.config.update" for e in audit.events)


def test_console_config_rejects_unknown_keys(env_file: str) -> None:
    app = _app(env_file)
    with TestClient(app) as client:
        token = _login(client)
        resp = client.put("/api/v1/console/config", headers=_auth(token), json={
            "values": {"DATABASE_URL": "postgresql://evil:evil@example.com/x"},
        })
        assert resp.status_code == 403


def test_console_config_requires_admin_token(env_file: str) -> None:
    app = _app(env_file)
    settings = _settings(env_file)
    with TestClient(app) as client:
        claims = {
            "sub": "low-priv", "iss": settings.oidc_issuer, "aud": settings.oidc_audience,
            "exp": 2_000_000_000, "nbf": 0, "realm_access": {"roles": ["campaign_author"]},
        }
        token = jwt.encode(claims, settings.require_secret_key().hex(), algorithm="HS256")
        resp = client.get("/api/v1/console/config", headers=_auth(token))
        assert resp.status_code == 403


def test_console_restart_creates_marker(env_file: str) -> None:
    app = _app(env_file)
    with TestClient(app) as client:
        token = _login(client)
        resp = client.post("/api/v1/console/restart", headers=_auth(token))
        assert resp.status_code == 200, resp.text
        assert resp.json()["ok"] is True
        marker = os.path.join(os.path.dirname(env_file), "data", "run", "restart")
        assert os.path.exists(marker)


def test_console_status_requires_auth(env_file: str) -> None:
    app = _app(env_file)
    with TestClient(app) as client:
        resp = client.get("/api/v1/console/status")
        assert resp.status_code == 401


def test_console_stop_creates_marker(env_file: str) -> None:
    app = _app(env_file)
    with TestClient(app) as client:
        token = _login(client)
        resp = client.post("/api/v1/console/stop", headers=_auth(token))
        assert resp.status_code == 200, resp.text
        assert resp.json()["ok"] is True
        marker = os.path.join(os.path.dirname(env_file), "data", "run", "stop")
        assert os.path.exists(marker)
