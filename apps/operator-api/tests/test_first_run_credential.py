"""First-run console password (WS4): one-time set flow, fail-closed once set."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.main import create_app

KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
CONSOLE_PASSWORD = "correct-horse-battery-staple1"  # >= 12 chars, letter + digit


class _FakeAuditStore:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def record(self, actor, action, object_type, object_id, detail=None) -> None:
        self.events.append(
            {"actor": actor, "action": action, "object_type": object_type, "object_id": object_id, "detail": detail}
        )

    def list_events(self, limit: int = 500) -> list[dict]:
        return list(reversed(self.events))[-limit:]


@pytest.fixture()
def unset_env_file(tmp_path) -> str:
    path = tmp_path / ".env"
    # A first-run env: no KP_CONSOLE_PASSWORD present.
    path.write_text("OPERATOR_API_LOG_LEVEL='INFO'\n", encoding="utf-8")
    return str(path)


def _settings(env_file: str) -> OperatorApiSettings:
    return OperatorApiSettings(
        audit_hmac_key=HMAC,
        ciphertext_kek=KEK,
        console_jwt_secret=CONSOLE_JWT,
        env_file=env_file,
        oidc_issuer="http://localhost:8443/realms/kingphisher",
        oidc_audience="kp-operator-api",
        console_static_dir="/nonexistent-console-dir",
    )


def _app(env_file: str):
    app = create_app(_settings(env_file))
    app.state.audit_store = _FakeAuditStore()
    return app


def test_login_reports_first_run_when_password_unset(unset_env_file: str) -> None:
    with TestClient(_app(unset_env_file)) as client:
        resp = client.post("/api/v1/console/session", json={"password": "anything"})
    assert resp.status_code == 428
    assert "not set" in resp.json()["detail"]


def test_first_run_set_password_mints_session_and_persists(unset_env_file: str) -> None:
    app = _app(unset_env_file)
    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/console/password",
            json={"password": CONSOLE_PASSWORD, "confirm": CONSOLE_PASSWORD},
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["auth_mode"] == "dev"
    assert body["token"]
    assert CONSOLE_PASSWORD not in resp.text
    # The write landed in the env file.
    content = Path(unset_env_file).read_text(encoding="utf-8")
    assert "KP_CONSOLE_PASSWORD=" in content


def test_first_run_set_password_rejects_mismatch(unset_env_file: str) -> None:
    with TestClient(_app(unset_env_file)) as client:
        resp = client.post(
            "/api/v1/console/password",
            json={"password": CONSOLE_PASSWORD, "confirm": "different-value"},
        )
    assert resp.status_code == 422


def test_first_run_set_password_rejects_weak(unset_env_file: str) -> None:
    with TestClient(_app(unset_env_file)) as client:
        resp = client.post("/api/v1/console/password", json={"password": "short", "confirm": "short"})
    assert resp.status_code == 422
    # No letter+digit mix also fails closed.
    resp = client.post(
        "/api/v1/console/password",
        json={"password": "alllettersbutnodigit", "confirm": "alllettersbutnodigit"},
    )
    assert resp.status_code == 422


def test_set_password_refuses_once_already_set(unset_env_file: str) -> None:
    app = _app(unset_env_file)
    with TestClient(app) as client:
        first = client.post(
            "/api/v1/console/password",
            json={"password": CONSOLE_PASSWORD, "confirm": CONSOLE_PASSWORD},
        )
        assert first.status_code == 200
        second = client.post(
            "/api/v1/console/password",
            json={"password": CONSOLE_PASSWORD, "confirm": CONSOLE_PASSWORD},
        )
    assert second.status_code == 409


def test_login_works_after_first_run_set(unset_env_file: str) -> None:
    app = _app(unset_env_file)
    with TestClient(app) as client:
        client.post("/api/v1/console/password", json={"password": CONSOLE_PASSWORD, "confirm": CONSOLE_PASSWORD})
        login = client.post("/api/v1/console/session", json={"password": CONSOLE_PASSWORD})
    assert login.status_code == 200
