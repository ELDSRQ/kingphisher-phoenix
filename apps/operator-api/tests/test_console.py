"""Tests for the browser console endpoints (login, config, status)."""

from __future__ import annotations

import os
import uuid
from typing import Self
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from fastapi.testclient import TestClient
from kp_authorization.rbac import Principal
from kp_operator_api import console as console_module
from kp_operator_api.auth import OidcIdP
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.main import create_app

KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
CONSOLE_PASSWORD = "correct-horse-battery-staple"


class FakeAuditStore:
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    def record(self, actor, action, object_type, object_id, detail=None) -> None:  # noqa: ANN001
        self.events.append(
            {
                "actor": actor,
                "action": action,
                "object_type": object_type,
                "object_id": object_id,
                "detail": detail or {},
            }
        )

    def list_events(self, limit: int = 500) -> list[dict[str, object]]:  # noqa: ANN001
        return list(reversed(self.events))[-limit:]


@pytest.fixture()
def env_file(tmp_path) -> str:  # noqa: ANN001
    path = tmp_path / ".env"
    path.write_text(f"{os.linesep.join(['KP_CONSOLE_PASSWORD=' + CONSOLE_PASSWORD, ''])}", encoding="utf-8")
    return str(path)


def _settings(env_file: str) -> OperatorApiSettings:
    # Pin every value the tokens/endpoints depend on: pydantic-settings still
    # loads the repo .env as a dotenv source, so tests must not inherit
    # whatever is in a developer's local .env.
    return OperatorApiSettings(
        audit_hmac_key=HMAC,
        ciphertext_kek=KEK,
        console_jwt_secret=CONSOLE_JWT,
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
            token,
            CONSOLE_JWT,
            algorithms=["HS256"],
            audience="kp-operator-api",
            issuer="http://localhost:8443/realms/kingphisher",
        )
        assert claims["realm_access"]["roles"] == ["administrator"]

        session = client.post("/api/v1/console/session", json={"password": CONSOLE_PASSWORD}).json()
        assert session["auth_mode"] == "dev"
        assert session["principal_id"] == "11111111-1111-4111-8111-111111111111"
        assert session["approval_limited"] is True


def test_console_session_mints_valid_uuid_subject(env_file: str) -> None:
    """HIGH-02: the console principal id must be a valid UUID (uuid.UUID() 500s)."""
    app = _app(env_file)
    with TestClient(app) as client:
        claims = jwt.decode(_login(client), CONSOLE_JWT, algorithms=["HS256"], audience="kp-operator-api")
        assert uuid.UUID(claims["sub"])  # must not raise


def test_console_session_rejects_wrong_password(env_file: str) -> None:
    app = _app(env_file)
    with TestClient(app) as client:
        resp = client.post("/api/v1/console/session", json={"password": "wrong"})
        assert resp.status_code == 401


def test_console_session_lockout_after_repeated_failures(env_file: str) -> None:
    app = _app(env_file)
    with TestClient(app) as client:
        for _ in range(5):
            client.post("/api/v1/console/session", json={"password": "wrong"})
        resp = client.post("/api/v1/console/session", json={"password": CONSOLE_PASSWORD})
        assert resp.status_code == 429


def test_console_session_refused_in_oidc_mode(env_file: str) -> None:
    settings = _settings(env_file)
    settings = settings.model_copy(update={"oidc_mode": "oidc"})
    app = create_app(settings)
    with TestClient(app) as client:
        resp = client.post("/api/v1/console/session", json={"password": CONSOLE_PASSWORD})
        assert resp.status_code == 401


def test_oidc_start_uses_pkce_state_and_nonce(env_file: str, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(env_file).model_copy(update={"oidc_mode": "oidc"})

    async def metadata(_issuer: str) -> dict[str, str]:
        return {
            "authorization_endpoint": "https://idp.example/authorize",
            "token_endpoint": "https://idp.example/token",
        }

    monkeypatch.setattr(console_module, "_oidc_metadata", metadata)
    with TestClient(create_app(settings)) as client:
        response = client.get("/api/v1/console/oidc/start")
        assert response.status_code == 200
        query = parse_qs(urlparse(response.json()["authorization_url"]).query)
        assert query["response_type"] == ["code"]
        assert query["client_id"] == ["kp-operator-console"]
        assert query["code_challenge_method"] == ["S256"]
        assert len(query["code_challenge"][0]) == 43
        assert query["state"][0]
        assert query["nonce"][0]
        cookie = response.cookies.get("kp_oidc_transaction")
        transaction = jwt.decode(cookie, CONSOLE_JWT, algorithms=["HS256"])
        assert transaction["state"] == query["state"][0]
        assert transaction["nonce"] == query["nonce"][0]
        assert "verifier" in transaction


def test_oidc_callback_exchanges_code_validates_nonce_and_sets_session(
    env_file: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(env_file).model_copy(update={"oidc_mode": "oidc"})
    transaction: dict[str, str] = {}

    async def metadata(_issuer: str) -> dict[str, str]:
        return {
            "authorization_endpoint": "https://idp.example/authorize",
            "token_endpoint": "https://idp.example/token",
        }

    class TokenResponse:
        status_code = 200

        def json(self) -> dict[str, str]:
            return {"access_token": "access-token", "id_token": "id-token"}

    class FakeClient:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def __aenter__(self) -> Self:
            return self

        async def __aexit__(self, *_args: object) -> None:
            pass

        async def post(self, url: str, data: dict[str, str]) -> TokenResponse:
            assert url == "https://idp.example/token"
            assert data["code_verifier"] == transaction["verifier"]
            assert data["code"] == "authorization-code"
            return TokenResponse()

    monkeypatch.setattr(console_module, "_oidc_metadata", metadata)
    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    monkeypatch.setattr(
        OidcIdP,
        "verify_claims",
        lambda _self, _token, **_kwargs: {"nonce": transaction["nonce"]},
    )
    monkeypatch.setattr(
        OidcIdP,
        "verify",
        lambda _self, _token: Principal(subject_id=str(uuid.uuid4()), roles=set()),
    )
    with TestClient(create_app(settings)) as client:
        start = client.get("/api/v1/console/oidc/start")
        state = parse_qs(urlparse(start.json()["authorization_url"]).query)["state"][0]
        transaction.update(jwt.decode(start.cookies["kp_oidc_transaction"], CONSOLE_JWT, algorithms=["HS256"]))
        response = client.get(
            "/api/v1/console/oidc/callback",
            params={"code": "authorization-code", "state": state},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert response.headers["location"] == "/console/"
        assert response.cookies["kp_oidc_session"] == "access-token"


def test_oidc_callback_rejects_state_mismatch(env_file: str, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(env_file).model_copy(update={"oidc_mode": "oidc"})

    async def metadata(_issuer: str) -> dict[str, str]:
        return {"authorization_endpoint": "https://idp.example/authorize"}

    monkeypatch.setattr(console_module, "_oidc_metadata", metadata)
    with TestClient(create_app(settings)) as client:
        client.get("/api/v1/console/oidc/start")
        response = client.get(
            "/api/v1/console/oidc/callback",
            params={"code": "code", "state": "attacker-state"},
        )
        assert response.status_code == 401


def test_console_session_requires_configured_password(tmp_path) -> None:  # noqa: ANN001
    env_file = str(tmp_path / ".env")
    with TestClient(_app(env_file)) as client:
        resp = client.post("/api/v1/console/session", json={"password": CONSOLE_PASSWORD})
        assert resp.status_code == 401


def test_console_config_read_never_returns_secret_values(env_file: str) -> None:
    app = _app(env_file)
    with TestClient(app) as client:
        token = _login(client)
        resp = client.get("/api/v1/console/config", headers=_auth(token))
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["masked"]["KP_CONSOLE_PASSWORD"] is True
        assert body["values"]["KP_CONSOLE_PASSWORD"] == ""
        assert "correct-horse-battery-staple" not in body["values"]["KP_CONSOLE_PASSWORD"]


def test_console_config_does_not_expose_database_dsns(env_file: str) -> None:
    app = _app(env_file)
    with TestClient(app) as client:
        token = _login(client)
        body = client.get("/api/v1/console/config", headers=_auth(token)).json()
        assert "OPERATOR_API_DATABASE_URL" not in body["values"]
        assert "OPERATOR_API_AUDIT_DATABASE_URL" not in body["values"]


def test_console_config_write_ignores_blank_secrets(env_file: str) -> None:
    """CRIT-01: a blank secret submitted by the GUI must not clobber the value."""
    app = _app(env_file)
    with TestClient(app) as client:
        token = _login(client)
        resp = client.put(
            "/api/v1/console/config",
            headers=_auth(token),
            json={
                "values": {
                    "KP_CONSOLE_PASSWORD": "",
                    "OPERATOR_API_TRAINING_DOMAINS": "example.com,training.local,demo.example",
                }
            },
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["changed"] == ["OPERATOR_API_TRAINING_DOMAINS"]
        assert client.post("/api/v1/console/session", json={"password": CONSOLE_PASSWORD}).status_code == 200


def test_console_config_write_persists_and_audits(env_file: str) -> None:
    audit = FakeAuditStore()
    app = _app(env_file, fake_audit=audit)
    with TestClient(app) as client:
        token = _login(client)
        resp = client.put(
            "/api/v1/console/config",
            headers=_auth(token),
            json={
                "values": {"OPERATOR_API_TRAINING_DOMAINS": "example.com,training.local,demo.example"},
            },
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["changed"] == ["OPERATOR_API_TRAINING_DOMAINS"]
        assert any(e["action"] == "console.config.update" for e in audit.events)


def test_console_config_rejects_unknown_keys(env_file: str) -> None:
    app = _app(env_file)
    with TestClient(app) as client:
        token = _login(client)
        resp = client.put(
            "/api/v1/console/config",
            headers=_auth(token),
            json={
                "values": {"DATABASE_URL": "postgresql://evil:evil@example.com/x"},
            },
        )
        assert resp.status_code == 403


def test_console_config_requires_admin_token(env_file: str) -> None:
    app = _app(env_file)
    settings = _settings(env_file)
    with TestClient(app) as client:
        claims = {
            "sub": "low-priv",
            "iss": settings.oidc_issuer,
            "aud": settings.oidc_audience,
            "exp": 2_000_000_000,
            "nbf": 0,
            "realm_access": {"roles": ["campaign_author"]},
        }
        token = jwt.encode(claims, settings.require_console_jwt_secret(), algorithm="HS256")
        resp = client.get("/api/v1/console/config", headers=_auth(token))
        assert resp.status_code == 403


def test_console_rejects_unrecognized_roles_fail_closed(env_file: str) -> None:
    """HIGH-01: unknown roles must not default to CAMPAIGN_OPERATOR."""
    app = _app(env_file)
    settings = _settings(env_file)
    with TestClient(app) as client:
        claims = {
            "sub": str(uuid.uuid4()),
            "iss": settings.oidc_issuer,
            "aud": settings.oidc_audience,
            "exp": 2_000_000_000,
            "nbf": 0,
            "realm_access": {"roles": ["no-such-role"]},
        }
        token = jwt.encode(claims, settings.require_console_jwt_secret(), algorithm="HS256")
        resp = client.get("/api/v1/console/status", headers=_auth(token))
        assert resp.status_code == 403


def test_console_token_signed_with_audit_key_is_rejected(env_file: str) -> None:
    """CRIT-03: the audit HMAC key must not double as the JWT secret."""
    app = _app(env_file)
    settings = _settings(env_file)
    with TestClient(app) as client:
        claims = {
            "sub": str(uuid.uuid4()),
            "iss": settings.oidc_issuer,
            "aud": settings.oidc_audience,
            "exp": 2_000_000_000,
            "nbf": 0,
            "realm_access": {"roles": ["administrator"]},
        }
        token = jwt.encode(claims, settings.require_secret_key(), algorithm="HS256")
        resp = client.get("/api/v1/console/status", headers=_auth(token))
        assert resp.status_code == 401


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


def test_audit_view_reads_from_audit_store(env_file: str) -> None:
    """CRIT-02: `/audit` must read from the injected AuditStore (dedicated
    audit engine), not the ORM session's `dm.AuditEvent` (which 500'd)."""
    audit = FakeAuditStore()
    audit.record(actor="admin", action="campaign.create", object_type="campaign", object_id="c1")
    audit.record(actor="admin", action="kill-switch.engage", object_type="system", object_id="delivery")
    app = _app(env_file, fake_audit=audit)
    with TestClient(app) as client:
        token = _login(client)
        resp = client.get("/api/v1/audit", headers=_auth(token))
        assert resp.status_code == 200, resp.text
        actions = [e["action"] for e in resp.json()]
        assert actions == ["kill-switch.engage", "campaign.create"]
