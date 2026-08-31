"""Tests for the browser console endpoints (login, config, status)."""

from __future__ import annotations

import os
import socket
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Self
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from fastapi.testclient import TestClient
from kp_authorization.rbac import Principal, Role
from kp_operator_api import console as console_module
from kp_operator_api.auth import OidcIdP
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.main import create_app

KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
CONSOLE_PASSWORD = "correct-horse-battery-staple"


def test_webhook_probe_fails_closed_if_validated_hostname_disappears(monkeypatch: pytest.MonkeyPatch) -> None:
    parsed = iter(
        (
            SimpleNamespace(
                scheme="https",
                hostname="hooks.example.com",
                username=None,
                password=None,
                fragment="",
                port=None,
            ),
            SimpleNamespace(hostname=None),
        )
    )
    monkeypatch.setattr(console_module, "urlparse", lambda _value: next(parsed))
    monkeypatch.setattr(
        console_module.socket,
        "create_connection",
        lambda *_args, **_kwargs: pytest.fail("a missing hostname must not reach the network"),
    )

    assert console_module._test_webhook("https://hooks.example.com") is False


def _acs_deployment_values() -> dict[str, str]:
    return {
        "deployment_stage": "foundation_bootstrap",
        "network_mode": "private",
        "acs_resource_mode": "provision",
        "acs_existing_communication_service_id": "",
        "acs_existing_email_endpoint": "",
        "acs_existing_email_domain_id": "",
        "acs_sending_domain": "mail.example.com",
        "acs_sender_local_part": "awareness",
        "acs_sender_display_name": "Security Awareness",
        "acs_dns_zone_id": "",
        "acs_daily_message_limit": "1000",
        "acs_messages_per_minute": "20",
        "acs_ramp_batch_size": "10",
        "acs_ramp_interval_seconds": "60",
        "allowed_recipient_domains": "example.com",
        "azure_deployment_client_id": "55555555-5555-4555-8555-555555555555",
        "ciphertext_active_key_id": "primary",
        "ciphertext_prior_key_ids": "",
        "ciphertext_prior_keys_secret_id": "",
    }


class FakeAuditStore:
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    def record(self, actor, action, object_type, object_id, detail=None) -> None:
        self.events.append(
            {
                "actor": actor,
                "action": action,
                "object_type": object_type,
                "object_id": object_id,
                "detail": detail or {},
            }
        )

    def list_events(self, limit: int = 500) -> list[dict[str, object]]:
        return list(reversed(self.events))[-limit:]


@pytest.fixture()
def env_file(tmp_path) -> str:
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


def _admin_token(settings: OperatorApiSettings) -> str:
    claims = {
        "sub": str(uuid.uuid4()),
        "iss": settings.oidc_issuer,
        "aud": settings.oidc_audience,
        "exp": 2_000_000_000,
        "nbf": 0,
        "realm_access": {"roles": ["administrator"]},
    }
    return jwt.encode(claims, settings.require_console_jwt_secret(), algorithm="HS256")


def _role_token(settings: OperatorApiSettings, *roles: str) -> str:
    claims = {
        "sub": str(uuid.uuid4()),
        "iss": settings.oidc_issuer,
        "aud": settings.oidc_audience,
        "exp": 2_000_000_000,
        "nbf": 0,
        "realm_access": {"roles": list(roles)},
    }
    return jwt.encode(claims, settings.require_console_jwt_secret(), algorithm="HS256")


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
        assert session["approval_limited"] is False
        assert session["roles"] == ["administrator"]
        expected_capabilities = sorted(
            f"{capability.action}:{capability.object}"
            for capability in Principal(subject_id="expected", roles={Role.ADMINISTRATOR}).capabilities()
        )
        assert session["capabilities"] == expected_capabilities
        assert "manage:roles" in session["capabilities"]
        assert token not in str(session["roles"] + session["capabilities"])


def test_oidc_current_session_derives_multi_role_capabilities_server_side(
    env_file: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(env_file).model_copy(update={"oidc_mode": "oidc"})
    principal = Principal(
        subject_id=str(uuid.uuid4()),
        roles={Role.CAMPAIGN_AUTHOR, Role.AUDITOR},
    )
    monkeypatch.setattr(OidcIdP, "verify", lambda _self, _token: principal)

    with TestClient(create_app(settings)) as client:
        client.cookies.set("kp_oidc_session", "opaque-access-token")
        response = client.get("/api/v1/console/session")

    assert response.status_code == 200
    body = response.json()
    assert body["token"] == ""
    assert body["roles"] == ["auditor", "campaign_author"]
    assert body["capabilities"] == [
        "create:campaign",
        "view:audit",
        "view_aggregate:results",
        "view_named:results",
    ]
    assert "opaque-access-token" not in response.text


def test_oidc_current_session_unknown_role_is_empty_and_fail_closed(
    env_file: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(env_file).model_copy(update={"oidc_mode": "oidc"})
    principal = Principal(subject_id=str(uuid.uuid4()), roles=set())
    monkeypatch.setattr(OidcIdP, "verify", lambda _self, _token: principal)

    with TestClient(create_app(settings)) as client:
        client.cookies.set("kp_oidc_session", "unknown-role-access-token")
        response = client.get("/api/v1/console/session")

    assert response.status_code == 200
    assert response.json()["roles"] == []
    assert response.json()["capabilities"] == []
    assert "unknown-role-access-token" not in response.text


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
            "authorization_endpoint": f"{settings.oidc_issuer}/authorize",
            "token_endpoint": f"{settings.oidc_issuer}/token",
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
    redirect_uri = "https://console.example/api/v1/console/oidc/callback"
    settings = _settings(env_file).model_copy(update={"oidc_mode": "oidc", "oidc_redirect_uri": redirect_uri})
    transaction: dict[str, str] = {}

    async def metadata(_issuer: str) -> dict[str, str]:
        return {
            "authorization_endpoint": f"{settings.oidc_issuer}/authorize",
            "token_endpoint": f"{settings.oidc_issuer}/token",
        }

    class TokenResponse:
        async def __aenter__(self) -> httpx.Response:
            return httpx.Response(
                200,
                request=httpx.Request("POST", "http://127.0.0.1:8443/realms/kingphisher/token"),
                json={"access_token": "access-token", "id_token": "id-token"},
            )

        async def __aexit__(self, *_args: object) -> None:
            pass

    class FakeClient:
        def __init__(self, **kwargs: object) -> None:
            assert kwargs["follow_redirects"] is False
            assert kwargs["trust_env"] is False
            assert kwargs["http2"] is False

        async def __aenter__(self) -> Self:
            return self

        async def __aexit__(self, *_args: object) -> None:
            pass

        def stream(
            self,
            method: str,
            url: str,
            *,
            data: dict[str, str],
            headers: dict[str, str],
            extensions: dict[str, str],
        ) -> TokenResponse:
            assert method == "POST"
            assert url == "http://127.0.0.1:8443/realms/kingphisher/token"
            assert headers == {"Host": "localhost:8443"}
            assert extensions == {}
            assert data["code_verifier"] == transaction["verifier"]
            assert data["code"] == "authorization-code"
            assert data["redirect_uri"] == redirect_uri
            return TokenResponse()

    monkeypatch.setattr(console_module, "_oidc_metadata", metadata)
    monkeypatch.setattr(
        console_module,
        "resolve_oidc_endpoint",
        lambda *_args, **_kwargs: SimpleNamespace(
            request_url="http://127.0.0.1:8443/realms/kingphisher/token",
            host_header="localhost:8443",
            extensions={},
        ),
    )
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
    with TestClient(create_app(settings), base_url="https://console.example") as client:
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
        session_cookie = next(
            value for value in response.headers.get_list("set-cookie") if value.startswith("kp_oidc_session=")
        )
        assert "Secure" in session_cookie


@pytest.mark.parametrize(
    "redirect_uri",
    (
        "http://console.example/api/v1/console/oidc/callback",
        "http://127.0.0.1:8000/api/v1/console/oidc/callback",
        "http://localhost:8001/api/v1/console/oidc/callback",
        "https://user@console.example/api/v1/console/oidc/callback",
        "https://console.example/wrong/callback",
        "https://console.example/api/v1/console/oidc/callback?next=/console",
        "https://console.example/api/v1/console/oidc/callback#fragment",
    ),
)
def test_oidc_redirect_uri_policy_rejects_plaintext_and_callback_evasions(redirect_uri: str) -> None:
    with pytest.raises(ValueError, match="redirect URI"):
        console_module._validated_oidc_redirect_uri(redirect_uri)


def test_oidc_start_rejects_unsafe_redirect_before_provider_discovery(
    env_file: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(env_file).model_copy(
        update={
            "oidc_mode": "oidc",
            "oidc_redirect_uri": "http://console.example/api/v1/console/oidc/callback",
        }
    )

    async def metadata(_issuer: str) -> dict[str, str]:
        pytest.fail("an unsafe redirect URI must fail before identity-provider discovery")

    monkeypatch.setattr(console_module, "_oidc_metadata", metadata)
    with TestClient(create_app(settings)) as client:
        response = client.get("/api/v1/console/oidc/start")

    assert response.status_code == 401


def test_oidc_start_marks_transaction_cookie_secure_for_https_callback(
    env_file: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    redirect_uri = "https://console.example/api/v1/console/oidc/callback"
    settings = _settings(env_file).model_copy(update={"oidc_mode": "oidc", "oidc_redirect_uri": redirect_uri})

    async def metadata(_issuer: str) -> dict[str, str]:
        return {"authorization_endpoint": f"{settings.oidc_issuer}/authorize"}

    monkeypatch.setattr(console_module, "_oidc_metadata", metadata)
    with TestClient(create_app(settings), base_url="https://console.example") as client:
        response = client.get("/api/v1/console/oidc/start")

    assert response.status_code == 200
    assert parse_qs(urlparse(response.json()["authorization_url"]).query)["redirect_uri"] == [redirect_uri]
    transaction_cookie = next(
        value for value in response.headers.get_list("set-cookie") if value.startswith("kp_oidc_transaction=")
    )
    assert "Secure" in transaction_cookie


def test_oidc_start_rejects_cross_origin_authorization_endpoint(env_file: str, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(env_file).model_copy(update={"oidc_mode": "oidc"})

    async def metadata(_issuer: str) -> dict[str, str]:
        return {"authorization_endpoint": "https://attacker.example/authorize"}

    monkeypatch.setattr(console_module, "_oidc_metadata", metadata)
    with TestClient(create_app(settings)) as client:
        response = client.get("/api/v1/console/oidc/start")

    assert response.status_code == 401


def test_oidc_callback_rejects_cross_origin_token_endpoint_before_secret_use(
    env_file: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(env_file).model_copy(update={"oidc_mode": "oidc"})

    async def metadata(_issuer: str) -> dict[str, str]:
        return {
            "authorization_endpoint": f"{settings.oidc_issuer}/authorize",
            "token_endpoint": "https://attacker.example/token",
        }

    monkeypatch.setattr(console_module, "_oidc_metadata", metadata)
    monkeypatch.setattr(
        console_module,
        "_oidc_token_response",
        lambda *_args, **_kwargs: pytest.fail("an untrusted token endpoint must not receive credentials"),
    )
    with TestClient(create_app(settings)) as client:
        start = client.get("/api/v1/console/oidc/start")
        state = parse_qs(urlparse(start.json()["authorization_url"]).query)["state"][0]
        response = client.get(
            "/api/v1/console/oidc/callback",
            params={"code": "authorization-code", "state": state},
        )

    assert response.status_code == 401


def test_oidc_callback_rejects_state_mismatch(env_file: str, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(env_file).model_copy(update={"oidc_mode": "oidc"})

    async def metadata(_issuer: str) -> dict[str, str]:
        return {"authorization_endpoint": f"{settings.oidc_issuer}/authorize"}

    monkeypatch.setattr(console_module, "_oidc_metadata", metadata)
    with TestClient(create_app(settings)) as client:
        client.get("/api/v1/console/oidc/start")
        response = client.get(
            "/api/v1/console/oidc/callback",
            params={"code": "code", "state": "attacker-state"},
        )
        assert response.status_code == 401


def test_console_session_requires_configured_password(tmp_path) -> None:
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
        assert body["config_store"] == "env_file"
        assert body["mutable"] is True


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


@pytest.mark.parametrize("path", ("/api/v1/console/config", "/api/v1/console/onboarding"))
def test_ai_destination_change_requires_fresh_credentials_through_every_mutation_route(
    env_file: str,
    path: str,
) -> None:
    console_module.set_key(env_file, "KP_WORKER_AI_BASE_URL", "https://ai.old.example")
    console_module.set_key(env_file, "KP_WORKER_AI_BEARER_TOKEN", "stored-token")
    console_module.set_key(env_file, "KP_WORKER_AI_API_KEY", "stored-key")
    app = _app(env_file)
    with TestClient(app) as client:
        headers = _auth(_login(client))
        rejected = client.put(
            path,
            headers=headers,
            json={
                "values": {
                    "KP_WORKER_AI_BASE_URL": "https://ai.new.example",
                    "KP_WORKER_AI_BEARER_TOKEN": "",
                    "KP_WORKER_AI_API_KEY": "",
                },
                **({"completed": False} if path.endswith("onboarding") else {}),
            },
        )

        assert rejected.status_code == 422, rejected.text
        assert "re-entering every configured credential" in rejected.text
        unchanged = console_module._env_values(Path(env_file))
        assert unchanged["KP_WORKER_AI_BASE_URL"] == "https://ai.old.example"
        assert unchanged["KP_WORKER_AI_BEARER_TOKEN"] == "stored-token"
        assert unchanged["KP_WORKER_AI_API_KEY"] == "stored-key"

        accepted = client.put(
            path,
            headers=headers,
            json={
                "values": {
                    "KP_WORKER_AI_BASE_URL": "https://ai.new.example",
                    "KP_WORKER_AI_BEARER_TOKEN": "fresh-token",
                    "KP_WORKER_AI_API_KEY": "fresh-key",
                },
                **({"completed": False} if path.endswith("onboarding") else {}),
            },
        )

    assert accepted.status_code == 200, accepted.text
    updated = console_module._env_values(Path(env_file))
    assert updated["KP_WORKER_AI_BASE_URL"] == "https://ai.new.example"
    assert updated["KP_WORKER_AI_BEARER_TOKEN"] == "fresh-token"
    assert updated["KP_WORKER_AI_API_KEY"] == "fresh-key"


@pytest.mark.parametrize("path", ("/api/v1/console/config", "/api/v1/console/onboarding"))
def test_oidc_redirect_policy_applies_to_every_configuration_mutation_route(env_file: str, path: str) -> None:
    with TestClient(_app(env_file)) as client:
        response = client.put(
            path,
            headers=_auth(_login(client)),
            json={
                "values": {"OPERATOR_API_OIDC_REDIRECT_URI": "http://console.example/api/v1/console/oidc/callback"},
                **({"completed": False} if path.endswith("onboarding") else {}),
            },
        )

    assert response.status_code == 422, response.text
    assert "must use HTTPS" in response.text
    assert "OPERATOR_API_OIDC_REDIRECT_URI" not in console_module._env_values(Path(env_file))


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


@pytest.mark.parametrize(
    "retired_key",
    ["KP_WORKER_REMINDER_AFTER_HOURS", "KP_WORKER_MAILPIT_SMTP_TLS", "KP_WORKER_QUEUE_PREFIX"],
)
def test_console_rejects_retired_worker_settings(env_file: str, retired_key: str) -> None:
    assert retired_key not in console_module._ALLOWED_KEYS
    with TestClient(_app(env_file)) as client:
        response = client.put(
            "/api/v1/console/config",
            headers=_auth(_login(client)),
            json={"values": {retired_key: "true"}},
        )

    assert response.status_code == 403


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


def test_onboarding_state_returns_only_nonsecret_values(env_file: str) -> None:
    app = _app(env_file)
    with TestClient(app) as client:
        token = _login(client)
        response = client.get("/api/v1/console/onboarding", headers=_auth(token))
        assert response.status_code == 200
        body = response.json()
        assert body["completed"] is False
        assert body["complete"] is False
        assert {step["component"] for step in body["steps"]} >= {"identity", "graph", "smtp"}
        assert CONSOLE_PASSWORD not in response.text
        assert "values" not in body
        secret_fields = [field for step in body["steps"] for field in step["fields"] if field["secret"]]
        assert secret_fields and all(field["value"] == "" for field in secret_fields)
        identity = next(step for step in body["steps"] if step["component"] == "identity")
        assert identity["estimated_minutes"] > 0
        assert identity["prerequisites"]
        mode = next(field for field in identity["fields"] if field["key"] == "OPERATOR_API_OIDC_MODE")
        assert {choice["value"] for choice in mode["choices"]} == {"dev", "oidc"}
        audience = next(field for field in identity["fields"] if field["key"] == "OPERATOR_API_OIDC_AUDIENCE")
        assert "identifier" in audience["help"]
        assert audience["example"] == "api://phishing-awareness-platform"
        assert "API registration" in audience["where_to_find"]
        training = next(step for step in body["steps"] if step["component"] == "training")
        assert {field["key"] for field in training["fields"]} == {
            "OPERATOR_API_TRAINING_BASE_URL",
            "OPERATOR_API_TRAINING_DOMAINS",
        }
        email = next(step for step in body["steps"] if step["component"] == "smtp")
        assert "KP_WORKER_ACS_CLIENT_ID" in {field["key"] for field in email["fields"]}
        assert email["provider_key"] == "KP_WORKER_EMAIL_PROVIDER"
        email_fields = {field["key"]: field for field in email["fields"]}
        assert {choice["value"] for choice in email_fields["KP_WORKER_EMAIL_PROVIDER"]["choices"]} == {
            "smtp",
            "azure_communication_services",
        }
        assert email_fields["KP_WORKER_SMTP_ADDRESS"]["providers"] == ["smtp"]
        assert email_fields["KP_WORKER_ACS_EMAIL_ENDPOINT"]["required_for"] == ["azure_communication_services"]
        mailbox = next(step for step in body["steps"] if step["component"] == "mailbox")
        assert mailbox["provider_key"] == "KP_WORKER_REPORTED_MAILBOX_PROVIDER"
        mailbox_fields = {field["key"]: field for field in mailbox["fields"]}
        assert {choice["value"] for choice in mailbox_fields["KP_WORKER_REPORTED_MAILBOX_PROVIDER"]["choices"]} == {
            "mailpit",
            "microsoft365",
        }
        assert mailbox_fields["KP_WORKER_REPORTED_MAILBOX_BEARER_TOKEN"]["secret"] is True
        assert mailbox_fields["KP_WORKER_REPORTED_MAILBOX_BEARER_TOKEN"]["value"] == ""


@pytest.mark.parametrize("role", ["campaign_author", "auditor"])
def test_console_help_explains_setup_terms_to_operational_roles(env_file: str, role: str) -> None:
    settings = _settings(env_file)
    with TestClient(_app(env_file)) as client:
        response = client.get("/api/v1/console/help", headers=_auth(_role_token(settings, role)))
        assert response.status_code == 200
        body = response.json()
        terms = {entry["term"] for entry in body["glossary"]}
        assert {
            "OIDC",
            "Audience",
            "Client ID",
            "SMTP",
            "STARTTLS",
            "API key",
            "Webhook",
            "Azure subscription ID",
            "Tenant ID",
            "Terraform state",
            "Workload identity",
        } <= terms
        assert any(topic["id"] == "azure-deployment" for topic in body["topics"])
        assert "Never paste" in body["safety_note"]


def test_console_help_rejects_unauthenticated_and_no_role_users(env_file: str) -> None:
    settings = _settings(env_file)
    with TestClient(_app(env_file)) as client:
        assert client.get("/api/v1/console/help").status_code == 401
        no_role = client.get("/api/v1/console/help", headers=_auth(_role_token(settings)))

    assert no_role.status_code == 403


def test_azure_deployment_wizard_is_nonsecret_and_guided(env_file: str) -> None:
    with TestClient(_app(env_file)) as client:
        assert client.get("/api/v1/console/azure-deployment").status_code == 401
        body = client.get("/api/v1/console/azure-deployment", headers=_auth(_login(client))).json()
    assert len(body["steps"]) == 5
    fields = [field for step in body["steps"] for field in step["fields"]]
    assert fields and all(field["secret"] is False for field in fields)
    assert all(field["where_to_find"] for field in fields)
    assert "never asks" in body["safety_note"]
    assert {step["id"] for step in body["steps"]} == {
        "azure_foundation",
        "azure_identity_dns",
        "azure_email",
        "azure_integrations",
        "azure_automation",
    }
    assert body["microsoft_graph"]["readiness_claim"] == "configuration_only"
    assert body["microsoft_graph"]["identity_separation"]
    assert body["acs_email"]["managed_domain_fallback"] is False
    assert body["acs_email"]["delivery_events_implemented"] is True
    assert body["orchestration"]["deployment_stages"] == [
        "foundation_bootstrap",
        "foundation_finalize",
        "workloads",
    ]
    assert body["orchestration"]["acs_evidence_schema"] == "kp.acs-stage-result.v1"
    fields_by_key = {field["key"]: field for field in fields}
    assert fields_by_key["ai_endpoint"]["required"] is True
    assert fields_by_key["ai_endpoint"]["advanced"] is False
    assert "first approved pattern" in fields_by_key["ai_endpoint"]["where_to_find"]
    assert [choice["value"] for choice in fields_by_key["deployment_stage"]["choices"]] == [
        "foundation_bootstrap",
        "foundation_finalize",
        "workloads",
    ]
    assert fields_by_key["deployment_stage"]["server_controlled"] is True
    assert fields_by_key["deployment_stage"]["suggested_default"] == "foundation_bootstrap"
    assert [choice["value"] for choice in fields_by_key["network_mode"]["choices"]] == ["private"]
    assert fields_by_key["network_mode"]["suggested_default"] == "private"
    assert fields_by_key["environment"]["suggested_default"] == "staging"
    assert fields_by_key["name_prefix"]["suggested_default"] == "kp"
    assert fields_by_key["location"]["suggested_default"] == "eastus2"
    assert "fixed after foundation" in fields_by_key["ciphertext_active_key_id"]["where_to_find"]
    assert "rotation is not yet supported" in fields_by_key["ciphertext_active_key_id"]["where_to_find"]
    assert "legacy recovery" in fields_by_key["ciphertext_prior_key_ids"]["where_to_find"]
    assert "does not rotate the active key" in fields_by_key["ciphertext_prior_key_ids"]["where_to_find"]
    readiness = body["release_readiness"]
    assert readiness["evidence_level"] == "local_contract_only"
    assert readiness["production_plan_allowed"] is False
    assert readiness["staging_plan_allowed"] is True
    assert {gate["id"]: gate["status"] for gate in readiness["gates"]} == {
        "operator_hsts_application": "implemented_unproven_at_edge",
        "operator_custom_domain": "external_unverified",
        "tracking_custom_domain": "external_unverified",
        "managed_certificates": "external_unverified",
        "default_host_restriction": "not_implemented",
        "waf_edge": "not_implemented",
        "live_hsts_observation": "external_unverified",
        "backup_restore": "external_unverified",
        "rollback": "unsupported",
    }
    assert "token" not in " ".join(field["label"].lower() for field in fields)


def test_azure_deployment_advanced_fields_are_classified_and_defaulted(env_file: str) -> None:
    with TestClient(_app(env_file)) as client:
        body = client.get("/api/v1/console/azure-deployment", headers=_auth(_login(client))).json()
    fields = [field for step in body["steps"] for field in step["fields"]]
    by_key = {field["key"]: field for field in fields}
    advanced_expected = {
        "acs_resource_mode",
        "acs_existing_communication_service_id",
        "acs_existing_email_endpoint",
        "acs_existing_email_domain_id",
        "acs_dns_zone_id",
        "acs_daily_message_limit",
        "acs_messages_per_minute",
        "acs_ramp_batch_size",
        "acs_ramp_interval_seconds",
        "runner_label",
        "tf_state_resource_group",
        "tf_state_storage_account",
        "tf_state_container",
        "network_mode",
        "azure_deployment_client_id",
        "ciphertext_active_key_id",
        "ciphertext_prior_key_ids",
        "ciphertext_prior_keys_secret_id",
        "directory_group_ids",
        "reported_mailbox_address",
        "alert_webhook_domains",
    }
    normal_expected = {
        "subscription_id",
        "environment",
        "location",
        "name_prefix",
        "entra_tenant_id",
        "operator_fqdn",
        "tracking_fqdn",
        "acs_sending_domain",
        "acs_sender_local_part",
        "acs_sender_display_name",
        "communication_data_location",
        "ai_endpoint",
        "enable_directory_sync",
        "enable_reported_mailbox",
        "allowed_recipient_domains",
    }
    assert set(by_key) >= (advanced_expected | normal_expected)
    assert all(by_key[key]["advanced"] is True for key in advanced_expected)
    assert all(by_key[key]["advanced"] is False for key in normal_expected)
    assert by_key["deployment_stage"]["advanced"] is False  # server-controlled, shown on the common path
    assert by_key["deployment_stage"]["server_controlled"] is True
    assert by_key["deployment_stage"]["suggested_default"] == "foundation_bootstrap"
    assert by_key["acs_sender_display_name"]["suggested_default"] == "Security Awareness"
    assert by_key["acs_sending_domain"]["suggested_default"] == "mail.example.com"
    assert by_key["acs_messages_per_minute"]["suggested_default"] == "20"
    assert by_key["location"]["suggested_default"] == "eastus2"
    assert by_key["environment"]["suggested_default"] == "staging"
    # Advanced internals that stay hidden may carry a suggested default or not,
    # but every field must report a boolean so the GUI cannot misread it.
    assert all(field["advanced"] is True or field["advanced"] is False for field in fields)


def test_azure_deployment_validation_accepts_safe_values_and_rejects_bad_hosts(env_file: str) -> None:
    valid = {
        **_acs_deployment_values(),
        "subscription_id": "11111111-1111-1111-1111-111111111111",
        "environment": "staging",
        "location": "eastus2",
        "name_prefix": "kp",
        "entra_tenant_id": "22222222-2222-2222-2222-222222222222",
        "entra_client_id": "33333333-3333-3333-3333-333333333333",
        "operator_fqdn": "awareness.example.com",
        "tracking_fqdn": "awareness-track.example.com",
        "communication_data_location": "United States",
        "ai_endpoint": "https://ai-gateway.example.com",
        "enable_directory_sync": "false",
        "directory_group_ids": "",
        "enable_reported_mailbox": "false",
        "reported_mailbox_address": "",
        "reported_mailbox_folder": "inbox",
        "alert_webhook_domains": "ntfy.example.com,hooks.example.com",
        "tf_state_resource_group": "rg-kp-state",
        "tf_state_storage_account": "kptfstateprod",
        "tf_state_container": "tfstate",
        "runner_label": "azure-vnet",
    }
    with TestClient(_app(env_file)) as client:
        headers = _auth(_login(client))
        response = client.post("/api/v1/console/azure-deployment/validate", headers=headers, json={"values": valid})
        assert response.status_code == 200
        assert response.json()["ok"] is True
        assert response.json()["errors"] == {}
        assert response.json()["warnings"] == []
        assert response.json()["release_readiness"]["evidence_level"] == "local_contract_only"
        assert response.json()["release_readiness"]["production_plan_allowed"] is False
        assert response.json()["provider_readiness"] == {
            "enabled_roles": [],
            "configuration_valid": True,
            "admin_consent_verified": False,
            "live_connectivity_verified": False,
        }
        foundation = dict(
            valid,
            deployment_stage="foundation_bootstrap",
        )
        response = client.post(
            "/api/v1/console/azure-deployment/validate", headers=headers, json={"values": foundation}
        )
        assert response.json()["ok"] is True
        assert response.json()["acs_email_readiness"]["deployment_stage"] == "foundation_bootstrap"
        assert response.json()["acs_email_readiness"]["advance_blocked_until_verified_artifact"] is True
        response = client.post(
            "/api/v1/console/azure-deployment/validate",
            headers=headers,
            json={"values": {**foundation, "deployment_stage": "workloads", "network_mode": "starter"}},
        )
        assert response.json()["ok"] is False
        assert "network_mode" in response.json()["errors"]
        existing = dict(
            valid,
            acs_resource_mode="existing",
            acs_existing_communication_service_id=(
                "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg-acs/"
                "providers/Microsoft.Communication/CommunicationServices/acs-existing"
            ),
            acs_existing_email_endpoint="https://acs-existing.communication.azure.com",
            acs_existing_email_domain_id=(
                "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg-acs/"
                "providers/Microsoft.Communication/emailServices/email-existing/domains/mail.example.com"
            ),
        )
        response = client.post("/api/v1/console/azure-deployment/validate", headers=headers, json={"values": existing})
        assert response.json()["ok"] is True
        explicit_tls_port = dict(
            existing,
            acs_existing_email_endpoint="https://acs-existing.communication.azure.com:443/",
        )
        response = client.post(
            "/api/v1/console/azure-deployment/validate", headers=headers, json={"values": explicit_tls_port}
        )
        assert response.json()["ok"] is True
        for endpoint in (
            "endpoint=https://acs.example;accesskey=secret",
            "https://nested.acs-existing.communication.azure.com",
            "https://acs-existing.communication.azure.com:444",
            "https://-acs.communication.azure.com",
            "https://acs-.communication.azure.com",
        ):
            unsafe_existing = dict(existing, acs_existing_email_endpoint=endpoint)
            response = client.post(
                "/api/v1/console/azure-deployment/validate", headers=headers, json={"values": unsafe_existing}
            )
            assert response.json()["ok"] is False
            assert "acs_existing_email_endpoint" in response.json()["errors"]
        invalid = dict(
            valid, tracking_fqdn="https://awareness.example.com/path", ai_endpoint="https://user:pass@ai.example"
        )
        response = client.post("/api/v1/console/azure-deployment/validate", headers=headers, json={"values": invalid})
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert {"tracking_fqdn", "ai_endpoint"} <= response.json()["errors"].keys()
        for local_ai_endpoint in ("https://localhost", "https://127.0.0.2"):
            response = client.post(
                "/api/v1/console/azure-deployment/validate",
                headers=headers,
                json={"values": {**valid, "ai_endpoint": local_ai_endpoint}},
            )
            assert response.json()["ok"] is False
            assert "ai_endpoint" in response.json()["errors"]
        forbidden = client.post(
            "/api/v1/console/azure-deployment/validate",
            headers=headers,
            json={"values": {**valid, "client_secret": "never-accepted"}},
        )
        assert forbidden.status_code == 403
        hostile_key = client.post(
            "/api/v1/console/azure-deployment/validate",
            headers=headers,
            json={"values": {**valid, "token=github_pat_never_return_this_key_material": "unused"}},
        )
        assert hostile_key.status_code == 403
        assert "github_pat" not in str(hostile_key.json())
        credential_like = client.post(
            "/api/v1/console/azure-deployment/validate",
            headers=headers,
            json={"values": {**valid, "acs_sender_display_name": "token=github_pat_never_return_this_value"}},
        )
        assert credential_like.status_code == 200
        assert credential_like.json()["ok"] is False
        assert "github_pat" not in str(credential_like.json())


def test_azure_ciphertext_recovery_accepts_only_versionless_secret_metadata(env_file: str) -> None:
    subscription_id = "11111111-1111-1111-1111-111111111111"
    base = {
        **_acs_deployment_values(),
        "subscription_id": subscription_id,
        "environment": "staging",
        "location": "eastus2",
        "name_prefix": "kp",
        "entra_tenant_id": "22222222-2222-2222-2222-222222222222",
        "entra_client_id": "33333333-3333-3333-3333-333333333333",
        "operator_fqdn": "awareness.example.com",
        "tracking_fqdn": "awareness-track.example.com",
        "communication_data_location": "United States",
        "ai_endpoint": "https://ai-gateway.example.com",
        "enable_directory_sync": "false",
        "directory_group_ids": "",
        "enable_reported_mailbox": "false",
        "reported_mailbox_address": "",
        "reported_mailbox_folder": "inbox",
        "alert_webhook_domains": "",
        "tf_state_resource_group": "rg-kp-state",
        "tf_state_storage_account": "kptfstateprod",
        "tf_state_container": "tfstate",
        "runner_label": "azure-vnet",
    }
    reference = (
        f"/subscriptions/{subscription_id}/resourceGroups/rg-kp-staging/providers/"
        "Microsoft.KeyVault/vaults/kp-staging-vault/secrets/ciphertext-prior-keys"
    )
    valid_rotation = {
        **base,
        "deployment_stage": "workloads",
        "ciphertext_active_key_id": "2026q3",
        "ciphertext_prior_key_ids": "primary,2026q2",
        "ciphertext_prior_keys_secret_id": reference,
    }

    with TestClient(_app(env_file)) as client:
        headers = _auth(_login(client))
        accepted = client.post(
            "/api/v1/console/azure-deployment/validate", headers=headers, json={"values": valid_rotation}
        )
        assert accepted.json()["ok"] is True
        for changes in (
            {"ciphertext_prior_keys_secret_id": f"{reference}/version-id"},
            {"ciphertext_prior_key_ids": "primary,primary"},
            {"ciphertext_prior_key_ids": "primary,"},
            {"ciphertext_prior_key_ids": "2026q3"},
            {"ciphertext_prior_keys_secret_id": ""},
            {"deployment_stage": "foundation_bootstrap"},
        ):
            rejected = client.post(
                "/api/v1/console/azure-deployment/validate",
                headers=headers,
                json={"values": {**valid_rotation, **changes}},
            )
            assert rejected.json()["ok"] is False
            assert any(key.startswith("ciphertext_") for key in rejected.json()["errors"])


def test_azure_ciphertext_recovery_validation_never_reflects_key_material(env_file: str) -> None:
    raw_key = "ab" * 32
    values = {
        **_acs_deployment_values(),
        "ciphertext_active_key_id": "rotated",
        "ciphertext_prior_key_ids": "primary",
        "ciphertext_prior_keys_secret_id": f"primary={raw_key}",
    }
    with TestClient(_app(env_file)) as client:
        headers = _auth(_login(client))
        response = client.post("/api/v1/console/azure-deployment/validate", headers=headers, json={"values": values})

    assert response.json()["ok"] is False
    assert raw_key not in response.text


def test_azure_deployment_validation_requires_ai_generation_gateway(env_file: str) -> None:
    """Managed Azure cannot enter a first-template dead end."""
    values = {
        **_acs_deployment_values(),
        "subscription_id": "11111111-1111-1111-1111-111111111111",
        "environment": "staging",
        "location": "eastus2",
        "name_prefix": "kp",
        "entra_tenant_id": "22222222-2222-2222-2222-222222222222",
        "entra_client_id": "33333333-3333-3333-3333-333333333333",
        "operator_fqdn": "awareness.example.com",
        "tracking_fqdn": "awareness-track.example.com",
        "communication_data_location": "United States",
        "ai_endpoint": "",
        "enable_directory_sync": "false",
        "directory_group_ids": "",
        "enable_reported_mailbox": "false",
        "reported_mailbox_address": "",
        "reported_mailbox_folder": "inbox",
        "alert_webhook_domains": "",
        "tf_state_resource_group": "rg-kp-state",
        "tf_state_storage_account": "kptfstateprod",
        "tf_state_container": "tfstate",
        "runner_label": "azure-vnet",
    }
    with TestClient(_app(env_file)) as client:
        headers = _auth(_login(client))
        response = client.post("/api/v1/console/azure-deployment/validate", headers=headers, json={"values": values})
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is False
    assert "first template" in body["errors"]["ai_endpoint"]
    assert body["warnings"] == []


def test_azure_provider_readiness_requires_selected_groups_and_mailbox(env_file: str) -> None:
    values = {
        **_acs_deployment_values(),
        "subscription_id": "11111111-1111-1111-1111-111111111111",
        "environment": "staging",
        "location": "eastus2",
        "name_prefix": "kp",
        "entra_tenant_id": "22222222-2222-2222-2222-222222222222",
        "entra_client_id": "33333333-3333-3333-3333-333333333333",
        "operator_fqdn": "awareness.example.com",
        "tracking_fqdn": "awareness-track.example.com",
        "communication_data_location": "United States",
        "ai_endpoint": "https://ai-gateway.example.com",
        "enable_directory_sync": "true",
        "directory_group_ids": "",
        "enable_reported_mailbox": "true",
        "reported_mailbox_address": "",
        "reported_mailbox_folder": "inbox",
        "alert_webhook_domains": "",
        "tf_state_resource_group": "rg-kp-state",
        "tf_state_storage_account": "kptfstateprod",
        "tf_state_container": "tfstate",
        "runner_label": "azure-vnet",
    }
    with TestClient(_app(env_file)) as client:
        headers = _auth(_login(client))
        invalid = client.post(
            "/api/v1/console/azure-deployment/validate",
            headers=headers,
            json={"values": values},
        ).json()
        values["directory_group_ids"] = "44444444-4444-4444-8444-444444444444"
        values["reported_mailbox_address"] = "phish-reports@example.com"
        valid = client.post(
            "/api/v1/console/azure-deployment/validate",
            headers=headers,
            json={"values": values},
        ).json()

    assert {"directory_group_ids", "reported_mailbox_address"} <= invalid["errors"].keys()
    assert invalid["provider_readiness"]["configuration_valid"] is False
    assert valid["ok"] is True
    assert valid["provider_readiness"]["enabled_roles"] == ["directory", "mailbox"]
    assert valid["provider_readiness"]["admin_consent_verified"] is False


@pytest.mark.parametrize(
    "obsolete_key",
    [
        "acs_domain_verification_status",
        "acs_spf_verification_status",
        "acs_dkim_verification_status",
        "acs_dkim2_verification_status",
        "acs_sender_username_status",
        "acs_domain_association_status",
        "acs_readiness_checked_at",
    ],
)
def test_azure_acs_readiness_is_fail_closed_and_secret_free(env_file: str, obsolete_key: str) -> None:
    values = {
        **_acs_deployment_values(),
        "subscription_id": "11111111-1111-1111-1111-111111111111",
        "environment": "staging",
        "location": "eastus2",
        "name_prefix": "kp",
        "entra_tenant_id": "22222222-2222-2222-2222-222222222222",
        "entra_client_id": "33333333-3333-3333-3333-333333333333",
        "operator_fqdn": "awareness.example.com",
        "tracking_fqdn": "awareness-track.example.com",
        "communication_data_location": "United States",
        "ai_endpoint": "",
        "enable_directory_sync": "false",
        "directory_group_ids": "",
        "enable_reported_mailbox": "false",
        "reported_mailbox_address": "",
        "reported_mailbox_folder": "inbox",
        "alert_webhook_domains": "",
        "tf_state_resource_group": "rg-kp-state",
        "tf_state_storage_account": "kptfstateprod",
        "tf_state_container": "tfstate",
        "runner_label": "azure-vnet",
        obsolete_key: "verified",
    }
    with TestClient(_app(env_file)) as client:
        response = client.post(
            "/api/v1/console/azure-deployment/validate",
            headers=_auth(_login(client)),
            json={"values": values},
        )

    assert response.status_code == 403
    assert "rejected unrecognized Azure deployment keys" in response.text
    assert "verified" not in response.text.lower()


def test_azure_deployment_assistance_is_advisory_and_nonsecret(env_file: str) -> None:
    with TestClient(_app(env_file)) as client:
        response = client.post(
            "/api/v1/console/onboarding/assist",
            headers=_auth(_login(client)),
            json={
                "component": "azure_identity_dns",
                "question": "Where do I find the tenant and application IDs? password=disposable-fake-secret",
                "values": {"entra_tenant_id": "22222222-2222-2222-2222-222222222222"},
            },
        )
    assert response.status_code == 200
    assert response.json()["suggestions"] == {}
    assert "Entra" in response.json()["answer"]
    assert "disposable-fake-secret" not in response.text


def test_setup_assist_falls_back_without_ai_and_does_not_audit(env_file: str) -> None:
    audit = FakeAuditStore()
    with TestClient(_app(env_file, fake_audit=audit)) as client:
        response = client.post(
            "/api/v1/console/onboarding/assist",
            headers=_auth(_login(client)),
            json={"component": "smtp", "question": "Which TLS option should I use?", "values": {}},
        )
        assert response.status_code == 200
        assert response.json()["source"] == "curated"
        assert "587" in response.json()["answer"]
        assert response.json()["suggestions"] == {}
        assert audit.events == []


def test_setup_assist_redacts_secrets_and_filters_ai_suggestions(
    env_file: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    console_module.set_key(env_file, "KP_WORKER_AI_BASE_URL", "https://ai.example")
    console_module.set_key(env_file, "KP_WORKER_AI_API_KEY", "stored-super-secret-key")
    captured: dict[str, object] = {}

    class AssistResponse:
        headers = httpx.Headers({"content-type": "application/json"})
        is_redirect = False

        def raise_for_status(self) -> None:
            return None

        async def aiter_bytes(self):
            yield httpx.Response(
                200,
                json={
                    "answer": "Use your registered application values.",
                    "suggestions": {
                        "OPERATOR_API_OIDC_AUDIENCE": "api://awareness",
                        "OPERATOR_API_OIDC_CLIENT_SECRET": "do-not-accept",
                        "KP_WORKER_SMTP_ADDRESS": "smtp.wrong-step.example:587",
                    },
                },
            ).content

    class AssistStream:
        async def __aenter__(self) -> AssistResponse:
            return AssistResponse()

        async def __aexit__(self, *_args: object) -> None:
            return None

    class FakeClient:
        def __init__(self, **kwargs: object) -> None:
            captured["client_kwargs"] = kwargs

        async def __aenter__(self) -> Self:
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        def stream(self, method: str, url: str, **kwargs: object) -> AssistStream:
            captured["method"] = method
            captured["url"] = url
            captured.update(kwargs)
            return AssistStream()

    monkeypatch.setattr(console_module.httpx, "AsyncClient", FakeClient)
    monkeypatch.setattr(
        console_module,
        "_resolve_setup_assist_endpoint",
        lambda *_args, **_kwargs: SimpleNamespace(
            request_url="https://93.184.216.34/setup-assist",
            host_header="ai.example",
            extensions={"sni_hostname": "ai.example"},
        ),
    )
    with TestClient(_app(env_file)) as client:
        response = client.post(
            "/api/v1/console/onboarding/assist",
            headers=_auth(_login(client)),
            json={
                "component": "identity",
                "question": "My token=question-secret, sk-standalonekey9, and stored-super-secret-key fail. Why?",
                "values": {
                    "OPERATOR_API_OIDC_AUDIENCE": "api://awareness",
                    "OPERATOR_API_OIDC_CLIENT_SECRET": "submitted-secret",
                    "KP_WORKER_SMTP_ADDRESS": "smtp.example:587",
                },
            },
        )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["source"] == "configured-ai"
    assert body["suggestions"] == {"OPERATOR_API_OIDC_AUDIENCE": "api://awareness"}
    sent = str(captured["json"])
    assert "question-secret" not in sent
    assert "sk-standalonekey9" not in sent
    assert "stored-super-secret-key" not in sent
    assert "submitted-secret" not in sent
    assert "smtp.example" not in sent
    assert captured["url"] == "https://93.184.216.34/setup-assist"
    assert captured["method"] == "POST"
    assert captured["headers"] == {"Host": "ai.example", "X-API-Key": "stored-super-secret-key"}
    assert captured["extensions"] == {"sni_hostname": "ai.example"}
    assert captured["client_kwargs"] == {
        "timeout": 5.0,
        "follow_redirects": False,
        "trust_env": False,
        "http2": False,
    }


def test_setup_assist_provider_failures_return_only_stable_curated_guidance(
    env_file: str, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    console_module.set_key(env_file, "KP_WORKER_AI_BASE_URL", "https://ai.example")
    provider_secret = "provider-body-secret-must-not-escape"

    class InvalidResponse:
        headers = httpx.Headers({"content-type": "application/json"})
        is_redirect = False

        def raise_for_status(self) -> None:
            return None

        async def aiter_bytes(self):
            yield httpx.Response(
                200,
                json={"answer": provider_secret, "extra": "not in the response contract"},
            ).content

    class InvalidStream:
        async def __aenter__(self) -> InvalidResponse:
            return InvalidResponse()

        async def __aexit__(self, *_args: object) -> None:
            return None

    class FakeClient:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def __aenter__(self) -> Self:
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        def stream(self, *_args: object, **_kwargs: object) -> InvalidStream:
            return InvalidStream()

    monkeypatch.setattr(console_module.httpx, "AsyncClient", FakeClient)
    monkeypatch.setattr(
        console_module,
        "_resolve_setup_assist_endpoint",
        lambda *_args, **_kwargs: SimpleNamespace(
            request_url="https://93.184.216.34/setup-assist",
            host_header="ai.example",
            extensions={"sni_hostname": "ai.example"},
        ),
    )
    with TestClient(_app(env_file)) as client:
        response = client.post(
            "/api/v1/console/onboarding/assist",
            headers=_auth(_login(client)),
            json={"component": "smtp", "question": "Which TLS mode?", "values": {}},
        )

    assert response.status_code == 200
    assert response.json()["source"] == "curated"
    assert response.json()["warnings"][-1] == (
        "The configured AI service was unavailable or returned an invalid response; local guidance is shown instead."
    )
    assert provider_secret not in response.text
    assert provider_secret not in caplog.text


def test_setup_assist_rejects_unsupported_component_and_overlong_question(env_file: str) -> None:
    with TestClient(_app(env_file)) as client:
        headers = _auth(_login(client))
        unsupported = client.post(
            "/api/v1/console/onboarding/assist",
            headers=headers,
            json={"component": "shell", "question": "help", "values": {}},
        )
        assert unsupported.status_code == 422
        overlong = client.post(
            "/api/v1/console/onboarding/assist",
            headers=headers,
            json={"component": "smtp", "question": "x" * 1001, "values": {}},
        )
        assert overlong.status_code == 422


def test_setup_assist_deduplicates_ignored_cross_step_warnings() -> None:
    answer, suggestions, warnings = console_module._validated_ai_assistance(
        {"answer": "Use an HTTPS receiver.", "suggestions": {"transport": "HTTPS", "verification": "HMAC"}},
        frozenset({"KP_WORKER_ALERT_WEBHOOK_DOMAINS"}),
    )
    assert answer == "Use an HTTPS receiver."
    assert suggestions == {}
    assert warnings == ["The AI returned a suggestion outside this setup step; it was ignored."]


def test_onboarding_write_persists_allowlisted_keys_and_audits_names_only(env_file: str) -> None:
    audit = FakeAuditStore()
    app = _app(env_file, fake_audit=audit)
    secret = "not-returned-or-audited"
    with TestClient(app) as client:
        token = _login(client)
        response = client.put(
            "/api/v1/console/onboarding",
            headers=_auth(token),
            json={
                "values": {
                    "OPERATOR_API_OIDC_CLIENT_SECRET": secret,
                    "MOCK_AI_URL": "http://ai.local:8282",
                },
                "completed": False,
            },
        )
        assert response.status_code == 200, response.text
        assert response.json()["changed"] == [
            "OPERATOR_API_OIDC_CLIENT_SECRET",
            "MOCK_AI_URL",
            "OPERATOR_API_ONBOARDING_COMPLETED",
        ]
        assert secret not in response.text
        event = next(event for event in audit.events if event["action"] == "console.onboarding.update")
        assert secret not in str(event)
        assert event["detail"] == {"changed": response.json()["changed"]}


def test_onboarding_write_rejects_unknown_keys(env_file: str) -> None:
    with TestClient(_app(env_file)) as client:
        token = _login(client)
        response = client.put(
            "/api/v1/console/onboarding",
            headers=_auth(token),
            json={"values": {"DATABASE_URL": "postgresql://credential@example/x"}},
        )
        assert response.status_code == 403


def test_onboarding_completion_requires_required_connections(env_file: str) -> None:
    with TestClient(_app(env_file)) as client:
        token = _login(client)
        response = client.put(
            "/api/v1/console/onboarding",
            headers=_auth(token),
            json={"values": {}, "completed": True},
        )
        assert response.status_code == 422
        assert "required setup steps" in response.json()["detail"]


@pytest.mark.parametrize(
    ("values", "detail"),
    (
        ({"KP_WORKER_EMAIL_PROVIDER": "not-a-provider"}, "email provider must be"),
        (
            {
                "KP_WORKER_EMAIL_PROVIDER": "azure_communication_services",
                "KP_WORKER_ACS_EMAIL_ENDPOINT": "https://mailer.communication.azure.com",
            },
            "managed identity client ID or local connection string",
        ),
        ({"KP_WORKER_REPORTED_MAILBOX_PROVIDER": "not-a-provider"}, "reported mailbox provider must be"),
    ),
)
def test_onboarding_rejects_partial_or_unknown_provider_configuration_atomically(
    env_file: str,
    values: dict[str, str],
    detail: str,
) -> None:
    original = console_module.Path(env_file).read_text(encoding="utf-8")
    with TestClient(_app(env_file)) as client:
        response = client.put(
            "/api/v1/console/onboarding",
            headers=_auth(_login(client)),
            json={"values": values},
        )

    assert response.status_code == 422
    assert detail in response.json()["detail"]
    assert console_module.Path(env_file).read_text(encoding="utf-8") == original


def test_onboarding_training_values_are_mirrored_to_workers(env_file: str) -> None:
    with TestClient(_app(env_file)) as client:
        token = _login(client)
        response = client.put(
            "/api/v1/console/onboarding",
            headers=_auth(token),
            json={
                "values": {
                    "OPERATOR_API_TRAINING_BASE_URL": "https://training.example/course",
                    "OPERATOR_API_TRAINING_DOMAINS": "training.example",
                }
            },
        )
        assert response.status_code == 200
        persisted = console_module._env_values(console_module.Path(env_file))
        assert persisted["KP_WORKER_TRAINING_BASE_URL"] == "https://training.example/course"
        assert persisted["KP_WORKER_TRAINING_DOMAINS"] == "training.example"


def test_onboarding_http_test_uses_transient_value_without_persisting(
    env_file: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    requested: list[str] = []

    target = console_module._ResolvedTarget(socket.AF_INET, ("93.184.216.34", 443), "93.184.216.34")

    def fake_status(url: str, resolved: console_module._ResolvedTarget, _headers: object) -> int:
        assert resolved is target
        requested.append(url)
        return 204

    monkeypatch.setattr(console_module, "_resolve_pinned_target", lambda *_args, **_kwargs: target)
    monkeypatch.setattr(console_module, "_pinned_http_status", fake_status)
    with TestClient(_app(env_file)) as client:
        token = _login(client)
        response = client.post(
            "/api/v1/console/onboarding/test",
            headers=_auth(token),
            json={"component": "ai", "values": {"MOCK_AI_URL": "https://ai.example/health"}},
        )
        assert response.json() == {
            "component": "ai",
            "ok": True,
            "outcome": "verified",
            "save_allowed": True,
            "verification_scope": "ai_endpoint_reachability",
            "error_kind": None,
            "message": "Connection successful.",
        }
        assert requested == ["https://ai.example/health/propose"]
        assert "ai.example" not in console_module.Path(env_file).read_text(encoding="utf-8")


def test_onboarding_smtp_test_uses_only_current_starttls_setting(
    env_file: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, bool, bool]] = []

    def probe(address: str, use_tls: bool, *, use_ssl: bool, **_kwargs: object) -> tuple[bool, None]:
        calls.append((address, use_tls, use_ssl))
        return True, None

    monkeypatch.setattr(console_module, "_probe_smtp", probe)
    with TestClient(_app(env_file)) as client:
        response = client.post(
            "/api/v1/console/onboarding/test",
            headers=_auth(_login(client)),
            json={
                "component": "smtp",
                "values": {
                    "KP_WORKER_SMTP_ADDRESS": "smtp.example.com:587",
                    "KP_WORKER_SMTP_STARTTLS": "true",
                    "KP_WORKER_SMTP_SSL": "false",
                },
            },
        )

    assert response.status_code == 200
    assert response.json()["ok"] is True
    assert response.json()["outcome"] == "verified"
    assert response.json()["verification_scope"] == "smtp_session"
    assert calls == [("smtp.example.com:587", True, False)]


def test_onboarding_acs_test_is_non_sending_reachability_only(
    env_file: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, dict[str, object]]] = []

    def probe(url: str, **kwargs: object) -> tuple[bool, None]:
        calls.append((url, kwargs))
        return True, None

    monkeypatch.setattr(console_module, "_probe_http", probe)
    monkeypatch.setattr(
        console_module,
        "_probe_smtp",
        lambda *_args, **_kwargs: pytest.fail("ACS validation must never use SMTP or send a message"),
    )
    with TestClient(_app(env_file)) as client:
        response = client.post(
            "/api/v1/console/onboarding/test",
            headers=_auth(_login(client)),
            json={
                "component": "smtp",
                "values": {
                    "KP_WORKER_EMAIL_PROVIDER": "azure_communication_services",
                    "KP_WORKER_ACS_EMAIL_ENDPOINT": "https://mailer.communication.azure.com",
                    "KP_WORKER_ACS_EMAIL_CONNECTION_STRING": "endpoint=secret-that-must-not-be-sent",
                },
            },
        )

    assert response.status_code == 200
    assert response.json() == {
        "component": "smtp",
        "ok": False,
        "outcome": "reachable_unverified",
        "save_allowed": True,
        "verification_scope": "acs_endpoint_reachability",
        "error_kind": None,
        "message": (
            "The ACS endpoint is reachable. No message or credential was sent; managed-identity access, "
            "custom-domain readiness, delivery, and inbox placement remain unverified."
        ),
    }
    assert calls == [
        (
            "https://mailer.communication.azure.com",
            {"reachable_only": True, "accept_auth_challenge": True},
        )
    ]
    assert "secret-that-must-not-be-sent" not in str(calls)


def test_onboarding_microsoft365_test_uses_exact_bounded_graph_path_and_transient_bearer(
    env_file: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, dict[str, object]]] = []

    def probe(url: str, **kwargs: object) -> tuple[bool, None]:
        calls.append((url, kwargs))
        return True, None

    monkeypatch.setattr(console_module, "_probe_http", probe)
    with TestClient(_app(env_file)) as client:
        response = client.post(
            "/api/v1/console/onboarding/test",
            headers=_auth(_login(client)),
            json={
                "component": "mailbox",
                "values": {
                    "KP_WORKER_REPORTED_MAILBOX_PROVIDER": "microsoft365",
                    "KP_WORKER_REPORTED_MAILBOX_URL": "https://graph.microsoft.com/v1.0",
                    "KP_WORKER_REPORTED_MAILBOX_ID": "reports+security@example.com",
                    "KP_WORKER_REPORTED_MAILBOX_FOLDER_ID": "Security reports",
                    "KP_WORKER_REPORTED_MAILBOX_BEARER_TOKEN": "transient-graph-token",
                },
            },
        )

    assert response.status_code == 200
    assert response.json()["outcome"] == "verified"
    assert response.json()["save_allowed"] is True
    assert response.json()["verification_scope"] == "microsoft365_mailbox_read"
    assert calls == [
        (
            "https://graph.microsoft.com/v1.0/users/reports%2Bsecurity%40example.com/"
            "mailFolders/Security%20reports/messages/delta?$top=1&$select=id",
            {
                "headers": {"Authorization": "Bearer transient-graph-token"},
                "require_2xx": True,
            },
        )
    ]


def test_onboarding_microsoft365_without_bearer_is_reachability_only(
    env_file: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, dict[str, object]]] = []

    def probe(url: str, **kwargs: object) -> tuple[bool, None]:
        calls.append((url, kwargs))
        return True, None

    monkeypatch.setattr(console_module, "_probe_http", probe)
    with TestClient(_app(env_file)) as client:
        response = client.post(
            "/api/v1/console/onboarding/test",
            headers=_auth(_login(client)),
            json={
                "component": "mailbox",
                "values": {
                    "KP_WORKER_REPORTED_MAILBOX_PROVIDER": "microsoft365",
                    "KP_WORKER_REPORTED_MAILBOX_URL": "https://graph.microsoft.com/v1.0",
                    "KP_WORKER_REPORTED_MAILBOX_ID": "reports@example.com",
                    "KP_WORKER_REPORTED_MAILBOX_FOLDER_ID": "inbox",
                    "KP_WORKER_REPORTED_MAILBOX_CLIENT_ID": "11111111-1111-4111-8111-111111111111",
                },
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is False
    assert body["outcome"] == "reachable_unverified"
    assert body["save_allowed"] is True
    assert body["verification_scope"] == "microsoft365_endpoint_reachability"
    assert "managed identity" in body["message"]
    assert calls[0][1] == {"reachable_only": True, "accept_auth_challenge": True}


def test_onboarding_microsoft365_explicit_bearer_auth_failure_blocks_save(
    env_file: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(console_module, "_probe_http", lambda *_args, **_kwargs: (False, "auth"))
    with TestClient(_app(env_file)) as client:
        response = client.post(
            "/api/v1/console/onboarding/test",
            headers=_auth(_login(client)),
            json={
                "component": "mailbox",
                "values": {
                    "KP_WORKER_REPORTED_MAILBOX_PROVIDER": "microsoft365",
                    "KP_WORKER_REPORTED_MAILBOX_URL": "https://graph.microsoft.com/v1.0",
                    "KP_WORKER_REPORTED_MAILBOX_ID": "reports@example.com",
                    "KP_WORKER_REPORTED_MAILBOX_FOLDER_ID": "inbox",
                    "KP_WORKER_REPORTED_MAILBOX_BEARER_TOKEN": "rejected-token",
                },
            },
        )

    body = response.json()
    assert body["ok"] is False
    assert body["outcome"] == "failed"
    assert body["save_allowed"] is False
    assert body["error_kind"] == "auth"


def test_onboarding_test_rejects_credentials_and_unsupported_components(
    env_file: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(console_module.httpx, "get", lambda *_args, **_kwargs: pytest.fail("network called"))
    with TestClient(_app(env_file)) as client:
        token = _login(client)
        bad_url = client.post(
            "/api/v1/console/onboarding/test",
            headers=_auth(token),
            json={"component": "graph", "values": {"MOCK_GRAPH_URL": "https://user:secret@example.test"}},
        )
        # A malformed address is a configuration problem, and the operator is
        # told that specifically rather than being sent to check credentials.
        body = bad_url.json()
        assert body["component"] == "graph"
        assert body["ok"] is False
        assert body["error_kind"] == "config"
        assert "format" in body["message"]
        unsupported = client.post(
            "/api/v1/console/onboarding/test",
            headers=_auth(token),
            json={"component": "shell", "values": {}},
        )
        assert unsupported.status_code == 422


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


def test_local_status_uses_local_probes_and_advertises_local_controls(
    env_file: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    tcp_calls: list[tuple[str, int]] = []
    process_calls: list[str] = []
    http_calls: list[str] = []

    def tcp_ok(host: str, port: int) -> bool:
        tcp_calls.append((host, port))
        return port == 5432

    def process_alive(path: console_module.Path) -> bool:
        process_calls.append(path.name)
        return path.name == "worker-delivery.pid"

    def http_ok(url: str) -> bool:
        http_calls.append(url)
        return True

    monkeypatch.setattr(console_module, "_tcp_ok", tcp_ok)
    monkeypatch.setattr(console_module, "_process_alive", process_alive)
    monkeypatch.setattr(console_module, "_http_ok", http_ok)

    # The probe derives its target from the configured URLs rather than assuming
    # 127.0.0.1:5432, so this test pins them explicitly instead of inheriting the
    # hermetic runner's deliberately unroutable port 1.
    settings = _settings(env_file)
    settings = settings.model_copy(
        update={
            "database_url": "postgresql+psycopg://kingphisher:pw@127.0.0.1:5432/kingphisher",
            "redis_url": "redis://:pw@127.0.0.1:6379/0",
        }
    )
    app = create_app(settings)
    app.state.audit_store = FakeAuditStore()
    with TestClient(app) as client:
        response = client.get("/api/v1/console/status", headers=_auth(_login(client)))

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["config_store"] == "env_file"
    assert body["runtime_control"] == "local_supervisor"
    assert body["capabilities"] == {
        "config_mutation": True,
        "process_restart": True,
        "local_component_probes": True,
    }
    assert body["tracking_api"] is True
    assert body["postgres"] is True
    assert body["redis"] is False
    # The probe must have followed the configured URLs, not a hardcoded pair.
    assert tcp_calls == [("127.0.0.1", 5432), ("127.0.0.1", 6379)]
    assert body["console_password_set"] is True
    assert body["workers"]["delivery"] is True
    assert sum(body["workers"].values()) == 1
    assert tcp_calls == [("127.0.0.1", 5432), ("127.0.0.1", 6379)]
    assert len(process_calls) == 8
    assert http_calls == [app.state.settings.tracking_base_url.rstrip("/") + "/healthz"]


def test_managed_status_is_explicitly_external_and_never_uses_local_probes(
    env_file: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(env_file).model_copy(update={"config_store": "managed"})

    def unexpected_probe(*_args: object, **_kwargs: object) -> bool:
        pytest.fail("managed status must not use local or process probes")

    monkeypatch.setattr(console_module, "_tcp_ok", unexpected_probe)
    monkeypatch.setattr(console_module, "_process_alive", unexpected_probe)
    monkeypatch.setattr(console_module, "_http_ok", unexpected_probe)
    monkeypatch.setattr(console_module, "_console_password", unexpected_probe)

    app = create_app(settings)
    app.state.audit_store = FakeAuditStore()
    with TestClient(app) as client:
        response = client.get("/api/v1/console/status", headers=_auth(_admin_token(settings)))

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["operator_api"] is True
    assert body["config_store"] == "managed"
    assert body["runtime_control"] == "azure_control_plane"
    assert "Azure Container Apps" in body["status_message"]
    assert body["tracking_api"] is None
    assert body["postgres"] is None
    assert body["redis"] is None
    assert body["console_password_set"] is None
    assert body["workers"] == {}
    assert body["capabilities"] == {
        "config_mutation": False,
        "process_restart": False,
        "local_component_probes": False,
    }


def test_managed_config_read_is_marked_read_only_and_ignores_ephemeral_env(
    env_file: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(env_file).model_copy(update={"config_store": "managed"})
    monkeypatch.setattr(
        console_module,
        "_env_values",
        lambda *_args, **_kwargs: pytest.fail("managed config must not read an incidental env file"),
    )
    app = create_app(settings)
    app.state.audit_store = FakeAuditStore()

    with TestClient(app) as client:
        response = client.get("/api/v1/console/config", headers=_auth(_admin_token(settings)))

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["config_store"] == "managed"
    assert body["mutable"] is False
    assert all(value == "" for value in body["values"].values())


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("put", "/api/v1/console/config", {"values": {}}),
        ("put", "/api/v1/console/onboarding", {"values": {}}),
        (
            "post",
            "/api/v1/console/onboarding/assist",
            {"component": "ai", "question": "How do I configure this?", "values": {}},
        ),
        ("post", "/api/v1/console/restart", None),
    ],
)
def test_managed_runtime_rejects_all_local_mutation_and_lifecycle_controls(
    env_file: str, method: str, path: str, body: dict[str, object] | None
) -> None:
    settings = _settings(env_file).model_copy(update={"config_store": "managed"})
    app = create_app(settings)
    app.state.audit_store = FakeAuditStore()
    marker_name = path.rsplit("/", maxsplit=1)[-1]
    marker = os.path.join(os.path.dirname(env_file), "data", "run", marker_name)

    with TestClient(app) as client:
        response = getattr(client, method)(path, json=body, headers=_auth(_admin_token(settings)))

    assert response.status_code == 409, response.text
    assert "Terraform" in response.text or "Container Apps" in response.text
    assert not os.path.exists(marker)


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
