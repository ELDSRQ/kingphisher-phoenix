"""P3 discovery consumer: on-demand web-search threat leads."""

from __future__ import annotations

import uuid

import httpx
import jwt
import kp_operator_api.console.discovery_routes as discovery_module
import pytest
from fastapi.testclient import TestClient
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.main import create_app
from sqlalchemy import Engine, create_engine
from sqlalchemy.pool import StaticPool

KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"


class _Audit:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def record(self, *, session: object, **kwargs: object) -> None:
        del session
        self.calls.append(dict(kwargs))

    def outbox_health(self) -> dict[str, int]:
        return {"overdue_pending": 0, "failed": 0, "dispatching_stale": 0}


def _settings(**overrides: object) -> OperatorApiSettings:
    base: dict[str, object] = {
        "audit_hmac_key": HMAC,
        "ciphertext_kek": KEK,
        "console_jwt_secret": CONSOLE_JWT,
        "database_url": "postgresql+psycopg://unused:unused@localhost:1/unused",
        "audit_database_url": "postgresql+psycopg://unused:unused@localhost:1/unused",
        "oidc_mode": "dev",
    }
    base.update(overrides)
    return OperatorApiSettings(**base)


def _headers(settings: OperatorApiSettings) -> dict[str, str]:
    token = jwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "iss": settings.oidc_issuer,
            "aud": settings.oidc_audience,
            "exp": 2_000_000_000,
            "nbf": 0,
            "realm_access": {"roles": ["source_curator"]},
        },
        settings.require_console_jwt_secret(),
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


def _engine() -> Engine:
    return create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )


def _client(settings: OperatorApiSettings) -> TestClient:
    app = create_app(settings)
    app.state.audit_verifier.status = "ok"
    app.state.audit_store = _Audit()
    return TestClient(app)


def test_discovery_reports_503_when_gateway_url_unset() -> None:
    client = _client(_settings())
    response = client.post(
        "/api/v1/console/discover/search",
        json={"query": "credential phishing campaigns targeting finance"},
        headers=_headers(_settings()),
    )
    assert response.status_code == 503


def test_discovery_rejects_pii_before_egress() -> None:
    client = _client(_settings(ai_gateway_url="https://gw.internal.example"))
    response = client.post(
        "/api/v1/console/discover/search",
        json={"query": "reset password for bob@example.com"},
        headers=_headers(_settings(ai_gateway_url="https://gw.internal.example")),
    )
    assert response.status_code == 422


def test_discovery_forwards_to_gateway_with_shared_bearer(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(ai_gateway_url="https://gw.internal.example", ai_gateway_api_key="shared-key")

    captured: dict[str, object] = {}

    class FakeClient:
        def __init__(self, *, timeout: float) -> None:
            assert timeout == 60.0

        async def __aenter__(self) -> FakeClient:
            return self

        async def __aexit__(self, *_args: object) -> None:
            pass

        async def post(self, url: str, *, json: object, headers: dict[str, str]) -> httpx.Response:
            captured["url"] = url
            captured["json"] = json
            captured["headers"] = headers
            return httpx.Response(
                200,
                request=httpx.Request("POST", url),
                json={
                    "leads": [{"title": "Invoice lure", "source_urls": ["https://cisa.gov/a"]}],
                    "model_id": "gpt-5.6-luna",
                },
            )

    monkeypatch.setattr(discovery_module.httpx, "AsyncClient", FakeClient)

    client = _client(settings)
    response = client.post(
        "/api/v1/console/discover/search",
        json={"query": "credential phishing campaigns"},
        headers=_headers(settings),
    )
    assert response.status_code == 200
    assert captured["url"] == "https://gw.internal.example/discover"
    assert captured["headers"]["Authorization"] == "Bearer shared-key"
    body = response.json()
    assert body["model_id"] == "gpt-5.6-luna"
    assert body["leads"][0]["title"] == "Invoice lure"


def test_discovery_lists_allowed_domains() -> None:
    client = _client(_settings())
    response = client.get(
        "/api/v1/console/discover/allowed-domains",
        headers=_headers(_settings()),
    )
    assert response.status_code == 200
    domains = response.json()
    assert "cisa.gov" in domains
    assert "proofpoint.com" in domains
