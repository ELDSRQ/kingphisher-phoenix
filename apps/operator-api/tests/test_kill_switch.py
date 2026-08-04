"""WS-10 kill-switch scope + confirm tests.

The confirm gate raises before any DB access, so these run without a live
database (the kill-switch requires a valid operator token only).
"""

from __future__ import annotations

import uuid

import jwt
from fastapi.testclient import TestClient
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.main import create_app

KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"


def _settings() -> OperatorApiSettings:
    return OperatorApiSettings(
        audit_hmac_key=HMAC,
        ciphertext_kek=KEK,
        console_jwt_secret=CONSOLE_JWT,
        console_static_dir="/nonexistent-console-dir",
    )


def _token(settings: OperatorApiSettings) -> str:
    claims = {
        "sub": str(uuid.uuid4()),
        "iss": settings.oidc_issuer,
        "aud": settings.oidc_audience,
        "exp": 2_000_000_000,
        "nbf": 0,
        "realm_access": {"roles": ["administrator"]},
    }
    return jwt.encode(claims, settings.require_console_jwt_secret(), algorithm="HS256")


def test_kill_switch_requires_confirm() -> None:
    app = create_app(_settings())
    with TestClient(app) as client:
        resp = client.post("/api/v1/kill-switch", json={}, headers={"Authorization": f"Bearer {_token(_settings())}"})
        assert resp.status_code == 422
        resp = client.post(
            "/api/v1/kill-switch",
            json={"confirm": False},
            headers={"Authorization": f"Bearer {_token(_settings())}"},
        )
        assert resp.status_code == 422


def test_kill_switch_rejects_non_uuid_campaign_id() -> None:
    app = create_app(_settings())
    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/kill-switch",
            json={"campaign_id": "not-a-uuid", "confirm": True},
            headers={"Authorization": f"Bearer {_token(_settings())}"},
        )
        assert resp.status_code == 422


def test_kill_switch_requires_auth() -> None:
    app = create_app(_settings())
    with TestClient(app) as client:
        resp = client.post("/api/v1/kill-switch", json={"confirm": True})
        assert resp.status_code == 401
