import uuid

import jwt
from fastapi.testclient import TestClient
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.main import create_app

KEK = "0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"


def _make_settings() -> OperatorApiSettings:
    return OperatorApiSettings(
        audit_hmac_key=HMAC,
        ciphertext_kek=KEK,
        console_jwt_secret=CONSOLE_JWT,
        tracking_base_url="http://track.local:8001",
        training_base_url="http://train.local:3000/training/awareness",
        training_domains="example.com,training.local",
    )


def _token(settings: OperatorApiSettings) -> str:
    claims = {
        "sub": str(uuid.uuid4()),
        "iss": settings.oidc_issuer,
        "aud": settings.oidc_audience,
        "exp": 2_000_000_000,
        "nbf": 0,
        "realm_access": {"roles": ["campaign_author"]},
    }
    return jwt.encode(claims, settings.require_console_jwt_secret(), algorithm="HS256")


def test_preview_template_renders() -> None:
    settings = _make_settings()
    app = create_app(settings)
    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/templates/preview",
            headers={"Authorization": f"Bearer {_token(settings)}"},
            json={
                "subject": "Hi {{ recipient.first_name }}",
                "plain_text": "Open {{ tracking.click_url }}",
                "safe_html": "",
            },
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["subject"] == "Hi Sample"
    assert "click/preview-" in body["plain_text"]


def test_preview_template_rejects_unauthorized_var() -> None:
    settings = _make_settings()
    app = create_app(settings)
    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/templates/preview",
            headers={"Authorization": f"Bearer {_token(settings)}"},
            json={"subject": "{{ recipient.employee_key }}", "plain_text": "", "safe_html": ""},
        )
    assert resp.status_code == 422


def test_preview_requires_auth() -> None:
    app = create_app(_make_settings())
    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/templates/preview",
            json={"subject": "x", "plain_text": "", "safe_html": ""},
        )
    assert resp.status_code == 401
