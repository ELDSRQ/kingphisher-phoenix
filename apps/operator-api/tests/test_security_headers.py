from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx import Response
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.main import create_app

KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
HSTS = "max-age=31536000"


def _settings(*, max_body_bytes: int = 1_000_000) -> OperatorApiSettings:
    return OperatorApiSettings(
        audit_hmac_key=HMAC,
        ciphertext_kek=KEK,
        console_jwt_secret=CONSOLE_JWT,
        console_static_dir="/nonexistent-console-dir",
        oidc_redirect_uri="https://operator.example/api/v1/console/oidc/callback",
        max_body_bytes=max_body_bytes,
    )


def _assert_hsts(response: Response) -> None:
    value = response.headers["strict-transport-security"]
    assert value == HSTS
    assert "includesubdomains" not in value.lower()
    assert "preload" not in value.lower()


def test_hsts_is_present_on_normal_auth_failure_and_not_found_responses() -> None:
    app = create_app(_settings())
    app.state.audit_verifier.status = "ok"
    with TestClient(app) as client:
        responses = [client.get("/livez"), client.get("/api/v1/campaigns"), client.get("/not-found")]

    assert [response.status_code for response in responses] == [200, 401, 404]
    for response in responses:
        _assert_hsts(response)


def test_hsts_is_present_on_csrf_and_audit_health_early_rejections() -> None:
    app = create_app(_settings())
    app.state.audit_verifier.status = "ok"
    with TestClient(app) as client:
        client.cookies.set("kp_oidc_session", "cookie-authenticated-browser")
        csrf = client.post(
            "/api/v1/console/session",
            headers={"Origin": "https://attacker.example", "Sec-Fetch-Site": "cross-site"},
            json={"username": "operator", "password": "irrelevant"},
        )
        client.cookies.clear()
        app.state.audit_health_check = lambda: False
        audit = client.post("/api/v1/campaigns", json={})

    assert csrf.status_code == 403
    assert audit.status_code == 503
    _assert_hsts(csrf)
    _assert_hsts(audit)


def test_hsts_is_present_on_oversized_body_rejection() -> None:
    app = create_app(_settings(max_body_bytes=32))
    app.state.audit_verifier.status = "ok"
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/console/session",
            headers={"Content-Type": "application/json"},
            content=b'\x7b"payload":"' + b"x" * 64 + b'"\x7d',
        )

    assert response.status_code == 413
    _assert_hsts(response)


def test_ambiguous_or_invalid_content_lengths_are_rejected_before_routing() -> None:
    app = create_app(_settings(max_body_bytes=32))
    app.state.audit_verifier.status = "ok"
    with TestClient(app) as client:
        duplicate = client.post(
            "/api/v1/console/session",
            headers=[("content-length", "2"), ("content-length", "2")],
            content=b"{}",
        )
        malformed = client.post(
            "/api/v1/console/session",
            headers={"content-length": "not-a-number"},
            content=b"{}",
        )
        enormous = client.post(
            "/api/v1/console/session",
            headers={"content-length": "9" * 10_000},
            content=b"{}",
        )

    assert duplicate.status_code == 400
    assert malformed.status_code == 400
    assert enormous.status_code == 413
    for response in (duplicate, malformed, enormous):
        _assert_hsts(response)


def test_hsts_is_present_on_unexpected_server_error_without_reflecting_detail() -> None:
    app: FastAPI = create_app(_settings())

    @app.get("/unexpected-error")
    def unexpected_error() -> None:
        raise RuntimeError("sensitive internal failure")

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/unexpected-error")

    assert response.status_code == 500
    assert response.json() == {"detail": "internal server error"}
    assert "sensitive" not in response.text
    _assert_hsts(response)


def test_request_validation_errors_are_bounded_and_do_not_reflect_invalid_input() -> None:
    app = create_app(_settings(max_body_bytes=200_000))
    app.state.audit_verifier.status = "ok"
    marker = "SECRET-MARKER-" + "x" * 100_000

    with TestClient(app) as client:
        response = client.post("/api/v1/console/session", json={"password": {"submitted": marker}})

    assert response.status_code == 422
    assert len(response.content) < 4_096
    assert marker not in response.text
    assert "submitted" not in response.text
    assert response.json() == {
        "code": "request_validation_failed",
        "detail": [
            {
                "type": "string_type",
                "loc": ["body", "password"],
                "msg": "Value is invalid",
            }
        ],
        "truncated": False,
    }
    _assert_hsts(response)
