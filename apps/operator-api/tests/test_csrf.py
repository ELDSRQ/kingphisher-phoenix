"""CSRF boundary tests for cookie-authenticated operator mutations."""

from __future__ import annotations

import uuid

import jwt
import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from kp_operator_api.auth import get_principal
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.main import create_app

KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
TRUSTED_ORIGIN = "https://operator.example"


@pytest.fixture()
def csrf_client(tmp_path) -> tuple[TestClient, str]:  # noqa: ANN001
    settings = OperatorApiSettings(
        audit_hmac_key=HMAC,
        ciphertext_kek=KEK,
        console_jwt_secret=CONSOLE_JWT,
        env_file=str(tmp_path / ".env"),
        console_static_dir="/nonexistent-console-dir",
        oidc_redirect_uri=f"{TRUSTED_ORIGIN}/api/v1/console/oidc/callback",
    )
    app = create_app(settings)
    app.state.audit_health_check = lambda: True

    @app.api_route("/csrf-probe", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    def csrf_probe(request: Request) -> dict[str, str]:
        principal = get_principal(request)
        return {"principal_id": principal.principal_id}

    claims = {
        "sub": str(uuid.uuid4()),
        "iss": settings.oidc_issuer,
        "aud": settings.oidc_audience,
        "exp": 2_000_000_000,
        "nbf": 0,
        "realm_access": {"roles": ["administrator"]},
    }
    token = jwt.encode(claims, settings.require_console_jwt_secret(), algorithm="HS256")
    return TestClient(app), token


def _authenticate_with_cookie(client: TestClient, token: str) -> None:
    client.cookies.set("kp_oidc_session", token)


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_cookie_authenticated_unsafe_methods_accept_configured_origin(
    csrf_client: tuple[TestClient, str], method: str
) -> None:
    client, token = csrf_client
    _authenticate_with_cookie(client, token)

    response = client.request(
        method,
        "/csrf-probe",
        headers={"Origin": f"{TRUSTED_ORIGIN}:443", "Sec-Fetch-Site": "same-origin"},
    )

    assert response.status_code == 200, response.text


def test_cookie_authenticated_request_accepts_same_origin_fetch_metadata_without_origin(
    csrf_client: tuple[TestClient, str],
) -> None:
    client, token = csrf_client
    _authenticate_with_cookie(client, token)

    response = client.post("/csrf-probe", headers={"Sec-Fetch-Site": "same-origin"})

    assert response.status_code == 200, response.text


def test_cookie_authenticated_request_accepts_configured_origin_without_fetch_metadata(
    csrf_client: tuple[TestClient, str],
) -> None:
    client, token = csrf_client
    _authenticate_with_cookie(client, token)

    response = client.post("/csrf-probe", headers={"Origin": TRUSTED_ORIGIN})

    assert response.status_code == 200, response.text


@pytest.mark.parametrize(
    ("origin", "fetch_site"),
    [
        ("https://admin.operator.example", "same-site"),
        ("https://attacker.example", "cross-site"),
        ("null", "cross-site"),
    ],
)
def test_cookie_authenticated_request_rejects_sibling_and_cross_origin(
    csrf_client: tuple[TestClient, str], origin: str, fetch_site: str
) -> None:
    client, token = csrf_client
    _authenticate_with_cookie(client, token)

    response = client.post(
        "/csrf-probe",
        headers={"Origin": origin, "Sec-Fetch-Site": fetch_site},
    )

    assert response.status_code == 403
    assert response.json()["code"] == "csrf_rejected"


def test_cookie_authenticated_request_rejects_missing_browser_signals(
    csrf_client: tuple[TestClient, str],
) -> None:
    client, token = csrf_client
    _authenticate_with_cookie(client, token)

    response = client.post("/csrf-probe")

    assert response.status_code == 403
    assert "same-origin browser metadata" in response.json()["detail"]


def test_cookie_authenticated_request_rejects_ambiguous_origin_and_fetch_site(
    csrf_client: tuple[TestClient, str],
) -> None:
    client, token = csrf_client
    _authenticate_with_cookie(client, token)

    response = client.post(
        "/csrf-probe",
        headers={"Origin": TRUSTED_ORIGIN, "Sec-Fetch-Site": "cross-site"},
    )

    assert response.status_code == 403
    assert "fetch site" in response.json()["detail"]


def test_bearer_client_does_not_require_browser_csrf_headers(
    csrf_client: tuple[TestClient, str],
) -> None:
    client, token = csrf_client

    response = client.post("/csrf-probe", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200, response.text


def test_bearer_authentication_takes_precedence_when_cookie_is_also_present(
    csrf_client: tuple[TestClient, str],
) -> None:
    client, token = csrf_client
    _authenticate_with_cookie(client, token)

    response = client.post("/csrf-probe", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200, response.text


def test_safe_cookie_authenticated_get_is_unaffected(csrf_client: tuple[TestClient, str]) -> None:
    client, token = csrf_client
    _authenticate_with_cookie(client, token)

    response = client.get("/csrf-probe")

    assert response.status_code == 200, response.text


def test_privacy_export_is_not_available_as_cross_site_safe_get(
    csrf_client: tuple[TestClient, str],
) -> None:
    client, token = csrf_client

    response = client.get(
        f"/api/v1/privacy/requests/{uuid.uuid4()}/export",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 405
    assert "POST" in response.headers["allow"]


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Origin": "https://attacker.example", "Sec-Fetch-Site": "cross-site"},
    ],
)
def test_cookie_authenticated_privacy_export_requires_same_origin_csrf_signals(
    csrf_client: tuple[TestClient, str],
    headers: dict[str, str],
) -> None:
    client, token = csrf_client
    _authenticate_with_cookie(client, token)

    response = client.post(f"/api/v1/privacy/requests/{uuid.uuid4()}/export", headers=headers)

    assert response.status_code == 403
    assert response.json()["code"] == "csrf_rejected"


def test_privacy_export_requires_an_authenticated_session(csrf_client: tuple[TestClient, str]) -> None:
    client, _token = csrf_client

    response = client.post(f"/api/v1/privacy/requests/{uuid.uuid4()}/export")

    assert response.status_code == 401


def test_origin_comparison_uses_configuration_instead_of_untrusted_host(
    csrf_client: tuple[TestClient, str],
) -> None:
    client, token = csrf_client
    _authenticate_with_cookie(client, token)

    accepted = client.post(
        "/csrf-probe",
        headers={"Host": "attacker.invalid", "Origin": TRUSTED_ORIGIN},
    )
    rejected = client.post(
        "/csrf-probe",
        headers={"Host": "attacker.invalid", "Origin": "https://attacker.invalid"},
    )

    assert accepted.status_code == 200, accepted.text
    assert rejected.status_code == 403
