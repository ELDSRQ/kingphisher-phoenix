from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import jwt
import pytest
from fastapi.testclient import TestClient
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.deps import get_session
from kp_operator_api.main import create_app

KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
SALT_HEX = "0f0e0d0c0b0a09080706050403020100"


class _MissingSession:
    def get(self, *_args: Any, **_kwargs: Any) -> None:
        return None


@pytest.fixture(scope="module")
def client() -> TestClient:
    settings = OperatorApiSettings(
        audit_hmac_key=HMAC,
        ciphertext_kek=KEK,
        console_jwt_secret=CONSOLE_JWT,
        recipient_hash_salt=SALT_HEX,
        tracking_token_hmac_key="34" * 32,
        roe_signing_key="11" * 32,
        domain_verification_key="22" * 32,
        database_url="postgresql+psycopg://unused:unused@localhost:1/unused",
        audit_database_url="postgresql+psycopg://unused:unused@localhost:1/unused",
    )
    app = create_app(settings)
    app.state.audit_verifier.status = "ok"
    app.state.audit_store = SimpleNamespace(
        outbox_health=lambda: {"overdue_pending": 0, "failed": 0, "dispatching_stale": 0}
    )

    def _missing_session() -> Iterator[_MissingSession]:
        yield _MissingSession()

    app.dependency_overrides[get_session] = _missing_session
    return TestClient(app)


def _headers() -> dict[str, str]:
    settings = OperatorApiSettings()
    token = jwt.encode(
        {
            "sub": str(uuid4()),
            "iss": settings.oidc_issuer,
            "aud": settings.oidc_audience,
            "exp": 2_000_000_000,
            "nbf": 0,
            "realm_access": {"roles": ["administrator"]},
        },
        CONSOLE_JWT.encode(),
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


_CAMPAIGN_BODY = {
    "pattern_id": "not-a-uuid",
    "template_version_id": str(uuid4()),
    "title": "Boundary test",
    "sender_mailbox": "simulations@example.com",
    "training_domain": "training.example.com",
    "schedule_start": datetime.now(UTC).isoformat(),
    "schedule_end": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
    "max_recipients": 1,
}


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("GET", "/api/v1/campaigns/not-a-uuid/report", None),
        ("PUT", "/api/v1/audience-groups/not-a-uuid", {"name": "Test", "recipient_ids": []}),
        ("POST", "/api/v1/sources/not-a-uuid/enable", None),
        ("DELETE", "/api/v1/recipients/not-a-uuid", None),
        ("DELETE", "/api/v1/alerts/subscriptions/not-a-uuid", None),
        (
            "POST",
            "/api/v1/privacy/requests/not-a-uuid/verify",
            {"method": "ticket", "evidence_ref": "SEC-1"},
        ),
        ("POST", "/api/v1/patterns/not-a-uuid/approve", None),
        (
            "POST",
            "/api/v1/templates/not-a-uuid/decision",
            {"decision": "approved", "rationale": "reviewed"},
        ),
        ("POST", "/api/v1/roe/not-a-uuid/revoke", {"reason": "complete"}),
    ],
)
def test_malformed_uuid_path_parameters_return_bounded_validation_errors(
    client: TestClient,
    method: str,
    path: str,
    body: dict[str, object] | None,
) -> None:
    response = client.request(method, path, json=body, headers=_headers())

    assert response.status_code == 422
    assert len(response.content) < 4096
    assert "Traceback" not in response.text


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/api/v1/campaigns", _CAMPAIGN_BODY),
        (
            f"/api/v1/recipients/{uuid4()}/exclusions",
            {"exclusion_type": "opt_out", "campaign_id": "not-a-uuid"},
        ),
        ("/api/v1/alerts/subscriptions", {"campaign_id": "not-a-uuid", "channel": "web"}),
        (
            "/api/v1/privacy/requests",
            {"request_type": "access_export", "requester_mailbox": "person@example.com", "campaign_id": "bad"},
        ),
        (
            "/api/v1/sources",
            {
                "name": "Feed",
                "source_type": "rss",
                "base_domain": "example.com",
                "license_state_id": "bad",
            },
        ),
    ],
)
def test_malformed_request_model_ids_return_validation_errors(
    client: TestClient,
    path: str,
    body: dict[str, object],
) -> None:
    response = client.post(path, json=body, headers=_headers())

    assert response.status_code == 422
    assert len(response.content) < 4096


def test_malformed_alert_filter_is_validated(client: TestClient) -> None:
    response = client.get(
        "/api/v1/alerts/subscriptions",
        params={"campaign_id": "not-a-uuid"},
        headers=_headers(),
    )

    assert response.status_code == 422


def test_domain_and_roe_boundaries_remain_bounded(client: TestClient) -> None:
    response = client.post(
        "/api/v1/sending-domains/challenge",
        json={"domain": "not a domain"},
        headers=_headers(),
    )

    assert response.status_code == 422
    assert len(response.content) < 4096


def test_valid_uuid_reaches_not_found_semantics(client: TestClient) -> None:
    response = client.get(f"/api/v1/campaigns/{uuid4()}/report", headers=_headers())

    assert response.status_code == 404
    assert response.json()["code"] == "KP-004"
    assert response.json()["detail"].endswith("campaign not found")


def test_uuid_validation_does_not_bypass_authorization(client: TestClient) -> None:
    response = client.get("/api/v1/campaigns/not-a-uuid/report")

    assert response.status_code == 401
