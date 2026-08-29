from __future__ import annotations

import csv
import io
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jwt
import pytest
from fastapi.testclient import TestClient
from kp_database.reporting import CampaignFunnel, CampaignReportNotFound, EvidenceWindow
from kp_operator_api import analytics_routes
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.deps import get_session
from kp_operator_api.main import create_app

KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
CAMPAIGN_ID = uuid.UUID("11111111-1111-4111-8111-111111111111")
GENERATED_AT = datetime(2026, 8, 27, 15, 30, tzinfo=UTC)


def _settings() -> OperatorApiSettings:
    return OperatorApiSettings(
        audit_hmac_key=HMAC,
        ciphertext_kek=KEK,
        console_jwt_secret=CONSOLE_JWT,
        tracking_base_url="http://track.local:8001",
        training_base_url="http://train.local:3000/training/awareness",
        training_domains="example.com,training.local",
    )


def _token(settings: OperatorApiSettings, *roles: str) -> str:
    claims = {
        "sub": str(uuid.uuid4()),
        "iss": settings.oidc_issuer,
        "aud": settings.oidc_audience,
        "exp": 2_000_000_000,
        "nbf": 0,
        "realm_access": {"roles": list(roles)},
    }
    return jwt.encode(claims, settings.require_console_jwt_secret(), algorithm="HS256")


def _report(*, window: EvidenceWindow | None = None) -> CampaignFunnel:
    return CampaignFunnel(
        campaign_id=CAMPAIGN_ID,
        generated_at=GENERATED_AT,
        evidence_window=window,
        targeted=10,
        sent=9,
        accepted=8,
        delivered=7,
        failed=1,
        indeterminate=1,
        opened=4,
        clicked=2,
        reported=3,
        training_assigned=2,
        training_completed=0,
    )


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[TestClient, OperatorApiSettings]]:
    settings = _settings()
    monkeypatch.setattr(
        analytics_routes, "campaign_funnel", lambda *_args, **kwargs: _report(window=kwargs["evidence_window"])
    )
    app = create_app(settings)
    app.dependency_overrides[get_session] = lambda: object()
    with TestClient(app) as test_client:
        yield test_client, settings


def _headers(settings: OperatorApiSettings, *roles: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {_token(settings, *roles)}"}


def test_json_requires_authentication(client: tuple[TestClient, OperatorApiSettings]) -> None:
    test_client, _ = client
    response = test_client.get(f"/api/v1/analytics/campaigns/{CAMPAIGN_ID}/funnel")
    assert response.status_code == 401


def test_json_requires_aggregate_capability(client: tuple[TestClient, OperatorApiSettings]) -> None:
    test_client, settings = client
    response = test_client.get(
        f"/api/v1/analytics/campaigns/{CAMPAIGN_ID}/funnel",
        headers=_headers(settings, "unknown_role"),
    )
    assert response.status_code == 403


def test_json_is_pii_free_and_denominators_are_explicit(client: tuple[TestClient, OperatorApiSettings]) -> None:
    test_client, settings = client
    response = test_client.get(
        f"/api/v1/analytics/campaigns/{CAMPAIGN_ID}/funnel",
        headers=_headers(settings, "campaign_author"),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["campaign_id"] == str(CAMPAIGN_ID)
    assert body["transport"] == [
        {"name": "targeted", "value": 10},
        {"name": "sent", "value": 9},
        {"name": "accepted", "value": 8},
        {"name": "delivered", "value": 7},
        {"name": "failed", "value": 1},
        {"name": "indeterminate", "value": 1},
    ]
    assert body["semantics"]["delivered"] == "destination MTA handoff; not inbox placement, display, or reading"
    training_rate = next(rate for rate in body["rates"] if rate["name"] == "training_completed")
    assert training_rate == {
        "name": "training_completed",
        "numerator": 0,
        "denominator": 2,
        "denominator_name": "campaign_training_assignments",
        "value": 0.0,
    }
    serialized = response.text.lower()
    for forbidden in ("mailbox", "department", "display_name", "employee_key", "recipient_id"):
        assert forbidden not in serialized


def test_empty_denominators_are_null_not_zero_rates(
    client: tuple[TestClient, OperatorApiSettings], monkeypatch: pytest.MonkeyPatch
) -> None:
    test_client, settings = client
    empty = CampaignFunnel(
        campaign_id=CAMPAIGN_ID,
        generated_at=GENERATED_AT,
        evidence_window=None,
        targeted=0,
        sent=0,
        accepted=0,
        delivered=0,
        failed=0,
        indeterminate=0,
        opened=0,
        clicked=0,
        reported=0,
        training_assigned=0,
        training_completed=0,
    )
    monkeypatch.setattr(analytics_routes, "campaign_funnel", lambda *_args, **_kwargs: empty)
    response = test_client.get(
        f"/api/v1/analytics/campaigns/{CAMPAIGN_ID}/funnel",
        headers=_headers(settings, "campaign_author"),
    )
    assert response.status_code == 200, response.text
    assert all(rate["value"] is None for rate in response.json()["rates"])


@pytest.mark.parametrize(
    ("query", "expected_detail"),
    [
        (
            "?evidence_start=2026-01-01T00:00:00Z",
            "KP-001: evidence_start and evidence_end must be supplied together",
        ),
        (
            "?evidence_start=2026-01-02T00:00:00Z&evidence_end=2026-01-01T00:00:00Z",
            "KP-001: evidence window start must precede end",
        ),
        (
            "?evidence_start=2025-01-01T00:00:00Z&evidence_end=2026-01-03T00:00:00Z",
            "KP-001: evidence window cannot exceed 366 days",
        ),
        (
            "?evidence_start=2026-01-01T00:00:00&evidence_end=2026-01-02T00:00:00",
            "KP-001: evidence window timestamps must include a timezone",
        ),
    ],
)
def test_invalid_evidence_windows_return_stable_422(
    client: tuple[TestClient, OperatorApiSettings], query: str, expected_detail: str
) -> None:
    test_client, settings = client
    response = test_client.get(
        f"/api/v1/analytics/campaigns/{CAMPAIGN_ID}/funnel{query}",
        headers=_headers(settings, "campaign_author"),
    )
    assert response.status_code == 422, response.text
    assert response.json() == {"code": "KP-001", "detail": expected_detail}


def test_evidence_window_does_not_reflect_arbitrary_value_error(
    client: tuple[TestClient, OperatorApiSettings], monkeypatch: pytest.MonkeyPatch
) -> None:
    test_client, settings = client
    secret = "database-password=do-not-reflect"

    def fail_closed(*_args: object, **_kwargs: object) -> EvidenceWindow:
        raise ValueError(secret)

    monkeypatch.setattr(analytics_routes, "EvidenceWindow", fail_closed)
    response = test_client.get(
        f"/api/v1/analytics/campaigns/{CAMPAIGN_ID}/funnel"
        "?evidence_start=2026-01-01T00:00:00Z&evidence_end=2026-01-02T00:00:00Z",
        headers=_headers(settings, "campaign_author"),
    )

    assert response.status_code == 422, response.text
    assert response.json() == {"code": "KP-001", "detail": "KP-001: evidence window is invalid"}
    assert secret not in response.text


def test_evidence_window_normalizes_to_utc(
    client: tuple[TestClient, OperatorApiSettings], monkeypatch: pytest.MonkeyPatch
) -> None:
    test_client, settings = client
    seen: dict[str, Any] = {}

    def capture(*_args: object, **kwargs: Any) -> CampaignFunnel:
        seen["window"] = kwargs["evidence_window"]
        return _report(window=kwargs["evidence_window"])

    monkeypatch.setattr(analytics_routes, "campaign_funnel", capture)
    response = test_client.get(
        f"/api/v1/analytics/campaigns/{CAMPAIGN_ID}/funnel"
        "?evidence_start=2026-08-01T00:00:00-04:00&evidence_end=2026-08-02T00:00:00-04:00",
        headers=_headers(settings, "campaign_author"),
    )
    assert response.status_code == 200, response.text
    window = seen["window"]
    assert isinstance(window, EvidenceWindow)
    assert window.start == datetime(2026, 8, 1, 4, tzinfo=UTC)
    assert response.json()["evidence_window"]["transport_snapshot"].endswith("not limited by the evidence window")


def test_malformed_campaign_uuid_returns_422_before_query(
    client: tuple[TestClient, OperatorApiSettings], monkeypatch: pytest.MonkeyPatch
) -> None:
    test_client, settings = client

    def unexpected(*_args: object, **_kwargs: object) -> CampaignFunnel:
        raise AssertionError("report query must not run")

    monkeypatch.setattr(analytics_routes, "campaign_funnel", unexpected)
    response = test_client.get(
        "/api/v1/analytics/campaigns/not-a-uuid/funnel",
        headers=_headers(settings, "campaign_author"),
    )
    assert response.status_code == 422


def test_absent_campaign_returns_404(
    client: tuple[TestClient, OperatorApiSettings], monkeypatch: pytest.MonkeyPatch
) -> None:
    test_client, settings = client

    def missing(*_args: object, **_kwargs: object) -> CampaignFunnel:
        raise CampaignReportNotFound(str(CAMPAIGN_ID))

    monkeypatch.setattr(analytics_routes, "campaign_funnel", missing)
    response = test_client.get(
        f"/api/v1/analytics/campaigns/{CAMPAIGN_ID}/funnel",
        headers=_headers(settings, "campaign_author"),
    )
    assert response.status_code == 404


def test_csv_requires_export_capability_and_is_formula_safe(
    client: tuple[TestClient, OperatorApiSettings],
) -> None:
    test_client, settings = client
    path = f"/api/v1/analytics/campaigns/{CAMPAIGN_ID}/funnel.csv"
    denied = test_client.get(path, headers=_headers(settings, "campaign_author"))
    assert denied.status_code == 403

    response = test_client.get(path, headers=_headers(settings, "administrator"))
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("text/csv")
    assert response.headers["content-disposition"] == f'attachment; filename="campaign-{CAMPAIGN_ID}-analytics.csv"'
    rows = list(csv.reader(io.StringIO(response.text)))
    assert rows[0] == ["metric", "value"]
    assert ["semantics.delivered", "destination_mta_handoff_not_inbox_or_read"] in rows
    assert ["rate.opened.denominator_name", "provider_accepted_handoffs"] in rows
    assert all(not cell.startswith(("=", "+", "-", "@")) for row in rows for cell in row)
    serialized = response.text.lower()
    for forbidden in ("mailbox", "department", "display_name", "employee_key", "recipient_id"):
        assert forbidden not in serialized


def test_operator_ui_uses_analytics_contract() -> None:
    app_js = (Path(__file__).resolve().parents[2] / "operator-ui" / "src" / "console-js" / "app.js").read_text()
    assert "/analytics/campaigns/${campaign.campaign_id}/funnel" in app_js
    assert "/analytics/campaigns/${campaignId}/funnel.csv" in app_js
    assert "destination MTA handoff; not inbox placement, display, or reading" in app_js
    assert 'rate.value === null ? "N/A"' in app_js
    assert 'name: "evidence_start"' in app_js
    assert 'name: "evidence_end"' in app_js
    assert "report.sender_mailbox" not in app_js
