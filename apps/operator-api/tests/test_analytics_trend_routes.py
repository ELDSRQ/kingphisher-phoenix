from __future__ import annotations

import csv
import io
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest
from fastapi.testclient import TestClient
from kp_database.reporting import (
    CampaignFunnel,
    CampaignPortfolio,
    CampaignSelectionWindow,
    CampaignTrendPoint,
    CampaignTrendReport,
)
from kp_domain_models import models as dm
from kp_operator_api import analytics_routes
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.deps import get_session
from kp_operator_api.main import create_app

KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
NOW = datetime(2026, 8, 27, 15, 30, tzinfo=UTC)
START = NOW - timedelta(days=365)
FIRST_ID = uuid.UUID("11111111-1111-4111-8111-111111111111")
SECOND_ID = uuid.UUID("22222222-2222-4222-8222-222222222222")


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
    return jwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "iss": settings.oidc_issuer,
            "aud": settings.oidc_audience,
            "exp": 2_000_000_000,
            "nbf": 0,
            "realm_access": {"roles": list(roles)},
        },
        settings.require_console_jwt_secret(),
        algorithm="HS256",
    )


def _headers(settings: OperatorApiSettings, *roles: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {_token(settings, *roles)}"}


def _funnel(campaign_id: uuid.UUID, *, accepted: int, clicked: int) -> CampaignFunnel:
    return CampaignFunnel(
        campaign_id=campaign_id,
        generated_at=NOW,
        evidence_window=None,
        targeted=accepted,
        sent=accepted,
        accepted=accepted,
        delivered=accepted - 1,
        failed=0,
        indeterminate=0,
        opened=clicked,
        clicked=clicked,
        reported=1,
        training_assigned=accepted,
        training_completed=accepted // 2,
    )


def _report() -> CampaignTrendReport:
    first = _funnel(FIRST_ID, accepted=2, clicked=1)
    second = _funnel(SECOND_ID, accepted=8, clicked=1)
    return CampaignTrendReport(
        generated_at=NOW,
        selection_window=CampaignSelectionWindow(START, NOW),
        truncated=False,
        points=(
            CampaignTrendPoint(
                campaign_id=FIRST_ID,
                schedule_start=NOW - timedelta(days=20),
                schedule_end=NOW - timedelta(days=20) + timedelta(hours=1),
                state=dm.CampaignState.COMPLETED,
                funnel=first,
            ),
            CampaignTrendPoint(
                campaign_id=SECOND_ID,
                schedule_start=NOW - timedelta(days=10),
                schedule_end=NOW - timedelta(days=10) + timedelta(hours=1),
                state=dm.CampaignState.STOPPED,
                funnel=second,
            ),
        ),
        portfolio=CampaignPortfolio(
            targeted=10,
            sent=10,
            accepted=10,
            delivered=8,
            failed=0,
            indeterminate=0,
            opened=2,
            clicked=2,
            reported=2,
            training_assigned=10,
            training_completed=5,
        ),
    )


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[TestClient, OperatorApiSettings]]:
    settings = _settings()
    monkeypatch.setattr(analytics_routes, "campaign_trend", lambda *_args, **_kwargs: _report())
    app = create_app(settings)
    app.dependency_overrides[get_session] = lambda: object()
    with TestClient(app) as test_client:
        yield test_client, settings


def _query() -> str:
    start = START.isoformat().replace("+00:00", "Z")
    end = NOW.isoformat().replace("+00:00", "Z")
    return f"?schedule_start={start}&schedule_end={end}&limit=12"


def test_trend_requires_authentication_and_aggregate_capability(
    client: tuple[TestClient, OperatorApiSettings],
) -> None:
    test_client, settings = client
    path = f"/api/v1/analytics/campaigns/trend{_query()}"
    assert test_client.get(path).status_code == 401
    assert test_client.get(path, headers=_headers(settings, "unknown_role")).status_code == 403


def test_trend_json_is_weighted_denominator_explicit_and_pii_free(
    client: tuple[TestClient, OperatorApiSettings],
) -> None:
    test_client, settings = client
    response = test_client.get(
        f"/api/v1/analytics/campaigns/trend{_query()}",
        headers=_headers(settings, "campaign_author"),
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["schema_version"] == "1"
    assert [point["campaign_id"] for point in body["points"]] == [str(FIRST_ID), str(SECOND_ID)]
    assert body["portfolio"]["unit"] == "campaign_assignment_exposures"
    clicked = next(rate for rate in body["portfolio"]["rates"] if rate["name"] == "clicked")
    assert clicked == {
        "name": "clicked",
        "numerator": 2,
        "denominator": 10,
        "denominator_name": "provider_accepted_handoff_exposures",
        "value": 0.2,
    }
    assert "never averages rates" in body["semantics"]["portfolio"]
    assert "not inbox placement" in body["semantics"]["delivered"]
    assert "not causal efficacy" in body["semantics"]["training_completed"]
    assert "not subtracted" in body["semantics"]["corrections"]

    def keys(value: object) -> set[str]:
        if isinstance(value, dict):
            return set(value) | {key for nested in value.values() for key in keys(nested)}
        if isinstance(value, list):
            return {key for nested in value for key in keys(nested)}
        return set()

    assert keys(body).isdisjoint({"title", "mailbox", "recipient_id", "department", "display_name", "employee_key"})


@pytest.mark.parametrize(
    "query",
    [
        "",
        "?schedule_start=2026-01-01T00:00:00Z",
        "?schedule_start=2026-01-01T00:00:00Z&schedule_end=2026-02-01T00:00:00Z&limit=13",
    ],
)
def test_trend_rejects_missing_and_out_of_range_inputs(
    client: tuple[TestClient, OperatorApiSettings], query: str
) -> None:
    test_client, settings = client
    response = test_client.get(
        f"/api/v1/analytics/campaigns/trend{query}",
        headers=_headers(settings, "campaign_author"),
    )
    assert response.status_code == 422, response.text


@pytest.mark.parametrize(
    ("query", "expected_detail"),
    [
        (
            "?schedule_start=2026-01-01T00:00:00&schedule_end=2026-02-01T00:00:00",
            "KP-001: campaign selection timestamps must include a timezone",
        ),
        (
            "?schedule_start=2026-02-01T00:00:00Z&schedule_end=2026-01-01T00:00:00Z",
            "KP-001: campaign selection start must precede end",
        ),
        (
            "?schedule_start=2025-01-01T00:00:00Z&schedule_end=2026-01-03T00:00:00Z",
            "KP-001: campaign selection window cannot exceed 366 days",
        ),
    ],
)
def test_trend_window_errors_have_stable_public_messages(
    client: tuple[TestClient, OperatorApiSettings], query: str, expected_detail: str
) -> None:
    test_client, settings = client
    response = test_client.get(
        f"/api/v1/analytics/campaigns/trend{query}",
        headers=_headers(settings, "campaign_author"),
    )

    assert response.status_code == 422, response.text
    assert response.json() == {"code": "KP-001", "detail": expected_detail}


def test_trend_limit_error_keeps_its_stable_public_message(
    client: tuple[TestClient, OperatorApiSettings], monkeypatch: pytest.MonkeyPatch
) -> None:
    test_client, settings = client

    def invalid_limit(*_args: object, **_kwargs: object) -> CampaignTrendReport:
        raise ValueError("trend limit must be between 1 and 12")

    monkeypatch.setattr(analytics_routes, "campaign_trend", invalid_limit)
    response = test_client.get(
        f"/api/v1/analytics/campaigns/trend{_query()}",
        headers=_headers(settings, "campaign_author"),
    )

    assert response.status_code == 422, response.text
    assert response.json() == {
        "code": "KP-001",
        "detail": "KP-001: trend limit must be between 1 and 12",
    }


def test_trend_does_not_reflect_arbitrary_value_error(
    client: tuple[TestClient, OperatorApiSettings], monkeypatch: pytest.MonkeyPatch
) -> None:
    test_client, settings = client
    secret = "postgresql://operator:do-not-reflect@database.internal/reports"

    def fail_closed(*_args: object, **_kwargs: object) -> CampaignTrendReport:
        raise ValueError(secret)

    monkeypatch.setattr(analytics_routes, "campaign_trend", fail_closed)
    response = test_client.get(
        f"/api/v1/analytics/campaigns/trend{_query()}",
        headers=_headers(settings, "campaign_author"),
    )

    assert response.status_code == 422, response.text
    assert response.json() == {"code": "KP-001", "detail": "KP-001: campaign trend request is invalid"}
    assert secret not in response.text


def test_trend_normalizes_bounds_before_query(
    client: tuple[TestClient, OperatorApiSettings], monkeypatch: pytest.MonkeyPatch
) -> None:
    test_client, settings = client
    seen: dict[str, Any] = {}

    def capture(*_args: object, **kwargs: Any) -> CampaignTrendReport:
        seen.update(kwargs)
        return _report()

    monkeypatch.setattr(analytics_routes, "campaign_trend", capture)
    response = test_client.get(
        "/api/v1/analytics/campaigns/trend"
        "?schedule_start=2026-08-01T00:00:00-04:00&schedule_end=2026-08-02T00:00:00-04:00&limit=2",
        headers=_headers(settings, "campaign_author"),
    )

    assert response.status_code == 200, response.text
    window = seen["schedule_window"]
    assert isinstance(window, CampaignSelectionWindow)
    assert window.start == datetime(2026, 8, 1, 4, tzinfo=UTC)
    assert seen["limit"] == 2


def test_trend_csv_requires_bulk_export_and_remains_formula_safe(
    client: tuple[TestClient, OperatorApiSettings],
) -> None:
    test_client, settings = client
    path = f"/api/v1/analytics/campaigns/trend.csv{_query()}"
    assert test_client.get(path, headers=_headers(settings, "campaign_author")).status_code == 403

    response = test_client.get(path, headers=_headers(settings, "administrator"))
    assert response.status_code == 200, response.text
    assert response.headers["content-disposition"] == 'attachment; filename="campaign-trend-analytics.csv"'
    rows = list(csv.reader(io.StringIO(response.text)))
    assert rows[0][0:3] == ["scope", "campaign_id", "schedule_start"]
    assert any(row[0] == "portfolio_assignment_exposures" and row[9:11] == ["rate", "clicked"] for row in rows)
    assert all(not cell.startswith(("=", "+", "-", "@")) for row in rows for cell in row)
    serialized = response.text.lower()
    for forbidden in ("title", "mailbox", "recipient_id", "department", "display_name", "employee_key"):
        assert forbidden not in serialized
