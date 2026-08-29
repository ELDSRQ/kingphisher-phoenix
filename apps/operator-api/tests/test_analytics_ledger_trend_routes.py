from __future__ import annotations

import csv
import io
import uuid
from collections.abc import Iterator
from datetime import UTC, date, datetime

import jwt
import pytest
from fastapi.testclient import TestClient
from kp_database.reporting import (
    LedgerTrendBucket,
    LedgerTrendPortfolio,
    LedgerTrendReport,
)
from kp_operator_api import analytics_routes
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.deps import get_session
from kp_operator_api.main import create_app

KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
NOW = datetime(2026, 8, 27, 15, 30, tzinfo=UTC)
START = date(2021, 1, 1)
END = date(2026, 1, 1)


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


def _report() -> LedgerTrendReport:
    return LedgerTrendReport(
        generated_at=NOW,
        window_start_inclusive=START,
        window_end_exclusive=END,
        buckets=(
            LedgerTrendBucket(
                month=date(2022, 3, 1),
                targeted=10,
                delivered=8,
                clicked=2,
                no_click=6,
                confirmed_interaction=1,
                reported=1,
                training_assigned=10,
                training_completed=4,
                no_activity_at_close=2,
            ),
            LedgerTrendBucket(
                month=date(2025, 7, 1),
                targeted=4,
                delivered=4,
                clicked=3,
                no_click=1,
                confirmed_interaction=2,
                reported=0,
                training_assigned=4,
                training_completed=2,
                no_activity_at_close=0,
            ),
        ),
        portfolio=LedgerTrendPortfolio(
            targeted=14,
            delivered=12,
            clicked=5,
            no_click=7,
            confirmed_interaction=3,
            reported=1,
            training_assigned=14,
            training_completed=6,
            no_activity_at_close=2,
        ),
    )


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[TestClient, OperatorApiSettings]]:
    settings = _settings()
    monkeypatch.setattr(analytics_routes, "ledger_trend", lambda *_args, **_kwargs: _report())
    app = create_app(settings)
    app.dependency_overrides[get_session] = lambda: object()
    with TestClient(app) as test_client:
        yield test_client, settings


def _query() -> str:
    return f"?window_start={START.isoformat()}&window_end={END.isoformat()}"


def test_ledger_trend_requires_authentication_and_aggregate_capability(
    client: tuple[TestClient, OperatorApiSettings],
) -> None:
    test_client, settings = client
    path = f"/api/v1/analytics/ledger/trend{_query()}"
    assert test_client.get(path).status_code == 401
    assert test_client.get(path, headers=_headers(settings, "unknown_role")).status_code == 403


def test_ledger_trend_json_is_bounded_denominator_explicit_and_pseudonym_free(
    client: tuple[TestClient, OperatorApiSettings],
) -> None:
    test_client, settings = client
    response = test_client.get(
        f"/api/v1/analytics/ledger/trend{_query()}",
        headers=_headers(settings, "campaign_author"),
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["schema_version"] == "1"
    assert [bucket["month"] for bucket in body["buckets"]] == ["2022-03-01", "2025-07-01"]
    first = body["buckets"][0]
    counts = {metric["name"]: metric["value"] for metric in first["counts"]}
    assert counts == {
        "targeted": 10,
        "delivered": 8,
        "clicked": 2,
        "no_click": 6,
        "confirmed_interaction": 1,
        "reported": 1,
        "training_assigned": 10,
        "training_completed": 4,
        "no_activity_at_close": 2,
    }
    rates = {metric["name"]: metric for metric in first["rates"]}
    assert rates["clicked"]["numerator"] == 2 and rates["clicked"]["denominator"] == 8
    assert rates["no_click"]["numerator"] == 6 and rates["no_click"]["denominator"] == 8
    portfolio_counts = {metric["name"]: metric["value"] for metric in body["portfolio"]["counts"]}
    assert portfolio_counts["clicked"] == 5 and portfolio_counts["no_click"] == 7
    assert "recipient_pseudonym" not in response.text
    assert "assignment_exposure_pseudonym" not in response.text
    assert ("a" * 64) not in response.text
    assert body["privacy"].startswith("aggregate ledger projections only")


def test_ledger_trend_csv_requires_export_capability_and_is_pseudonym_free(
    client: tuple[TestClient, OperatorApiSettings],
) -> None:
    test_client, settings = client
    path = f"/api/v1/analytics/ledger/trend.csv{_query()}"
    assert test_client.get(path).status_code == 401
    assert test_client.get(path, headers=_headers(settings, "campaign_author")).status_code == 403

    response = test_client.get(path, headers=_headers(settings, "administrator"))
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    rows = list(csv.reader(io.StringIO(response.text)))
    header = rows[0]
    assert "bucket" in header and "metric" in header and "denominator_name" in header
    assert any(row[6] == "clicked" for row in rows)
    assert any(row[4] == "portfolio" for row in rows)
    assert not any(cell.startswith(("=", "+", "-", "@")) for row in rows for cell in row if cell.strip())


def test_ledger_trend_rejects_invalid_window(client: tuple[TestClient, OperatorApiSettings]) -> None:
    test_client, settings = client
    bad = f"?window_start={END.isoformat()}&window_end={START.isoformat()}"
    response = test_client.get(f"/api/v1/analytics/ledger/trend{bad}", headers=_headers(settings, "campaign_author"))
    assert response.status_code == 422
    assert response.json() == {"code": "KP-001", "detail": "KP-001: ledger trend window start must precede end"}

    oversized_start = date(2020, 1, 1)
    oversized = f"?window_start={oversized_start.isoformat()}&window_end={END.isoformat()}"
    response = test_client.get(
        f"/api/v1/analytics/ledger/trend{oversized}",
        headers=_headers(settings, "campaign_author"),
    )
    assert response.status_code == 422
    assert response.json() == {"code": "KP-001", "detail": "KP-001: ledger trend window cannot exceed 1826 days"}
