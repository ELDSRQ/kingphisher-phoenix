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
    LedgerRepeatBucket,
    LedgerRepeatDistribution,
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


def _report() -> LedgerRepeatDistribution:
    return LedgerRepeatDistribution(
        generated_at=NOW,
        window_start_inclusive=START,
        window_end_exclusive=END,
        exposure_buckets=(
            LedgerRepeatBucket(exposures=1, participants=12),
            LedgerRepeatBucket(exposures=2, participants=4),
            LedgerRepeatBucket(exposures=3, participants=2),
            LedgerRepeatBucket(exposures=4, participants=1),
            LedgerRepeatBucket(exposures=5, participants=1),
        ),
        engaged_buckets=(
            LedgerRepeatBucket(exposures=1, participants=10),
            LedgerRepeatBucket(exposures=2, participants=3),
            LedgerRepeatBucket(exposures=3, participants=1),
            LedgerRepeatBucket(exposures=4, participants=0),
            LedgerRepeatBucket(exposures=5, participants=0),
        ),
        unique_exposed=20,
        exposures_total=31,
        unique_engaged=14,
        engaged_exposures_total=17,
        no_activity_at_close=3,
    )


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[TestClient, OperatorApiSettings]]:
    settings = _settings()
    monkeypatch.setattr(analytics_routes, "ledger_repeat_distribution", lambda *_args, **_kwargs: _report())
    app = create_app(settings)
    app.dependency_overrides[get_session] = lambda: object()
    with TestClient(app) as test_client:
        yield test_client, settings


def _query() -> str:
    return f"?window_start={START.isoformat()}&window_end={END.isoformat()}"


def test_ledger_repeats_requires_authentication_and_aggregate_capability(
    client: tuple[TestClient, OperatorApiSettings],
) -> None:
    test_client, settings = client
    path = f"/api/v1/analytics/ledger/repeats{_query()}"
    assert test_client.get(path).status_code == 401
    assert test_client.get(path, headers=_headers(settings, "unknown_role")).status_code == 403


def test_ledger_repeats_json_is_bounded_denominator_explicit_and_pseudonym_free(
    client: tuple[TestClient, OperatorApiSettings],
) -> None:
    test_client, settings = client
    response = test_client.get(
        f"/api/v1/analytics/ledger/repeats{_query()}",
        headers=_headers(settings, "campaign_author"),
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["schema_version"] == "1"
    assert [bucket["exposures"] for bucket in body["exposure_buckets"]] == [1, 2, 3, 4, 5]
    assert [bucket["participants"] for bucket in body["exposure_buckets"]] == [12, 4, 2, 1, 1]
    assert [bucket["participants"] for bucket in body["engaged_buckets"]] == [10, 3, 1, 0, 0]
    summary = {metric["name"]: metric["value"] for metric in body["summary"]}
    assert summary == {
        "unique_exposed": 20,
        "exposures_total": 31,
        "unique_engaged": 14,
        "engaged_exposures_total": 17,
        "no_activity_at_close": 3,
    }
    rates = {metric["name"]: metric for metric in body["rates"]}
    assert rates["repeat_exposure"]["numerator"] == 8 and rates["repeat_exposure"]["denominator"] == 20
    assert rates["repeat_engagement"]["numerator"] == 4 and rates["repeat_engagement"]["denominator"] == 14
    assert "recipient_pseudonym" not in response.text
    assert ("a" * 64) not in response.text
    assert body["privacy"].startswith("aggregate ledger projections only")


def test_ledger_repeats_csv_requires_export_capability_and_is_pseudonym_free(
    client: tuple[TestClient, OperatorApiSettings],
) -> None:
    test_client, settings = client
    path = f"/api/v1/analytics/ledger/repeats.csv{_query()}"
    assert test_client.get(path).status_code == 401
    assert test_client.get(path, headers=_headers(settings, "campaign_author")).status_code == 403

    response = test_client.get(path, headers=_headers(settings, "administrator"))
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    rows = list(csv.reader(io.StringIO(response.text)))
    header = rows[0]
    assert "kind" in header and "metric" in header and "denominator_name" in header
    assert any(row[4] == "bucket" and row[5] == "exposures_2" for row in rows)
    assert any(row[4] == "summary" and row[5] == "repeat_exposure" for row in rows)
    assert not any(cell.startswith(("=", "+", "-", "@")) for row in rows for cell in row if cell.strip())


def test_ledger_repeats_rejects_invalid_window(client: tuple[TestClient, OperatorApiSettings]) -> None:
    test_client, settings = client
    bad = f"?window_start={END.isoformat()}&window_end={START.isoformat()}"
    response = test_client.get(
        f"/api/v1/analytics/ledger/repeats{bad}",
        headers=_headers(settings, "campaign_author"),
    )
    assert response.status_code == 422
    assert response.json() == {"code": "KP-001", "detail": "KP-001: ledger repeat window start must precede end"}

    oversized_start = date(2020, 1, 1)
    oversized = f"?window_start={oversized_start.isoformat()}&window_end={END.isoformat()}"
    response = test_client.get(
        f"/api/v1/analytics/ledger/repeats{oversized}",
        headers=_headers(settings, "campaign_author"),
    )
    assert response.status_code == 422
    assert response.json() == {"code": "KP-001", "detail": "KP-001: ledger repeat window cannot exceed 1826 days"}
