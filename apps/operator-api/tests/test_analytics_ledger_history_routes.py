from __future__ import annotations

import csv
import io
import uuid
from collections.abc import Iterator
from datetime import UTC, date, datetime

import jwt
import pytest
from fastapi.testclient import TestClient
from kp_database.awareness_ledger import (
    LedgerRecipientHistory,
    LedgerRecipientHistoryEntry,
)
from kp_operator_api import analytics_routes
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.deps import get_session
from kp_operator_api.main import create_app

KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
NOW = datetime(2026, 8, 27, 15, 30, tzinfo=UTC)


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


class _First:
    def __init__(self, present: bool) -> None:
        self._present = present

    def first(self) -> object:
        return object() if self._present else None


class _Session:
    """Minimal session: the recipient existence probe always succeeds."""

    def execute(self, _statement: object) -> _First:
        return _First(True)


def _history() -> LedgerRecipientHistory:
    campaign_a = uuid.uuid4()
    campaign_b = uuid.uuid4()
    return LedgerRecipientHistory(
        recipient_pseudonym="f" * 64,
        pseudonym_key_version="synthetic-local-v1",
        generated_at=NOW,
        truncated=False,
        entries=(
            LedgerRecipientHistoryEntry(
                campaign_id=campaign_a,
                campaign_date=date(2024, 3, 1),
                campaign_date_basis="scheduled_start",
                delivered=True,
                observed_open=True,
                observed_click=False,
                confirmed_interaction=False,
                reported=False,
                training_started=False,
                training_completed=False,
                no_activity_at_close=False,
            ),
            LedgerRecipientHistoryEntry(
                campaign_id=campaign_b,
                campaign_date=date(2025, 7, 1),
                campaign_date_basis="scheduled_start",
                delivered=True,
                observed_open=False,
                observed_click=True,
                confirmed_interaction=True,
                reported=False,
                training_started=True,
                training_completed=True,
                no_activity_at_close=False,
            ),
        ),
        exposures_total=2,
        delivered_total=2,
        engaged_total=2,
        no_activity_at_close_total=0,
        repeat_exposures=1,
    )


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[TestClient, OperatorApiSettings]]:
    settings = _settings()
    monkeypatch.setattr(analytics_routes, "ledger_recipient_history", lambda *_args, **_kwargs: _history())
    app = create_app(settings)
    app.dependency_overrides[get_session] = lambda: _Session()
    with TestClient(app) as test_client:
        yield test_client, settings


RECIPIENT_ID = uuid.uuid4()


def test_ledger_history_requires_authentication_and_named_capability(
    client: tuple[TestClient, OperatorApiSettings],
) -> None:
    test_client, settings = client
    path = f"/api/v1/analytics/ledger/recipients/{RECIPIENT_ID}/history"
    assert test_client.get(path).status_code == 401
    assert test_client.get(path, headers=_headers(settings, "campaign_author")).status_code == 403


def test_ledger_history_json_is_bounded_pseudonym_free_and_named_only(
    client: tuple[TestClient, OperatorApiSettings],
) -> None:
    test_client, settings = client
    response = test_client.get(
        f"/api/v1/analytics/ledger/recipients/{RECIPIENT_ID}/history",
        headers=_headers(settings, "security_approver"),
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["schema_version"] == "1"
    assert body["truncated"] is False
    summary = {metric["name"]: metric["value"] for metric in body["summary"]}
    assert summary == {
        "exposures_total": 2,
        "delivered_total": 2,
        "engaged_total": 2,
        "no_activity_at_close_total": 0,
        "repeat_exposures": 1,
    }
    assert len(body["entries"]) == 2
    assert [entry["campaign_date"] for entry in body["entries"]] == ["2024-03-01", "2025-07-01"]
    assert body["entries"][0]["observed_open"] is True
    assert body["entries"][1]["confirmed_interaction"] is True
    assert "recipient_pseudonym" not in response.text
    assert "assignment_exposure_pseudonym" not in response.text
    assert ("f" * 64) not in response.text
    assert "person@example.com" not in response.text
    assert "display_name" not in response.text
    assert body["privacy"].startswith("named capability-protected ledger history")


def test_ledger_history_csv_requires_export_capability_and_is_pseudonym_free(
    client: tuple[TestClient, OperatorApiSettings],
) -> None:
    test_client, settings = client
    path = f"/api/v1/analytics/ledger/recipients/{RECIPIENT_ID}/history.csv"
    assert test_client.get(path).status_code == 401
    assert test_client.get(path, headers=_headers(settings, "security_approver")).status_code == 403

    response = test_client.get(path, headers=_headers(settings, "administrator"))
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    rows = list(csv.reader(io.StringIO(response.text)))
    header = rows[0]
    assert "campaign_date" in header and "campaign_id" in header and "no_activity_at_close" in header
    assert any(row[3] == "2024-03-01" for row in rows)
    assert any(row[3] == "summary" and row[6] == "repeat_exposures" for row in rows)
    assert not any(cell.startswith(("=", "+", "-", "@")) for row in rows for cell in row if cell.strip())
