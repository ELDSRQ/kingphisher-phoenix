"""Persistent global emergency-stop integration tests."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest
from fastapi.testclient import TestClient
from kp_database.base import Base
from kp_database.models import Campaign, CampaignPattern, SystemSafetyState
from kp_database.session import create_db_engine, make_session_factory
from kp_domain_models import models as dm
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.main import create_app

pytestmark = pytest.mark.postgres


KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
TEST_URL = os.environ.get(
    "DATABASE_URL_TEST", "postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher_test"
)


def _db_available() -> bool:
    if os.environ.get("KP_TEST_PROFILE") != "postgres":
        return False
    try:
        engine = create_db_engine(TEST_URL)
        with engine.connect():
            pass
        engine.dispose()
        return True
    except Exception:  # noqa: BLE001 - optional disposable development database
        return False


requires_db = pytest.mark.skipif(not _db_available(), reason="PostgreSQL integration database is not reachable")


def _settings() -> OperatorApiSettings:
    return OperatorApiSettings(
        audit_hmac_key=HMAC,
        ciphertext_kek=KEK,
        console_jwt_secret=CONSOLE_JWT,
        tracking_token_hmac_key="34" * 32,
        roe_signing_key="11" * 32,
        database_url=TEST_URL,
        audit_database_url=TEST_URL,
        console_static_dir="/nonexistent-console-dir",
    )


def _token(role: str) -> str:
    settings = _settings()
    return jwt.encode(
        {
            "sub": str(uuid4()),
            "iss": settings.oidc_issuer,
            "aud": settings.oidc_audience,
            "exp": 2_000_000_000,
            "nbf": 0,
            "realm_access": {"roles": [role]},
        },
        settings.require_console_jwt_secret(),
        algorithm="HS256",
    )


def _client() -> TestClient:
    app = create_app(_settings())
    # This metadata-only integration test verifies persistence and audit
    # events, while immutable-chain health is independently migration-tested.
    app.state.audit_health_check = lambda: True
    return TestClient(app)


@requires_db
def test_global_stop_survives_app_restart_and_only_authorized_reset_reopens() -> None:
    engine = create_db_engine(TEST_URL)
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    factory = make_session_factory(engine)
    campaign_id = uuid4()
    with factory() as session:
        pattern = CampaignPattern(
            campaign_pattern_id=uuid4(),
            lure_category=dm.LureCategory.OTHER,
            confidence=dm.Confidence.HIGH,
        )
        session.add(pattern)
        session.flush()
        session.add_all(
            [
                SystemSafetyState(singleton_id=1, emergency_stop_engaged=False),
                Campaign(
                    campaign_id=campaign_id,
                    pattern_id=pattern.campaign_pattern_id,
                    title="Future campaign",
                    state=dm.CampaignState.DRAFT,
                    sender_mailbox="training@example.com",
                    training_domain="training.example.com",
                    schedule_start=datetime.now(UTC) + timedelta(days=1),
                    schedule_end=datetime.now(UTC) + timedelta(days=2),
                    max_recipients=1,
                    expires_at=datetime.now(UTC) + timedelta(days=3),
                ),
            ]
        )
        session.commit()

    admin = {"Authorization": f"Bearer {_token('administrator')}"}
    auditor = {"Authorization": f"Bearer {_token('auditor')}"}
    try:
        with _client() as first_app:
            missing = first_app.post(
                "/api/v1/kill-switch",
                json={"campaign_id": str(uuid4()), "confirm": True, "reason": "scoped response"},
                headers=admin,
            )
            assert missing.status_code == 404
            engaged = first_app.post(
                "/api/v1/kill-switch",
                json={"confirm": True, "reason": "possible relay compromise"},
                headers=admin,
            )
            assert engaged.status_code == 200
            assert engaged.json()["engaged"] is True
            generation = engaged.json()["generation"]

        # A distinct application instance reads the same row: the state does
        # not depend on process memory or reconstructing audit history.
        with _client() as restarted_app:
            state = restarted_app.get("/api/v1/kill-switch", headers=admin)
            assert state.status_code == 200
            assert state.json()["engaged"] is True
            assert state.json()["engage_reason"] == "possible relay compromise"

            repeated_engage = restarted_app.post(
                "/api/v1/kill-switch",
                json={"confirm": True, "reason": "confirm stop remains required"},
                headers=admin,
            )
            assert repeated_engage.status_code == 200
            assert repeated_engage.json()["changed"] is False
            assert repeated_engage.json()["generation"] == generation

            blocked = restarted_app.post(f"/api/v1/campaigns/{campaign_id}/schedule", headers=admin)
            assert blocked.status_code == 409
            assert "global emergency stop" in blocked.json()["detail"]

            denied = restarted_app.post(
                "/api/v1/kill-switch/reset",
                json={"confirm": True, "reason": "unauthorized attempt"},
                headers=auditor,
            )
            assert denied.status_code == 403
            assert restarted_app.get("/api/v1/kill-switch", headers=admin).json()["engaged"] is True

            reset = restarted_app.post(
                "/api/v1/kill-switch/reset",
                json={"confirm": True, "reason": "relay credentials rotated and validated"},
                headers=admin,
            )
            assert reset.status_code == 200
            assert reset.json() == {"engaged": False, "changed": True, "generation": generation + 1}

            repeated_reset = restarted_app.post(
                "/api/v1/kill-switch/reset",
                json={"confirm": True, "reason": "confirm reset state"},
                headers=admin,
            )
            assert repeated_reset.status_code == 200
            assert repeated_reset.json() == {
                "engaged": False,
                "changed": False,
                "generation": generation + 1,
            }

            attempts = restarted_app.get("/api/v1/audit", headers=admin).json()
            system_actions = [
                event["action"]
                for event in attempts
                if event["object_type"] == "system" and event["object_id"] == "delivery"
            ]
            assert system_actions.count("kill-switch.engage") == 2
            assert system_actions.count("kill-switch.disengage") == 2

        with _client() as after_reset_app:
            assert after_reset_app.get("/api/v1/kill-switch", headers=admin).json()["engaged"] is False
            reopened = after_reset_app.post(f"/api/v1/campaigns/{campaign_id}/schedule", headers=admin)
            assert reopened.status_code == 409
            assert "global emergency stop" not in reopened.json()["detail"]

            scoped = after_reset_app.post(
                "/api/v1/kill-switch",
                json={"campaign_id": str(campaign_id), "confirm": True, "reason": "campaign response"},
                headers=admin,
            )
            assert scoped.status_code == 200
            assert scoped.json()["changed"] is True
            with factory() as session:
                assert session.get(Campaign, campaign_id).state == dm.CampaignState.STOPPED
    finally:
        engine.dispose()
