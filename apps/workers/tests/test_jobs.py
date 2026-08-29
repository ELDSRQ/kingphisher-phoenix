"""Delivery ownership tests against the disposable development PostgreSQL."""

from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from kp_database.base import Base
from kp_database.models import Campaign, CampaignPattern, CipherText, Recipient, RecipientAssignment
from kp_database.session import create_db_engine, make_session_factory
from kp_domain_models import models as dm
from kp_workers.jobs import (
    _DELIVERABLE_CAMPAIGN_STATES,
    _TERMINAL_CAMPAIGN_STATES,
    _TEST_SEND_CAMPAIGN_STATES,
    _campaign_state_allows_delivery,
    _claim_delivery,
    _delivery_tracking_bearer,
    reconcile_campaign_lifecycle,
)
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

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
    except Exception:  # noqa: BLE001 - optional local dependency
        return False


requires_db = pytest.mark.skipif(not _db_available(), reason="PostgreSQL integration database is not reachable")


@pytest.mark.parametrize(
    "state",
    [
        dm.CampaignState.STOPPED,
        dm.CampaignState.COMPLETED,
        dm.CampaignState.CANCELLED,
        dm.CampaignState.EXPIRED,
        dm.CampaignState.RECALL_IN_PROGRESS,
        dm.CampaignState.RECALLED,
        dm.CampaignState.REJECTED,
    ],
)
def test_test_send_fails_closed_for_ended_campaigns(state: dm.CampaignState) -> None:
    assert _campaign_state_allows_delivery(state, test_send=True) is False


def test_delivery_state_fence_preserves_review_test_sends_and_regular_launch_states() -> None:
    review_states = {
        dm.CampaignState.DRAFT,
        dm.CampaignState.PATTERN_REVIEW,
        dm.CampaignState.CONTENT_REVIEW,
        dm.CampaignState.SECURITY_REVIEW,
        dm.CampaignState.PRIVACY_REVIEW,
        dm.CampaignState.PENDING_APPROVAL,
        dm.CampaignState.APPROVED,
    }
    launch_states = {
        dm.CampaignState.SCHEDULED,
        dm.CampaignState.SENDING,
        dm.CampaignState.ACTIVE,
    }

    assert all(_campaign_state_allows_delivery(state, test_send=True) for state in review_states | launch_states)
    assert all(_campaign_state_allows_delivery(state, test_send=False) for state in launch_states)
    assert all(not _campaign_state_allows_delivery(state, test_send=False) for state in review_states)
    assert review_states | launch_states == _TEST_SEND_CAMPAIGN_STATES
    assert launch_states == _DELIVERABLE_CAMPAIGN_STATES
    assert frozenset(dm.CampaignState) == _TEST_SEND_CAMPAIGN_STATES | _TERMINAL_CAMPAIGN_STATES


def test_delivery_bearer_is_bound_to_assignment_verifier_and_checksum() -> None:
    assignment_id = uuid4()
    bearer = "A" * 43
    verifier = "ab" * 32
    assignment = SimpleNamespace(recipient_assignment_id=assignment_id)
    token = SimpleNamespace(
        recipient_assignment_id=assignment_id,
        token_hash=verifier,
        status=dm.TokenStatus.ACTIVE,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    payload = {
        "tracking_bearers": {
            str(assignment_id): {
                "bearer": bearer,
                "verifier": verifier,
                "checksum": hashlib.sha256(bearer.encode("ascii")).hexdigest(),
            }
        }
    }

    assert _delivery_tracking_bearer(payload, assignment, token) == (bearer, "ok")  # type: ignore[arg-type]
    payload["tracking_bearers"][str(assignment_id)]["bearer"] = "B" * 43
    assert _delivery_tracking_bearer(payload, assignment, token) == (None, "tracking_bearer_invalid")  # type: ignore[arg-type]
    assert _delivery_tracking_bearer({}, assignment, token) == (None, "tracking_bearer_missing")  # type: ignore[arg-type]


def _seed_assignment() -> tuple[Engine, sessionmaker[Session], UUID, UUID]:
    engine = create_db_engine(TEST_URL)
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    CipherText.configure_key(b"0" * 32)
    factory = make_session_factory(engine)
    session = factory()
    pattern = CampaignPattern(
        campaign_pattern_id=uuid4(),
        lure_category=dm.LureCategory.OTHER,
        confidence=dm.Confidence.HIGH,
    )
    session.add(pattern)
    session.flush()
    campaign = Campaign(
        campaign_id=uuid4(),
        pattern_id=pattern.campaign_pattern_id,
        title="Claim test",
        state=dm.CampaignState.ACTIVE,
        sender_mailbox="sender@example.com",
        training_domain="training.example.com",
        schedule_end=datetime.now(UTC) + timedelta(days=7),
        max_recipients=1,
        expires_at=datetime.now(UTC) + timedelta(days=7),
    )
    recipient = Recipient(
        recipient_id=uuid4(),
        employee_key="claim-test",
        mailbox="learner@example.com",
        mailbox_sha256="c" * 64,
        status=dm.RecipientStatus.ACTIVE,
    )
    assignment = RecipientAssignment(
        recipient_assignment_id=uuid4(),
        campaign_id=campaign.campaign_id,
        recipient_id=recipient.recipient_id,
        send_state=dm.SendState.QUEUED,
        idempotency_key=f"claim-{uuid4()}",
    )
    session.add_all([campaign, recipient])
    session.flush()
    session.add(assignment)
    session.commit()
    session.close()
    return engine, factory, assignment.recipient_assignment_id, campaign.campaign_id


@pytest.mark.postgres
@requires_db
def test_competing_delivery_claims_allow_exactly_one_owner() -> None:
    engine, factory, assignment_id, campaign_id = _seed_assignment()
    first = factory()
    second = factory()
    try:
        first_row = first.get(RecipientAssignment, assignment_id)
        second_row = second.get(RecipientAssignment, assignment_id)
        assert first_row is not None and second_row is not None

        claimed_at = datetime.now(UTC)
        first_attempt = _claim_delivery(first, first_row, campaign_id, claimed_at=claimed_at)
        second_attempt = _claim_delivery(second, second_row, campaign_id, claimed_at=claimed_at)

        assert first_attempt is not None
        assert second_attempt is None
        verify = factory()
        try:
            stored = verify.get(RecipientAssignment, assignment_id)
            assert stored is not None
            assert stored.send_state == dm.SendState.SENDING
            assert stored.delivery_attempt_id == first_attempt
            assert stored.delivery_attempt_count == 1
        finally:
            verify.close()
    finally:
        first.close()
        second.close()
        engine.dispose()


@pytest.mark.postgres
@requires_db
def test_stale_claim_becomes_indeterminate_and_never_queued() -> None:
    engine, factory, assignment_id, campaign_id = _seed_assignment()
    session = factory()
    try:
        row = session.get(RecipientAssignment, assignment_id)
        assert row is not None
        claimed_at = datetime.now(UTC) - timedelta(hours=25)
        assert _claim_delivery(session, row, campaign_id, claimed_at=claimed_at) is not None

        reconcile_campaign_lifecycle(session, datetime.now(UTC), queued_stale_hours=24)
        session.commit()
        session.refresh(row)
        assert row.send_state == dm.SendState.INDETERMINATE
        assert row.failure_reason == "worker_lost_after_claim"
        assert row.delivery_attempt_id is not None
    finally:
        session.close()
        engine.dispose()


@pytest.mark.postgres
@requires_db
def test_campaign_shared_delivery_lock_excludes_scoped_stop_update() -> None:
    engine, factory, _assignment_id, campaign_id = _seed_assignment()
    delivery = factory()
    scoped_stop = factory()
    try:
        locked = delivery.get(
            Campaign,
            campaign_id,
            with_for_update={"read": True},
            populate_existing=True,
        )
        assert locked is not None

        scoped_stop.execute(text("SET LOCAL lock_timeout = '250ms'"))
        with pytest.raises(OperationalError):
            scoped_stop.get(
                Campaign,
                campaign_id,
                with_for_update=True,
                populate_existing=True,
            )
        scoped_stop.rollback()

        delivery.rollback()
        assert (
            scoped_stop.get(
                Campaign,
                campaign_id,
                with_for_update=True,
                populate_existing=True,
            )
            is not None
        )
    finally:
        delivery.close()
        scoped_stop.close()
        engine.dispose()
