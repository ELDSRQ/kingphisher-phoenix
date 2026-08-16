"""WS-6 retention worker tests against a disposable Postgres.

Require the local dev stack (`docker compose up -d postgres`) and the
`kingphisher_test` database (created by `make db-init`); skipped otherwise.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from dotenv import load_dotenv
from kp_database.audit_store import AuditStore
from kp_database.base import Base
from kp_database.models import (
    Campaign,
    CampaignPattern,
    CipherText,
    Recipient,
    RecipientAssignment,
    RetentionAction,
    RetentionPolicy,
)
from kp_database.session import create_db_engine, make_session_factory
from kp_domain_models import models as dm
from kp_workers.config import WorkerSettings
from kp_workers.jobs import WorkerContext, maybe_publish_retention, process_retention, reconcile_campaign_lifecycle
from sqlalchemy import select

load_dotenv(Path(__file__).resolve().parents[3] / ".env", override=False)

HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
KEK = HMAC

TEST_URL = os.environ.get(
    "DATABASE_URL_TEST", "postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher_test"
)

_available = None


def _db_available() -> bool:
    global _available
    if _available is None:
        try:
            engine = create_db_engine(TEST_URL)
            with engine.connect():
                pass
            engine.dispose()
            _available = True
        except Exception:  # noqa: BLE001 - DB simply not up
            _available = False
    return _available


requires_db = pytest.mark.skipif(not _db_available(), reason="dev Postgres not reachable")


class StubQueue:
    def __init__(self) -> None:
        self.published: list[tuple[str, dict]] = []

    def publish(self, topic: str, message: dict) -> None:
        self.published.append((topic, message))


def _make_ctx(queue: StubQueue) -> WorkerContext:
    session_factory = make_session_factory(create_db_engine(TEST_URL))
    audit_store = AuditStore(create_db_engine(TEST_URL), hmac_key=bytes.fromhex(HMAC))
    settings = WorkerSettings(
        audit_hmac_key=HMAC,
        ciphertext_kek=KEK,
        database_url=TEST_URL,
        audit_database_url=TEST_URL,
    )
    return WorkerContext(settings, session_factory, audit_store, queue)


def _seed_assignments() -> tuple[str, str, str]:
    """Seed one campaign with two DELIVERED assignments (old + recent) and one
    QUEUED old assignment. Returns all three assignment identifiers."""
    session = make_session_factory(create_db_engine(TEST_URL))()
    try:
        pattern = CampaignPattern(
            campaign_pattern_id=uuid4(),
            lure_category=dm.LureCategory.INVOICE,
            confidence=dm.Confidence.HIGH,
        )
        session.add(pattern)
        session.flush()
        campaign = Campaign(
            campaign_id=uuid4(),
            pattern_id=pattern.campaign_pattern_id,
            title="Retention Drill",
            state=dm.CampaignState.ACTIVE,
            sender_mailbox="drills@example.com",
            training_domain="training.local",
            timezone="UTC",
            max_recipients=10,
            created_by=uuid4(),
            expires_at=datetime.now(UTC) + timedelta(days=14),
        )
        session.add(campaign)
        recipient = Recipient(
            recipient_id=uuid4(),
            employee_key="u1",
            mailbox="u1@example.com",
            mailbox_sha256="a" * 64,
            display_name="U One",
        )
        session.add(recipient)
        session.flush()

        old_delivered = RecipientAssignment(
            recipient_assignment_id=uuid4(),
            campaign_id=campaign.campaign_id,
            recipient_id=recipient.recipient_id,
            send_state=dm.SendState.DELIVERED,
            idempotency_key=f"old-delivered-{uuid4()}",
            created_at=datetime.now(UTC) - timedelta(days=400),
        )
        recent_delivered = RecipientAssignment(
            recipient_assignment_id=uuid4(),
            campaign_id=campaign.campaign_id,
            recipient_id=recipient.recipient_id,
            send_state=dm.SendState.DELIVERED,
            idempotency_key=f"recent-delivered-{uuid4()}",
            created_at=datetime.now(UTC) - timedelta(days=10),
        )
        old_queued = RecipientAssignment(
            recipient_assignment_id=uuid4(),
            campaign_id=campaign.campaign_id,
            recipient_id=recipient.recipient_id,
            send_state=dm.SendState.QUEUED,
            idempotency_key=f"old-queued-{uuid4()}",
            created_at=datetime.now(UTC) - timedelta(days=400),
        )
        session.add_all([old_delivered, recent_delivered, old_queued])
        session.commit()
        return (
            str(old_delivered.recipient_assignment_id),
            str(recent_delivered.recipient_assignment_id),
            str(old_queued.recipient_assignment_id),
        )
    finally:
        session.close()


def _remaining_assignments() -> set[str]:
    session = make_session_factory(create_db_engine(TEST_URL))()
    try:
        rows = session.execute(select(RecipientAssignment.recipient_assignment_id)).scalars().all()
        return {str(r) for r in rows}
    finally:
        session.close()


@pytest.fixture(scope="module", autouse=True)
def _setup() -> None:
    engine = create_db_engine(TEST_URL)
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    engine.dispose()
    CipherText.configure_key(bytes.fromhex(KEK))


@requires_db
def test_retention_deletes_all_old_assignments() -> None:
    old_id, recent_id, old_queued_id = _seed_assignments()
    session = make_session_factory(create_db_engine(TEST_URL))()
    try:
        session.add(
            RetentionPolicy(
                retention_policy_id=uuid4(),
                name="Default",
                data_category="recipient_assignments",
                retention_days=365,
                is_default=True,
            )
        )
        session.commit()
    finally:
        session.close()

    queue = StubQueue()
    ctx = _make_ctx(queue)
    process_retention(ctx, {"payload": {}, "idempotency_key": f"run-{uuid4()}"})

    remaining = _remaining_assignments()
    assert old_id not in remaining
    assert old_queued_id not in remaining
    assert recent_id in remaining

    session = make_session_factory(create_db_engine(TEST_URL))()
    try:
        action = session.scalar(select(RetentionAction).order_by(RetentionAction.executed_at.desc()).limit(1))
        assert action is not None
        assert action.target_table == "linked_campaign_data"
        assert action.row_count_deleted == 2
    finally:
        session.close()


@requires_db
def test_maybe_publish_retention_self_publishes() -> None:
    queue = StubQueue()
    ctx = _make_ctx(queue)
    maybe_publish_retention(ctx, datetime.now(UTC))
    assert len(queue.published) == 1
    topic, message = queue.published[0]
    assert topic == "retention"
    assert message["retention_policy_id"] == "default"
    assert message["idempotency_key"].startswith("retention-self-")


@requires_db
def test_reconcile_campaign_lifecycle_closes_elapsed_windows() -> None:
    session = make_session_factory(create_db_engine(TEST_URL))()
    try:
        pattern = CampaignPattern(
            campaign_pattern_id=uuid4(),
            lure_category=dm.LureCategory.INVOICE,
            confidence=dm.Confidence.HIGH,
        )
        session.add(pattern)
        session.flush()
        now = datetime.now(UTC)
        active = Campaign(
            campaign_id=uuid4(),
            pattern_id=pattern.campaign_pattern_id,
            title="Active elapsed",
            state=dm.CampaignState.ACTIVE,
            sender_mailbox="drills@example.com",
            training_domain="training.local",
            schedule_end=now - timedelta(minutes=1),
            timezone="UTC",
            max_recipients=1,
            expires_at=now - timedelta(minutes=1),
        )
        scheduled = Campaign(
            campaign_id=uuid4(),
            pattern_id=pattern.campaign_pattern_id,
            title="Never launched",
            state=dm.CampaignState.SCHEDULED,
            sender_mailbox="drills@example.com",
            training_domain="training.local",
            schedule_end=now - timedelta(minutes=1),
            timezone="UTC",
            max_recipients=1,
            expires_at=now - timedelta(minutes=1),
        )
        session.add_all([active, scheduled])
        session.flush()
        assert reconcile_campaign_lifecycle(session, now) == {"completed": 1, "expired": 1}
        session.commit()
        assert active.state == dm.CampaignState.COMPLETED
        assert scheduled.state == dm.CampaignState.EXPIRED
    finally:
        session.close()
