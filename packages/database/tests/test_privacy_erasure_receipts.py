"""Erasure must delete reply AND reported receipts for a subject (KP-AUD-003).

These belong to the explicit ``make test-postgres`` profile and require its
migrated disposable database and roles. Reply receipts previously escaped
``erase_recipient_data`` entirely, leaving orphaned rows carrying the subject's
encrypted external message id; the awareness ledger is PII-free and pseudonymous
and is intentionally retained through erasure.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, date, datetime, timedelta
from uuid import uuid4

import pytest
from kp_database.base import Base
from kp_database.models import (
    AwarenessLedgerEntry,
    Campaign,
    CampaignPattern,
    CipherText,
    Recipient,
    RecipientAssignment,
    ReplyMailReceipt,
    ReportedMailReceipt,
)
from kp_database.privacy import erase_recipient_data
from kp_database.reporting import SINGLE_TENANT_DATABASE_SCOPE
from kp_database.session import create_db_engine, make_session_factory
from kp_domain_models import models as dm
from sqlalchemy import func, select
from sqlalchemy.orm import Session

pytestmark = pytest.mark.postgres

KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

TEST_URL = os.environ.get(
    "DATABASE_URL_TEST", "postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher_test"
)

_available = None


def _db_available() -> bool:
    if os.environ.get("KP_TEST_PROFILE") != "postgres":
        return False
    global _available
    if _available is None:
        engine = None
        try:
            engine = create_db_engine(TEST_URL)
            with engine.connect():
                pass
            _available = True
        except Exception:
            _available = False
        finally:
            if engine is not None:
                engine.dispose()
    return _available


requires_db = pytest.mark.skipif(not _db_available(), reason="PostgreSQL integration database is not reachable")


@pytest.fixture(scope="module", autouse=True)
def _setup() -> None:
    engine = create_db_engine(TEST_URL)
    try:
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)
    finally:
        engine.dispose()
    CipherText.configure_key(bytes.fromhex(KEK))


@contextmanager
def _test_session() -> Iterator[Session]:
    engine = create_db_engine(TEST_URL)
    try:
        with make_session_factory(engine)() as session:
            yield session
    finally:
        engine.dispose()


def _seed_subject_with_receipts() -> tuple[str, str]:
    """Seed a recipient with one assignment, a reply + reported receipt, and a
    retained pseudonymous awareness-ledger entry. Returns (recipient_id,
    assignment_id)."""
    with _test_session() as session:
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
            title="Erasure Drill",
            state=dm.CampaignState.COMPLETED,
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
            employee_key=f"erase-{uuid4()}",
            mailbox=f"erase-{uuid4()}@example.com",
            # A unique 64-char hex digest per row (uq_recipients_mailbox_sha256_active).
            mailbox_sha256=(uuid4().hex + uuid4().hex)[:64],
            display_name="Erase Subject",
        )
        session.add(recipient)
        session.flush()
        assignment = RecipientAssignment(
            recipient_assignment_id=uuid4(),
            campaign_id=campaign.campaign_id,
            recipient_id=recipient.recipient_id,
            send_state=dm.SendState.DELIVERED,
            idempotency_key=f"erase-assign-{uuid4()}",
            created_at=datetime.now(UTC),
        )
        session.add(assignment)
        session.flush()
        session.add(
            ReportedMailReceipt(
                reported_mail_receipt_id=uuid4(),
                provider="microsoft365",
                scope_hash="1" * 64,
                external_id="reported-secret",
                external_id_hash="2" * 64,
                recipient_assignment_id=assignment.recipient_assignment_id,
                disposition="reported",
                evidence={},
                received_at=datetime.now(UTC),
            )
        )
        session.add(
            ReplyMailReceipt(
                reply_mail_receipt_id=uuid4(),
                provider="microsoft365",
                scope_hash="3" * 64,
                external_id="reply-secret",
                external_id_hash="4" * 64,
                recipient_assignment_id=assignment.recipient_assignment_id,
                disposition="replied",
                evidence={},
                received_at=datetime.now(UTC),
            )
        )
        campaign_date = date.today()
        session.add(
            AwarenessLedgerEntry(
                awareness_ledger_entry_id=uuid4(),
                tenant_scope=SINGLE_TENANT_DATABASE_SCOPE,
                pseudonym_key_version="synthetic-local-v1",
                recipient_pseudonym="a" * 64,
                assignment_exposure_pseudonym="b" * 64,
                campaign_id=campaign.campaign_id,
                campaign_date=campaign_date,
                campaign_date_basis="scheduled_start",
                targeted=True,
                accepted=False,
                delivered=False,
                observed_open=False,
                observed_click=False,
                reported=False,
                confirmed_interaction=False,
                training_assigned=False,
                training_started=False,
                training_completed=False,
                training_passed=False,
                campaign_closed=True,
                no_activity_at_close=True,
                projected_at=datetime.now(UTC),
                retain_until=campaign_date + timedelta(days=1826),
            )
        )
        session.commit()
        return str(recipient.recipient_id), str(assignment.recipient_assignment_id)


@requires_db
def test_erasure_deletes_reply_and_reported_receipts() -> None:
    import uuid as _uuid

    recipient_id, assignment_id = _seed_subject_with_receipts()
    assignment_uuid = _uuid.UUID(assignment_id)

    with _test_session() as session:
        assert (
            session.scalar(
                select(func.count())
                .select_from(ReplyMailReceipt)
                .where(ReplyMailReceipt.recipient_assignment_id == assignment_uuid)
            )
            == 1
        )
        assert (
            session.scalar(
                select(func.count())
                .select_from(ReportedMailReceipt)
                .where(ReportedMailReceipt.recipient_assignment_id == assignment_uuid)
            )
            == 1
        )
        ledger_before = session.scalar(select(func.count()).select_from(AwarenessLedgerEntry)) or 0

    with _test_session() as session:
        erased = erase_recipient_data(session, _uuid.UUID(recipient_id), erased_at=datetime.now(UTC))
        session.commit()
        assert erased is True

    with _test_session() as session:
        # Both receipt tables for this subject's assignment are empty, and the
        # assignment itself is gone (so no SET NULL orphan can remain).
        assert (
            session.scalar(
                select(func.count())
                .select_from(ReplyMailReceipt)
                .where(ReplyMailReceipt.recipient_assignment_id == assignment_uuid)
            )
            == 0
        )
        assert (
            session.scalar(
                select(func.count())
                .select_from(ReportedMailReceipt)
                .where(ReportedMailReceipt.recipient_assignment_id == assignment_uuid)
            )
            == 0
        )
        assert session.get(RecipientAssignment, assignment_uuid) is None
        # No orphaned receipt (SET NULL) left anywhere from this assignment.
        assert (
            session.scalar(
                select(func.count()).select_from(ReplyMailReceipt).where(ReplyMailReceipt.external_id_hash == "4" * 64)
            )
            == 0
        )
        # The pseudonymous awareness ledger is intentionally retained.
        ledger_after = session.scalar(select(func.count()).select_from(AwarenessLedgerEntry)) or 0
        assert ledger_after == ledger_before

        recipient = session.get(Recipient, _uuid.UUID(recipient_id))
        assert recipient is not None and recipient.deleted_at is not None
