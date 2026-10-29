"""Erasure must delete reply AND reported receipts for a subject (KP-AUD-003).

These belong to the explicit ``make test-postgres`` profile and require its
migrated disposable database and roles. Reply receipts previously escaped
``erase_recipient_data`` entirely, leaving orphaned rows carrying the subject's
encrypted external message id. The awareness ledger is PSEUDONYMOUS (not
anonymous): its recipient_pseudonym is HMAC(key, recipient_id), so while the
governed key exists the rows stay re-identifiable personal data. Erasure
therefore PURGES the subject's ledger rows under the active key version
(Option A): the subject's rows disappear while a bystander's identical-shaped
rows are untouched.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, date, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from kp_database.awareness_ledger import (
    LOCAL_AWARENESS_PSEUDONYM_KEY,
    LOCAL_AWARENESS_PSEUDONYM_KEY_VERSION,
    recipient_pseudonym,
)
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
_LEDGER_KEY = bytes.fromhex(LOCAL_AWARENESS_PSEUDONYM_KEY)
_LEDGER_VERSION = LOCAL_AWARENESS_PSEUDONYM_KEY_VERSION

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


def _unique_hex() -> str:
    return (uuid4().hex + uuid4().hex)[:64]


def _seed_subject_with_receipts(tag: str) -> tuple[str, str, str, str]:
    """Seed a recipient with one assignment, a reply + reported receipt, and a
    retained pseudonymous awareness-ledger entry.

    Returns ``(recipient_id, assignment_id, reply_external_id_hash,
    reported_external_id_hash)``. All provider/scope/external-id hashes are
    unique per subject so two subjects can coexist (uq_reply/reported_external).
    """
    reply_hash = _unique_hex()
    reported_hash = _unique_hex()
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
            title=f"Erasure Drill {tag}",
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
            employee_key=f"erase-{tag}-{uuid4()}",
            mailbox=f"erase-{tag}-{uuid4()}@example.com",
            # A unique 64-char hex digest per row (uq_recipients_mailbox_sha256_active).
            mailbox_sha256=_unique_hex(),
            display_name="Erase Subject",
        )
        session.add(recipient)
        session.flush()
        assignment = RecipientAssignment(
            recipient_assignment_id=uuid4(),
            campaign_id=campaign.campaign_id,
            recipient_id=recipient.recipient_id,
            send_state=dm.SendState.DELIVERED,
            idempotency_key=f"erase-assign-{tag}-{uuid4()}",
            created_at=datetime.now(UTC),
        )
        session.add(assignment)
        session.flush()
        session.add(
            ReportedMailReceipt(
                reported_mail_receipt_id=uuid4(),
                provider="microsoft365",
                scope_hash=_unique_hex(),
                external_id=f"reported-secret-{tag}",
                external_id_hash=reported_hash,
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
                scope_hash=_unique_hex(),
                external_id=f"reply-secret-{tag}",
                external_id_hash=reply_hash,
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
                pseudonym_key_version=_LEDGER_VERSION,
                # Real keyed pseudonym so erasure can recompute and match it.
                recipient_pseudonym=recipient_pseudonym(
                    tenant_scope=SINGLE_TENANT_DATABASE_SCOPE,
                    recipient_id=recipient.recipient_id,
                    key=_LEDGER_KEY,
                ),
                assignment_exposure_pseudonym=_unique_hex(),
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
        return (
            str(recipient.recipient_id),
            str(assignment.recipient_assignment_id),
            reply_hash,
            reported_hash,
        )


def _receipt_counts(session: Session, assignment_uuid: UUID) -> tuple[int, int]:
    reply = (
        session.scalar(
            select(func.count())
            .select_from(ReplyMailReceipt)
            .where(ReplyMailReceipt.recipient_assignment_id == assignment_uuid)
        )
        or 0
    )
    reported = (
        session.scalar(
            select(func.count())
            .select_from(ReportedMailReceipt)
            .where(ReportedMailReceipt.recipient_assignment_id == assignment_uuid)
        )
        or 0
    )
    return reply, reported


@requires_db
def test_erasure_deletes_subject_receipts_and_spares_other_subjects() -> None:
    # Subject under erasure, and a bystander whose data must be untouched.
    recipient_id, assignment_id, reply_hash, reported_hash = _seed_subject_with_receipts("subject")
    other_id, other_assignment_id, other_reply_hash, other_reported_hash = _seed_subject_with_receipts("bystander")
    assignment_uuid = UUID(assignment_id)
    other_assignment_uuid = UUID(other_assignment_id)

    with _test_session() as session:
        assert _receipt_counts(session, assignment_uuid) == (1, 1)
        assert _receipt_counts(session, other_assignment_uuid) == (1, 1)
        ledger_before = session.scalar(select(func.count()).select_from(AwarenessLedgerEntry)) or 0

    subject_pseudonym = recipient_pseudonym(
        tenant_scope=SINGLE_TENANT_DATABASE_SCOPE, recipient_id=UUID(recipient_id), key=_LEDGER_KEY
    )
    other_pseudonym = recipient_pseudonym(
        tenant_scope=SINGLE_TENANT_DATABASE_SCOPE, recipient_id=UUID(other_id), key=_LEDGER_KEY
    )

    with _test_session() as session:
        erased = erase_recipient_data(
            session,
            UUID(recipient_id),
            erased_at=datetime.now(UTC),
            pseudonym_key=_LEDGER_KEY,
            pseudonym_key_version=_LEDGER_VERSION,
        )
        session.commit()
        assert erased is True

    with _test_session() as session:
        # The erased subject's receipts are gone and the assignment removed, so
        # no SET NULL orphan can remain for either receipt table.
        assert _receipt_counts(session, assignment_uuid) == (0, 0)
        assert session.get(RecipientAssignment, assignment_uuid) is None
        for model, erased_hash in (
            (ReplyMailReceipt, reply_hash),
            (ReportedMailReceipt, reported_hash),
        ):
            assert (
                session.scalar(select(func.count()).select_from(model).where(model.external_id_hash == erased_hash))
                == 0
            )

        # Over-deletion guard: the bystander subject keeps BOTH receipts and its
        # assignment. Erasure is strictly scoped to the subject's assignments.
        assert _receipt_counts(session, other_assignment_uuid) == (1, 1)
        assert session.get(RecipientAssignment, other_assignment_uuid) is not None
        assert (
            session.scalar(
                select(func.count())
                .select_from(ReplyMailReceipt)
                .where(ReplyMailReceipt.external_id_hash == other_reply_hash)
            )
            == 1
        )
        assert (
            session.scalar(
                select(func.count())
                .select_from(ReportedMailReceipt)
                .where(ReportedMailReceipt.external_id_hash == other_reported_hash)
            )
            == 1
        )
        other = session.get(Recipient, UUID(other_id))
        assert other is not None and other.deleted_at is None

        # Option A: the subject's keyed-pseudonym ledger rows are PURGED on
        # erasure, while the bystander's identical-shaped row is untouched.
        def _ledger_rows_for(pseudonym: str) -> int:
            return (
                session.scalar(
                    select(func.count())
                    .select_from(AwarenessLedgerEntry)
                    .where(
                        AwarenessLedgerEntry.tenant_scope == SINGLE_TENANT_DATABASE_SCOPE,
                        AwarenessLedgerEntry.recipient_pseudonym == pseudonym,
                        AwarenessLedgerEntry.pseudonym_key_version == _LEDGER_VERSION,
                    )
                )
                or 0
            )

        assert _ledger_rows_for(subject_pseudonym) == 0
        assert _ledger_rows_for(other_pseudonym) == 1
        ledger_after = session.scalar(select(func.count()).select_from(AwarenessLedgerEntry)) or 0
        assert ledger_after == ledger_before - 1

        recipient = session.get(Recipient, UUID(recipient_id))
        assert recipient is not None and recipient.deleted_at is not None
