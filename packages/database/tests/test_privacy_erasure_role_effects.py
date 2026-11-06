"""Migrated, least-privilege erasure effects on a new preserved test database."""

from __future__ import annotations

import os
import threading
import time
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from kp_database.grants import TABLE_GRANTS, WORKLOAD_COLUMN_GRANTS
from kp_database.models import (
    AwarenessLedgerEntry,
    Campaign,
    CampaignPattern,
    CipherText,
    Microsoft365IntegrationState,
    Recipient,
    RecipientAssignment,
    ReplyMailReceipt,
    ReportedMailReceipt,
)
from kp_database.privacy import erase_recipient_data_with_result
from kp_database.reporting import SINGLE_TENANT_DATABASE_SCOPE
from kp_database.retention_holds import RetentionHoldActive, create_retention_hold, release_retention_hold
from kp_database.session import make_session_factory
from kp_domain_models import models as dm
from psycopg import sql
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

pytestmark = pytest.mark.postgres
KEY = b"p" * 32
VERSION = "privacy-role-v1"


@pytest.fixture(scope="module")
def factory():  # type: ignore[no-untyped-def]
    source = make_url(os.environ.get("DATABASE_URL_TEST", "postgresql+psycopg://invalid@127.0.0.1:1/refused"))
    if os.environ.get("KP_TEST_PROFILE") != "postgres" or not (
        source.database == "kingphisher_test"
        or (source.database or "").startswith(("kp_hold_qualification_", "kp_reconcile_qualification_"))
    ):
        pytest.fail("privacy role proof requires the explicit disposable PostgreSQL profile")
    name = f"kp_privacy_qualification_{uuid4().hex}"
    admin = create_engine(source.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        raw = connection.connection.driver_connection
        for role in ("audit_writer", "kp_operator", "kp_worker_retention"):
            if not raw.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (role,)).fetchone():
                raw.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(role)))
        raw.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    admin.dispose()
    url = source.set(database=name).render_as_string(hide_password=False)
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("DATABASE_URL", url)
        command.upgrade(Config(str(Path(__file__).resolve().parents[1] / "alembic.ini")), "head")
    engine = create_engine(url)
    with engine.begin() as connection:
        raw = connection.connection.driver_connection
        raw.execute("GRANT USAGE ON SCHEMA public TO kp_operator")
        for privilege, tables in TABLE_GRANTS["operator"].items():
            raw.execute(
                sql.SQL("GRANT {} ON TABLE {} TO kp_operator").format(
                    sql.SQL(privilege), sql.SQL(", ").join(sql.Identifier(table) for table in tables)
                )
            )
        for privilege, tables in WORKLOAD_COLUMN_GRANTS.get("operator", {}).items():
            for table, columns in tables.items():
                raw.execute(
                    sql.SQL("GRANT {} ({}) ON TABLE {} TO kp_operator").format(
                        sql.SQL(privilege),
                        sql.SQL(", ").join(sql.Identifier(column) for column in columns),
                        sql.Identifier(table),
                    )
                )
    previous = (CipherText._active_key_id, CipherText._active_key, CipherText._prior_keys)
    CipherText.configure_key(bytes.fromhex("17" * 32))
    yield make_session_factory(engine)
    engine.dispose()
    CipherText._active_key_id, CipherText._active_key, CipherText._prior_keys = previous


def _ledger(session, recipient_id: UUID, *, version: str = VERSION):  # type: ignore[no-untyped-def]
    from kp_database.awareness_ledger import recipient_pseudonym

    campaign_date = date(2026, 1, 1)
    entry = AwarenessLedgerEntry(
        awareness_ledger_entry_id=uuid4(),
        tenant_scope=SINGLE_TENANT_DATABASE_SCOPE,
        pseudonym_key_version=version,
        recipient_pseudonym=recipient_pseudonym(
            tenant_scope=SINGLE_TENANT_DATABASE_SCOPE, recipient_id=recipient_id, key=KEY
        ),
        assignment_exposure_pseudonym=uuid4().hex + uuid4().hex,
        campaign_id=uuid4(),
        campaign_date=campaign_date,
        campaign_date_basis="scheduled_start",
        targeted=True,
        accepted=True,
        delivered=True,
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
    session.add(entry)
    return entry.awareness_ledger_entry_id


def _seed(factory, *, tombstoned: bool = False):  # type: ignore[no-untyped-def]
    recipient_id, assignment_id = uuid4(), uuid4()
    now = datetime.now(UTC)
    with factory() as session:
        pattern_id, campaign_id = uuid4(), uuid4()
        session.add(
            CampaignPattern(
                campaign_pattern_id=pattern_id, lure_category=dm.LureCategory.INVOICE, confidence=dm.Confidence.HIGH
            )
        )
        session.flush()
        session.add(
            Campaign(
                campaign_id=campaign_id,
                pattern_id=pattern_id,
                title="Private erasure qualification",
                state=dm.CampaignState.COMPLETED,
                sender_mailbox="drill@example.test",
                training_domain="training.test",
                timezone="UTC",
                max_recipients=10,
                created_by=uuid4(),
                expires_at=now + timedelta(days=1),
            )
        )
        session.add(
            Recipient(
                recipient_id=recipient_id,
                employee_key=f"synthetic-{recipient_id}",
                mailbox=f"synthetic-{recipient_id}@example.test",
                mailbox_sha256=uuid4().hex + uuid4().hex,
                deleted_at=now if tombstoned else None,
            )
        )
        session.flush()
        session.add(
            RecipientAssignment(
                recipient_assignment_id=assignment_id,
                campaign_id=campaign_id,
                recipient_id=recipient_id,
                send_state=dm.SendState.DELIVERED,
                idempotency_key=f"privacy-role-{assignment_id}",
                created_at=now,
            )
        )
        session.flush()
        for model, receipt_key in (
            (ReportedMailReceipt, "reported_mail_receipt_id"),
            (ReplyMailReceipt, "reply_mail_receipt_id"),
        ):
            session.add(
                model(
                    **{
                        receipt_key: uuid4(),
                        "provider": "mailpit",
                        "scope_hash": uuid4().hex + uuid4().hex,
                        "external_id": "synthetic-private-id",
                        "external_id_hash": uuid4().hex + uuid4().hex,
                        "recipient_assignment_id": assignment_id,
                        "disposition": "qualification",
                        "evidence": {},
                        "received_at": now,
                    }
                )
            )
        active = [_ledger(session, recipient_id), _ledger(session, recipient_id)]
        retired = _ledger(session, recipient_id, version="retained-v0")
        session.commit()
    return recipient_id, assignment_id, active, retired


def _erase_as_operator(factory, recipient_id: UUID, *, version: str = VERSION):  # type: ignore[no-untyped-def]
    with factory() as session:
        session.execute(text("SET LOCAL ROLE kp_operator"))
        result = erase_recipient_data_with_result(
            session, recipient_id, erased_at=datetime.now(UTC), pseudonym_key=KEY, pseudonym_key_version=version
        )
        session.commit()
        return result


def test_actual_operator_erases_multiple_rows_receipts_and_preview_without_outcome_read_access(factory) -> None:  # type: ignore[no-untyped-def]
    subject, assignment, active, retired = _seed(factory)
    bystander, other_assignment, other_active, _ = _seed(factory)
    preview_id = uuid4()
    with factory() as session:
        session.add(
            Microsoft365IntegrationState(
                integration_state_id=preview_id,
                kind="directory",
                provider="mailpit",
                scope_hash=uuid4().hex + uuid4().hex,
                config_fingerprint=uuid4().hex + uuid4().hex,
                status="preview_ready",
                pending_preview_id=uuid4(),
                pending_preview_hash=uuid4().hex + uuid4().hex,
                pending_payload='{"synthetic":true}',
                pending_created_at=datetime.now(UTC),
                pending_expires_at=datetime.now(UTC) + timedelta(hours=1),
                last_counts={},
            )
        )
        session.commit()

    result = _erase_as_operator(factory, subject)

    assert result.tombstoned_now and not result.already_tombstoned and result.ledger_rows_purged == 2
    with factory() as session:
        assert all(session.get(AwarenessLedgerEntry, identity) is None for identity in active)
        assert session.get(AwarenessLedgerEntry, retired) is not None
        assert all(session.get(AwarenessLedgerEntry, identity) is not None for identity in other_active)
        assert session.get(RecipientAssignment, assignment) is None
        assert session.get(RecipientAssignment, other_assignment) is not None
        for model in (ReportedMailReceipt, ReplyMailReceipt):
            assert (
                session.scalar(
                    select(func.count()).select_from(model).where(model.recipient_assignment_id == assignment)
                )
                == 0
            )
            assert (
                session.scalar(
                    select(func.count()).select_from(model).where(model.recipient_assignment_id == other_assignment)
                )
                == 1
            )
        assert session.get(Recipient, bystander).deleted_at is None
        assert session.get(Microsoft365IntegrationState, preview_id).pending_payload is None
    for query in (
        "SELECT observed_click FROM awareness_ledger_entries",
        "SELECT external_id FROM reply_mail_receipts",
        "SELECT external_id FROM reported_mail_receipts",
    ):
        with factory() as session:
            session.execute(text("SET LOCAL ROLE kp_operator"))
            with pytest.raises(DBAPIError) as error:
                session.execute(text(query))
            assert getattr(error.value.orig, "sqlstate", None) == "42501"
            session.rollback()


def test_historical_tombstone_remediation_is_scoped_by_version_and_preserves_marker(factory) -> None:  # type: ignore[no-untyped-def]
    subject, _, active, retired = _seed(factory, tombstoned=True)
    with factory() as session:
        recipient = session.get(Recipient, subject)
        original = (recipient.mailbox, recipient.mailbox_sha256, recipient.deleted_at)

    miss = _erase_as_operator(factory, subject, version="wrong-version")
    assert miss.already_tombstoned and not miss.tombstoned_now and miss.ledger_rows_purged == 0
    repaired = _erase_as_operator(factory, subject)
    assert repaired.already_tombstoned and repaired.ledger_rows_purged == 2
    retained = _erase_as_operator(factory, subject, version="retained-v0")
    assert retained.already_tombstoned and retained.ledger_rows_purged == 1
    assert _erase_as_operator(factory, subject).ledger_rows_purged == 0
    with factory() as session:
        recipient = session.get(Recipient, subject)
        assert (recipient.mailbox, recipient.mailbox_sha256, recipient.deleted_at) == original
        assert all(session.get(AwarenessLedgerEntry, identity) is None for identity in [*active, retired])


def test_erasure_waits_for_assignment_projector_then_purges_its_committed_ledger(factory) -> None:  # type: ignore[no-untyped-def]
    from kp_database.awareness_ledger import project_awareness_ledger_batch, recipient_pseudonym

    subject, assignment, _, _ = _seed(factory)
    entered = threading.Event()
    backend: list[int] = []
    outcomes: list[object] = []
    with factory() as projector:
        projector.execute(
            select(RecipientAssignment)
            .where(RecipientAssignment.recipient_assignment_id == assignment)
            .with_for_update()
        ).scalar_one()

        def erase():  # type: ignore[no-untyped-def]
            try:
                with factory() as eraser:
                    eraser.execute(text("SET LOCAL ROLE kp_operator"))
                    eraser.execute(text("SET LOCAL statement_timeout = '8s'"))
                    backend.append(eraser.scalar(text("SELECT pg_backend_pid()")))
                    entered.set()
                    result = erase_recipient_data_with_result(
                        eraser,
                        subject,
                        erased_at=datetime.now(UTC),
                        pseudonym_key=KEY,
                        pseudonym_key_version=VERSION,
                    )
                    eraser.commit()
                    outcomes.append(result)
            except Exception as error:
                outcomes.append(error)

        thread = threading.Thread(target=erase)
        thread.start()
        try:
            assert entered.wait(2)
            deadline = time.monotonic() + 3
            with factory() as monitor:
                while time.monotonic() < deadline:
                    waiting = monitor.scalar(
                        text("SELECT wait_event_type = 'Lock' FROM pg_stat_activity WHERE pid = :pid"),
                        {"pid": backend[0]},
                    )
                    # End the monitoring transaction to avoid cached activity
                    # snapshots; the worker must actually reach a row lock.
                    monitor.rollback()
                    if waiting:
                        break
                    threading.Event().wait(0.01)
                assert waiting, "erasure did not reach the held assignment lock"
            projection = project_awareness_ledger_batch(
                projector,
                tenant_scope=SINGLE_TENANT_DATABASE_SCOPE,
                pseudonym_key=KEY,
                pseudonym_key_version=VERSION,
                assignment_ids=[assignment],
                projected_at=datetime.now(UTC),
            )
            assert projection.projected_entries == 1
            projector.commit()
        finally:
            projector.rollback()
            thread.join(9)
    assert not thread.is_alive()
    assert len(outcomes) == 1 and not isinstance(outcomes[0], Exception), outcomes
    with factory() as session:
        assert session.get(RecipientAssignment, assignment) is None
        assert (
            session.scalar(
                select(func.count())
                .select_from(AwarenessLedgerEntry)
                .where(
                    AwarenessLedgerEntry.recipient_pseudonym
                    == recipient_pseudonym(tenant_scope=SINGLE_TENANT_DATABASE_SCOPE, recipient_id=subject, key=KEY),
                    AwarenessLedgerEntry.pseudonym_key_version == VERSION,
                )
            )
            == 0
        )


def test_hold_blocks_historical_tombstone_cleanup_with_actual_operator_privileges(factory) -> None:  # type: ignore[no-untyped-def]
    subject, _, active, _ = _seed(factory, tombstoned=True)
    hold_id = uuid4()
    with factory() as session:
        create_retention_hold(
            session,
            hold_id=hold_id,
            reference="qualification",
            reason="Preserve synthetic case",
            actor="test",
            now=datetime.now(UTC),
        )
        session.commit()
    try:
        with pytest.raises(RetentionHoldActive):
            _erase_as_operator(factory, subject)
        with factory() as session:
            assert all(session.get(AwarenessLedgerEntry, identity) is not None for identity in active)
    finally:
        with factory() as session:
            release_retention_hold(
                session, hold_id=hold_id, reason="Synthetic proof complete", actor="test", now=datetime.now(UTC)
            )
            session.commit()


@pytest.mark.parametrize(("key", "version"), ((b"short", VERSION), (KEY, "invalid version")))
def test_direct_erasure_rejects_invalid_key_before_mutation(factory, key: bytes, version: str) -> None:  # type: ignore[no-untyped-def]
    subject, assignment, active, _ = _seed(factory)
    with factory() as session:
        session.execute(text("SET LOCAL ROLE kp_operator"))
        with pytest.raises(ValueError):
            erase_recipient_data_with_result(
                session, subject, erased_at=datetime.now(UTC), pseudonym_key=key, pseudonym_key_version=version
            )
        session.rollback()
    with factory() as session:
        assert session.get(Recipient, subject).deleted_at is None
        assert session.get(RecipientAssignment, assignment) is not None
        assert all(session.get(AwarenessLedgerEntry, identity) is not None for identity in active)
