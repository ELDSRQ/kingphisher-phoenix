"""Real PostgreSQL hold serialization on a task-owned qualification database.

Uses a new database on the explicit test server. The normal development/test
schema is never cleared; the test preserves schema, hold history and evidence.
"""

from __future__ import annotations

import os
import threading
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from kp_database.awareness_ledger import recipient_pseudonym
from kp_database.models import (
    AwarenessLedgerEntry,
    CipherText,
    Microsoft365IntegrationState,
    Recipient,
    RetentionAction,
    TrackingEvent,
)
from kp_database.privacy import erase_recipient_data
from kp_database.retention_holds import (
    RetentionHoldActive,
    active_retention_hold,
    create_retention_hold,
    release_retention_hold,
    require_no_retention_hold,
)
from kp_database.session import create_db_engine, make_session_factory
from kp_domain_models import models as dm
from kp_workers.retention_jobs import process_retention
from psycopg import sql
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

pytestmark = pytest.mark.postgres
KEY = b"q" * 32
VERSION = "hold-qualification-v1"


@pytest.fixture(scope="module")
def factory():  # type: ignore[no-untyped-def]
    url = os.environ.get("DATABASE_URL_TEST", "")
    if os.environ.get("KP_TEST_PROFILE") != "postgres" or not url:
        pytest.fail("retention-hold qualification requires the explicit PostgreSQL profile")
    source = make_url(url)
    if not (source.database or "").startswith("kp_hold_qualification_") and source.database != "kingphisher_test":
        pytest.fail("retention-hold qualification refuses the selected non-test database")
    # The standard CI integration database may be rebuilt by sibling tests.
    # Give this proof its own fresh database, preserving it until the
    # disposable CI host ends; never clear the shared integration schema.
    name = f"kp_hold_qualification_{uuid4().hex}"
    admin = create_engine(source.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        raw = connection.connection.driver_connection
        raw.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
        for role in ["audit_writer", "kp_operator", "kp_worker_retention"]:
            if not raw.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone():
                raw.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(role)))
    admin.dispose()
    url = source.set(database=name).render_as_string(hide_password=False)
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("DATABASE_URL", url)
        command.upgrade(Config(str(Path(__file__).resolve().parents[1] / "alembic.ini")), "head")
    prior_keys = (CipherText._active_key_id, CipherText._active_key, CipherText._prior_keys)
    CipherText.configure_key(bytes.fromhex("17" * 32))
    engine = create_db_engine(url)
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0060_delivery_authority_locks"
    yield make_session_factory(engine)
    engine.dispose()
    CipherText._active_key_id, CipherText._active_key, CipherText._prior_keys = prior_keys


def test_committed_hold_blocks_a_purger_that_waited_for_its_transaction(factory) -> None:  # type: ignore[no-untyped-def]
    entered = threading.Event()
    outcome = []
    with factory() as setter:
        hold, _ = create_retention_hold(
            setter,
            hold_id=uuid4(),
            reference="concurrency-set",
            reason="Serialize before purge",
            actor="qualification",
            now=datetime.now(UTC),
        )
        hold_id = hold.retention_hold_id

        def purge():  # type: ignore[no-untyped-def]
            with factory() as purger:
                purger.execute(text("SET LOCAL statement_timeout = '5s'"))
                entered.set()
                try:
                    require_no_retention_hold(purger)
                    outcome.append("incorrectly_permitted")
                except RetentionHoldActive:
                    outcome.append("held")

        thread = threading.Thread(target=purge)
        thread.start()
        assert entered.wait(2)
        assert not threading.Event().wait(0.05)
        assert outcome == []
        setter.commit()
        thread.join(5)
        assert not thread.is_alive() and outcome == ["held"]
    with factory() as session:
        release_retention_hold(
            session, hold_id=hold_id, reason="Concurrency proof recorded", actor="qualification", now=datetime.now(UTC)
        )
        session.commit()


def test_hold_set_waits_for_an_existing_purge_transaction_to_finish(factory) -> None:  # type: ignore[no-untyped-def]
    entered, finished = threading.Event(), threading.Event()
    hold_id = uuid4()
    with factory() as purger:
        require_no_retention_hold(purger)

        def setter():  # type: ignore[no-untyped-def]
            with factory() as session:
                session.execute(text("SET LOCAL statement_timeout = '5s'"))
                entered.set()
                create_retention_hold(
                    session,
                    hold_id=hold_id,
                    reference="concurrency-purge",
                    reason="Wait for prior purge",
                    actor="qualification",
                    now=datetime.now(UTC),
                )
                session.commit()
                finished.set()

        thread = threading.Thread(target=setter)
        thread.start()
        assert entered.wait(2)
        assert not finished.wait(0.05)
        purger.commit()
        thread.join(5)
        assert not thread.is_alive() and finished.is_set()
    with factory() as session:
        assert active_retention_hold(session) == hold_id
        release_retention_hold(
            session, hold_id=hold_id, reason="Concurrency proof recorded", actor="qualification", now=datetime.now(UTC)
        )
        session.commit()


def test_hold_preserves_raw_and_expired_ledger_data_then_erasure_resumes(factory) -> None:  # type: ignore[no-untyped-def]
    now = datetime.now(UTC)
    recipient_id, event_id, entry_id, hold_id = uuid4(), uuid4(), uuid4(), uuid4()
    with factory() as session:
        session.add(
            Recipient(
                recipient_id=recipient_id,
                employee_key=f"hold-{recipient_id}",
                mailbox=f"hold-{recipient_id}@example.com",
                mailbox_sha256=uuid4().hex * 2,
                display_name="Synthetic hold subject",
                status=dm.RecipientStatus.ACTIVE,
            )
        )
        session.add(
            TrackingEvent(
                event_id=event_id,
                recipient_id=recipient_id,
                event_type=dm.EventType.OPENED,
                confidence=dm.Confidence.LOW,
                occurred_at=now - timedelta(days=400),
                payload={},
            )
        )
        campaign_date = date.today() - timedelta(days=2000)
        session.add(
            AwarenessLedgerEntry(
                awareness_ledger_entry_id=entry_id,
                tenant_scope="single_tenant_database",
                pseudonym_key_version=VERSION,
                recipient_pseudonym=recipient_pseudonym(
                    tenant_scope="single_tenant_database", recipient_id=recipient_id, key=KEY
                ),
                assignment_exposure_pseudonym=uuid4().hex * 2,
                campaign_id=uuid4(),
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
                projected_at=now,
                retain_until=campaign_date + timedelta(days=1826),
            )
        )
        create_retention_hold(
            session,
            hold_id=hold_id,
            reference="preservation-effect",
            reason="Preserve raw and pseudonymous evidence",
            actor="qualification",
            now=now,
        )
        session.commit()
    audit = []
    context = SimpleNamespace(
        session_factory=factory,
        settings=SimpleNamespace(queued_stale_hours=24, require_awareness_pseudonym_config=lambda: (KEY, VERSION)),
        audit_store=SimpleNamespace(record=lambda **values: audit.append(values)),
    )
    key = f"held-retention-{uuid4()}"
    process_retention(context, {"payload": {}, "idempotency_key": key})
    with factory() as session:
        assert session.get(TrackingEvent, event_id) is not None
        assert session.get(AwarenessLedgerEntry, entry_id) is not None
        assert (
            session.scalar(select(RetentionAction.row_count_deleted).where(RetentionAction.idempotency_key == key)) == 0
        )
        with pytest.raises(RetentionHoldActive):
            erase_recipient_data(session, recipient_id, erased_at=now, pseudonym_key=KEY, pseudonym_key_version=VERSION)
        assert session.get(Recipient, recipient_id).deleted_at is None
        session.rollback()
        release_retention_hold(
            session, hold_id=hold_id, reason="Preservation proof recorded", actor="qualification", now=datetime.now(UTC)
        )
        session.commit()
        assert erase_recipient_data(
            session, recipient_id, erased_at=datetime.now(UTC), pseudonym_key=KEY, pseudonym_key_version=VERSION
        )
        session.commit()
        assert session.get(TrackingEvent, event_id) is None
        assert session.get(AwarenessLedgerEntry, entry_id) is None
        assert session.get(Recipient, recipient_id).deleted_at is not None
        assert (
            session.scalar(
                select(func.count()).select_from(RetentionAction).where(RetentionAction.idempotency_key == key)
            )
            == 1
        )
    assert audit[0]["action"] == "retention.held"


def test_migrated_runtime_roles_have_only_the_reviewed_hold_privileges(factory) -> None:  # type: ignore[no-untyped-def]
    with factory() as session:
        for privilege in ["SELECT", "INSERT", "UPDATE"]:
            assert session.scalar(
                text("SELECT has_table_privilege('kp_operator', 'retention_holds', :privilege)"),
                {"privilege": privilege},
            )
        for privilege in ["DELETE", "TRUNCATE"]:
            assert not session.scalar(
                text("SELECT has_table_privilege('kp_operator', 'retention_holds', :privilege)"),
                {"privilege": privilege},
            )
        for privilege in ["INSERT", "UPDATE", "DELETE", "TRUNCATE"]:
            assert not session.scalar(
                text("SELECT has_table_privilege('kp_worker_retention', 'retention_holds', :privilege)"),
                {"privilege": privilege},
            )
        session.execute(text("SET LOCAL ROLE kp_worker_retention"))
        assert active_retention_hold(session) is None


def test_database_guard_blocks_direct_purge_and_tombstoning_by_legacy_processes(factory) -> None:  # type: ignore[no-untyped-def]
    recipient_id, event_id, hold_id = uuid4(), uuid4(), uuid4()
    integration_id = uuid4()
    now = datetime.now(UTC)
    with factory() as session:
        session.add(
            Recipient(
                recipient_id=recipient_id,
                employee_key=f"direct-{recipient_id}",
                mailbox=f"direct-{recipient_id}@example.com",
                mailbox_sha256=uuid4().hex * 2,
                status=dm.RecipientStatus.ACTIVE,
            )
        )
        session.add(
            TrackingEvent(
                event_id=event_id,
                recipient_id=recipient_id,
                event_type=dm.EventType.OPENED,
                confidence=dm.Confidence.LOW,
                occurred_at=now,
                payload={},
            )
        )
        session.add(
            Microsoft365IntegrationState(
                integration_state_id=integration_id,
                kind="directory",
                provider="microsoft365",
                scope_hash=uuid4().hex * 2,
                config_fingerprint=uuid4().hex * 2,
                status="preview_ready",
                pending_preview_id=uuid4(),
                pending_preview_hash=uuid4().hex * 2,
                pending_payload='{"recipients": []}',
                pending_created_at=now,
                pending_expires_at=now + timedelta(hours=1),
            )
        )
        create_retention_hold(
            session,
            hold_id=hold_id,
            reference="legacy-process-guard",
            reason="Preserve across process versions",
            actor="qualification",
            now=now,
        )
        session.commit()
        for statement, values in [
            ("DELETE FROM events WHERE event_id = :identifier", {"identifier": event_id}),
            ("UPDATE recipients SET deleted_at = now() WHERE recipient_id = :identifier", {"identifier": recipient_id}),
            ("TRUNCATE events CASCADE", {}),
            (
                "UPDATE microsoft365_integration_states SET pending_payload = NULL "
                "WHERE integration_state_id = :identifier",
                {"identifier": integration_id},
            ),
            (
                "DELETE FROM microsoft365_integration_states WHERE integration_state_id = :identifier",
                {"identifier": integration_id},
            ),
        ]:
            with pytest.raises(DBAPIError) as error:
                session.execute(text(statement), values)
            assert getattr(error.value.orig, "sqlstate", None) == "55000"
            session.rollback()
        assert session.get(Recipient, recipient_id).deleted_at is None
        assert session.get(TrackingEvent, event_id) is not None
        assert session.get(Microsoft365IntegrationState, integration_id).pending_payload is not None
        release_retention_hold(
            session,
            hold_id=hold_id,
            reason="Legacy-process proof recorded",
            actor="qualification",
            now=datetime.now(UTC),
        )
        session.commit()
        session.execute(text("DELETE FROM events WHERE event_id = :identifier"), {"identifier": event_id})
        session.commit()
        assert session.get(TrackingEvent, event_id) is None
