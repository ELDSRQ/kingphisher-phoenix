"""Minimized privacy export through a real managed operator login.

Shares the preserved task-database bootstrap fixture with queue role proofs;
canonical runtime-role provisioning must run serially on a synthetic test host.
"""

from __future__ import annotations

import importlib.util
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from fastapi import Response
from kp_database.awareness_ledger import (
    MAX_LEDGER_RECIPIENT_HISTORY,
    privacy_ledger_recipient_history,
    recipient_pseudonym,
)
from kp_database.models import CipherText, PrivacyRequest, Recipient
from kp_database.privacy import hash_mailbox
from kp_database.reporting import SINGLE_TENANT_DATABASE_SCOPE as SCOPE
from kp_database.session import make_session_factory
from kp_domain_models import models as dm
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.routes.privacy import export_privacy_request
from psycopg import sql
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from test_privacy_erasure_role_effects import KEY, VERSION, _ledger, _seed
from test_queue_reconcile_postgres import managed_database as _managed_database

pytestmark = pytest.mark.postgres
SALT = b"h" * 32


@pytest.fixture(scope="module")
def managed_database():
    yield from _managed_database.__wrapped__()


@pytest.fixture
def subject(managed_database):
    url, admin, _, _ = managed_database
    previous = (CipherText._active_key_id, CipherText._active_key, CipherText._prior_keys)
    CipherText.configure_key(bytes.fromhex("17" * 32))
    factory = make_session_factory(admin)
    recipient_id, assignment_id, _, _ = _seed(factory)
    _seed(factory)  # unrelated subject must never appear in the export
    request_id = uuid4()
    now = datetime.now(UTC)
    with factory() as session:
        recipient = session.get(Recipient, recipient_id)
        recipient.mailbox_sha256 = hash_mailbox(recipient.mailbox, SALT)
        session.add(
            PrivacyRequest(
                privacy_request_id=request_id,
                request_type=dm.PrivacyRequestType.ACCESS_EXPORT,
                requester_key=recipient.mailbox,
                status="verified",
                verified_at=now,
                verification_method="qualification",
                verification_evidence_ref="synthetic-subject",
                opened_at=now,
                sla_deadline=now + timedelta(days=45),
            )
        )
        session.commit()
    worker = create_engine(url.set(username="kp_operator", password="effect-operator"))
    settings = OperatorApiSettings.model_construct(
        config_store="managed",
        recipient_hash_salt=SALT.hex(),
        awareness_pseudonym_key=KEY.hex(),
        awareness_pseudonym_key_version=VERSION,
    )
    yield request_id, recipient_id, assignment_id, factory, worker, settings
    worker.dispose()
    CipherText._active_key_id, CipherText._active_key, CipherText._prior_keys = previous


def test_managed_export_returns_only_subject_projection_and_minimized_receipts(subject):
    request_id, recipient_id, assignment_id, _, worker, settings = subject
    response = Response()
    with make_session_factory(worker)() as session:
        assert session.scalar(text("SELECT session_user")) == "kp_operator"
        payload = export_privacy_request(
            request_id,
            response,
            session=session,
            settings=settings,
            audit=SimpleNamespace(record=lambda **_kwargs: None),
            principal=SimpleNamespace(principal_id="privacy-qualification"),
        )
    assert [row["recipient_id"] for row in payload["records"]] == [str(recipient_id)]
    for name in ("reported_receipts", "reply_receipts"):
        assert len(payload[name]) == 1
        assert payload[name][0]["recipient_assignment_id"] == str(assignment_id)
        assert set(payload[name][0]) == {"recipient_assignment_id", "disposition", "received_at"}
    assert payload["awareness_ledger"]["available"] and len(payload["awareness_ledger"]["entries"]) == 2
    assert not payload["awareness_ledger"]["truncated"]
    assert "no-store" in response.headers["Cache-Control"]
    for query in (
        "SELECT observed_click FROM public.awareness_ledger_entries",
        "SELECT external_id FROM public.reply_mail_receipts",
        "SELECT evidence FROM public.reported_mail_receipts",
    ):
        with worker.connect() as connection:
            with pytest.raises(DBAPIError) as denied:
                connection.execute(text(query))
            assert denied.value.orig.sqlstate == "42501"


def test_governed_export_rejects_unverified_request_and_invalid_scope_or_bounds(subject):
    request_id, recipient_id, _, factory, worker, _ = subject
    pseudonym = recipient_pseudonym(tenant_scope=SCOPE, recipient_id=recipient_id, key=KEY)
    parameters = dict(
        request=request_id, recipient=recipient_id, scope=SCOPE, pseudonym=pseudonym, version=VERSION, limit=501
    )
    query = text(
        "SELECT * FROM public.kp_privacy_subject_ledger(:request,:recipient,:scope,:pseudonym,:version,:limit)"
    )
    for override in (
        {"scope": "other_tenant"},
        {"pseudonym": "malformed"},
        {"version": "invalid version"},
        {"limit": 502},
        {"limit": None},
        {"limit": 0},
    ):
        with worker.connect() as connection:
            with pytest.raises(DBAPIError) as denied:
                connection.execute(query, parameters | override)
            assert denied.value.orig.sqlstate == "22023"
    with factory() as session:
        session.get(PrivacyRequest, request_id).status = "opened"
        session.commit()
    with worker.connect() as connection:
        with pytest.raises(DBAPIError) as denied:
            connection.execute(query, parameters)
        assert denied.value.orig.sqlstate == "42501"


def test_export_is_capped_and_reports_truncation(subject):
    request_id, recipient_id, _, factory, worker, _ = subject
    with factory() as session:
        for _ in range(MAX_LEDGER_RECIPIENT_HISTORY):
            _ledger(session, recipient_id)
        session.commit()
    with make_session_factory(worker)() as session:
        history = privacy_ledger_recipient_history(
            session,
            privacy_request_id=request_id,
            recipient_id=recipient_id,
            tenant_scope=SCOPE,
            pseudonym_key=KEY,
            pseudonym_key_version=VERSION,
        )
    assert len(history.entries) == MAX_LEDGER_RECIPIENT_HISTORY and history.truncated


def test_only_operator_login_can_execute_export_function(subject, managed_database):
    _, _, _, _, _, _ = subject
    url, admin, _, audit_password = managed_database
    signature = "public.kp_privacy_subject_ledger(uuid,uuid,text,text,text,integer)"
    for role, password in (
        ("audit_writer", audit_password),
        ("kp_tracking", "effect-tracking"),
        ("kp_worker_retention", "effect-retention"),
    ):
        engine = create_engine(url.set(username=role, password=password))
        with engine.connect() as connection:
            assert not connection.scalar(
                text("SELECT has_function_privilege(:signature,'EXECUTE')"), {"signature": signature}
            )
        engine.dispose()
    with admin.connect() as connection:
        definition = connection.scalar(
            text("SELECT pg_get_functiondef(CAST(:signature AS regprocedure))"), {"signature": signature}
        )
        assert "SET search_path TO 'pg_catalog'" in definition
        with pytest.raises(DBAPIError) as denied:
            connection.execute(
                text("SELECT * FROM public.kp_privacy_subject_ledger(NULL,NULL,'single_tenant_database',NULL,NULL,1)")
            )
        assert denied.value.orig.sqlstate == "42501"  # superuser EXECUTE still fails invoker binding


@pytest.mark.parametrize("exception", (RuntimeError, ValueError))
def test_managed_key_failure_marks_ledger_unavailable_without_partial_disclosure(subject, monkeypatch, exception):
    request_id, _, _, _, worker, settings = subject

    def invalid(_settings):
        raise exception("synthetic invalid governed key")

    monkeypatch.setattr(OperatorApiSettings, "require_awareness_pseudonym_config", invalid)
    with make_session_factory(worker)() as session:
        payload = export_privacy_request(
            request_id,
            Response(),
            session=session,
            settings=settings,
            audit=SimpleNamespace(record=lambda **_kwargs: None),
            principal=SimpleNamespace(principal_id="privacy-qualification"),
        )
    assert not payload["awareness_ledger"]["available"]
    assert payload["awareness_ledger"]["entries"] == []
    assert payload["awareness_ledger"]["unavailable_reason"] == "ledger_pseudonym_key_unavailable"
    assert len(payload["reported_receipts"]) == len(payload["reply_receipts"]) == 1


def test_export_migration_under_noinherit_nonsuperuser_with_owner_owned_ledger(managed_database):
    url, _, _, _ = managed_database
    suffix = uuid4().hex
    role, name = f"kp_export_migrator_{suffix}", f"kp_export_qualification_{suffix}"
    admin = create_engine(url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        raw = connection.connection.driver_connection
        raw.execute(
            sql.SQL("CREATE ROLE {} LOGIN PASSWORD {} NOINHERIT NOSUPERUSER NOCREATEROLE NOCREATEDB").format(
                sql.Identifier(role), sql.Literal("synthetic-migration-only")
            )
        )
        raw.execute(sql.SQL("GRANT audit_owner TO {}").format(sql.Identifier(role)))
        raw.execute(sql.SQL("CREATE DATABASE {} OWNER {}").format(sql.Identifier(name), sql.Identifier(role)))
    admin.dispose()
    migrator = create_engine(url.set(database=name, username=role, password="synthetic-migration-only"))
    migration_path = Path(__file__).resolve().parents[1] / "alembic/versions/0055_privacy_subject_export.py"
    spec = importlib.util.spec_from_file_location("privacy_export_migration_effect", migration_path)
    assert spec and spec.loader
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    with migrator.begin() as connection:
        connection.execute(text("CREATE TABLE public.transactional_outbox (outbox_id uuid)"))
        connection.execute(
            text(
                "CREATE TABLE public.awareness_ledger_entries (awareness_ledger_entry_id uuid, "
                "tenant_scope text, recipient_pseudonym text, pseudonym_key_version text, "
                "campaign_id uuid, campaign_date date, campaign_date_basis text, delivered boolean, "
                "observed_open boolean, observed_click boolean, confirmed_interaction boolean, "
                "reported boolean, training_started boolean, training_completed boolean, "
                "no_activity_at_close boolean)"
            )
        )
        connection.execute(
            text("CREATE TABLE public.privacy_requests (privacy_request_id uuid,status text,verified_at timestamptz)")
        )
        connection.execute(text("CREATE TABLE public.recipients (recipient_id uuid)"))
        for table in ("reported_mail_receipts", "reply_mail_receipts"):
            connection.execute(text(f"CREATE TABLE public.{table} (disposition text, received_at timestamptz)"))
        connection.execute(text("GRANT USAGE, CREATE ON SCHEMA public TO audit_owner"))
        for table in ("transactional_outbox", "awareness_ledger_entries"):
            connection.execute(text(f"ALTER TABLE public.{table} OWNER TO audit_owner"))
        connection.execute(text("REVOKE CREATE ON SCHEMA public FROM audit_owner"))
        with Operations.context(MigrationContext.configure(connection)):
            migration.upgrade()
        assert connection.scalar(text("SELECT current_user")) == role
        assert (
            connection.scalar(
                text("SELECT pg_get_userbyid(proowner) FROM pg_proc WHERE oid=CAST(:signature AS regprocedure)"),
                {"signature": migration.SIGNATURE},
            )
            == "audit_owner"
        )
    migrator.dispose()
