"""Explicit development shared-owner compatibility in a fresh synthetic DB.

Never rotates an existing login. CI may reuse its supplied kingphisher source
credentials; qualification admins may create the absent legacy role once, or
must explicitly supply KP_TEST_LEGACY_OWNER_DATABASE_URL for an existing role.
The new database and any new role are preserved as qualification evidence.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
from _migrate_schema import ALEMBIC_INI, _database_url_env
from alembic import command
from alembic.config import Config
from kp_database.audit_store import AuditStore
from kp_database.grants import OUTBOX_CONFLICT_SELECT_COLUMNS, OUTBOX_INSERT_COLUMNS
from kp_database.models import Campaign, CampaignProgram, CampaignProgramOccurrence, CipherText
from kp_database.session import make_session_factory
from kp_domain_models import models as dm
from kp_workers.program_jobs import maybe_materialize_due_program_iterations
from psycopg import sql
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url
from test_adaptive_program_iterations import _adaptive_source, _recipient

pytestmark = pytest.mark.postgres


def test_explicit_development_shared_owner_tick_uses_direct_draft_path():
    if os.environ.get("KP_TEST_PROFILE") != "postgres":
        pytest.skip("requires explicit isolated PostgreSQL profile")
    source = make_url(os.environ["DATABASE_URL_TEST"])
    if source.database != "kingphisher_test" and not (source.database or "").startswith("kp_reconcile_qualification_"):
        pytest.fail("development qualification refuses a non-test source database")
    admin = create_engine(source.set(database="postgres"), isolation_level="AUTOCOMMIT")
    legacy = source if source.username == "kingphisher" else None
    name = "kp_adaptive_development_" + uuid4().hex
    with admin.connect() as connection:
        if legacy is None:
            exists = connection.scalar(text("SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='kingphisher')"))
            if not exists:
                password = "QualificationLegacyOwnerOnly20261106"
                connection.connection.driver_connection.execute(
                    sql.SQL("CREATE ROLE kingphisher LOGIN PASSWORD {} NOSUPERUSER NOCREATEROLE NOCREATEDB").format(
                        sql.Literal(password)
                    )
                )
                legacy = source.set(username="kingphisher", password=password)
            else:
                override = os.environ.get("KP_TEST_LEGACY_OWNER_DATABASE_URL")
                if not override:
                    pytest.fail(
                        "existing legacy role requires explicit KP_TEST_LEGACY_OWNER_DATABASE_URL; never rotate it"
                    )
                legacy = make_url(override)
                assert legacy.username == "kingphisher"
                assert (legacy.host, legacy.port) == (source.host, source.port)
        connection.connection.driver_connection.execute(
            sql.SQL("CREATE DATABASE {} OWNER kingphisher").format(sql.Identifier(name))
        )
    admin.dispose()
    admin_url, legacy_url = source.set(database=name), legacy.set(database=name)
    config = Config(str(ALEMBIC_INI))
    with _database_url_env(admin_url.render_as_string(hide_password=False)):
        command.upgrade(config, "head")
    admin = create_engine(admin_url)
    with admin.begin() as connection:
        # The legacy principal owns the fresh business tables, while the
        # audit_owner evidence tables retain their migrated owner and boundary.
        tables = connection.scalars(
            text("SELECT tablename FROM pg_tables WHERE schemaname='public' AND tableowner=current_user")
        )
        for table in tuple(tables):
            connection.connection.driver_connection.execute(
                sql.SQL("ALTER TABLE public.{} OWNER TO kingphisher").format(sql.Identifier(table))
            )
        for privilege, columns in (("INSERT", OUTBOX_INSERT_COLUMNS), ("SELECT", OUTBOX_CONFLICT_SELECT_COLUMNS)):
            connection.connection.driver_connection.execute(
                sql.SQL("GRANT {} ({}) ON public.transactional_outbox TO kingphisher").format(
                    sql.SQL(privilege), sql.SQL(",").join(map(sql.Identifier, columns))
                )
            )
    engine = create_engine(legacy_url)
    previous = (CipherText._active_key_id, CipherText._active_key, CipherText._prior_keys)
    CipherText.configure_key(b"p" * 32)
    factory = make_session_factory(engine)
    try:
        with factory() as session:
            assert session.scalar(text("SELECT session_user")) == "kingphisher"
            program_id = _adaptive_source(session, [_recipient(f"legacy-{uuid4().hex}@example.test")])
            program = session.get(CampaignProgram, program_id)
            source_campaign = session.get(Campaign, program.source_campaign_id)
            source_campaign.state = dm.CampaignState.COMPLETED
            author = program.created_by
            session.commit()
        ctx = SimpleNamespace(
            settings=SimpleNamespace(
                runtime_mode="development", database_url=legacy_url.render_as_string(hide_password=False)
            ),
            session_factory=factory,
            audit_store=AuditStore(admin, intent_engine=engine),
        )
        assert maybe_materialize_due_program_iterations(ctx, datetime.now(UTC)) == {
            "created": 1,
            "skipped": 0,
            "errored": 0,
        }
        with factory() as session:
            occurrence = session.scalars(
                select(CampaignProgramOccurrence).where(
                    CampaignProgramOccurrence.campaign_program_id == program_id,
                    CampaignProgramOccurrence.occurrence_number == 2,
                )
            ).one()
            draft = session.get(Campaign, occurrence.campaign_id)
            assert draft.state == dm.CampaignState.DRAFT and draft.delivery_mode == "reviewed_direct"
            assert draft.created_by == author and draft.roe_id is None and draft.manifest_signed_at is None
        assert maybe_materialize_due_program_iterations(ctx, datetime.now(UTC))["created"] == 0
    finally:
        engine.dispose()
        admin.dispose()
        CipherText._active_key_id, CipherText._active_key, CipherText._prior_keys = previous
