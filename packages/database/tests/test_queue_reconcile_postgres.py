"""Managed queue recovery with real NOINHERIT worker logins.

Creates and preserves a uniquely named qualification database. Never clears the
selected source database. Local runs must explicitly select a task test source.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from uuid import uuid4

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from kp_contracts.queue import MAX_QUEUE_RECONCILE_WINDOW_HOURS, QUEUE_PUBLISH_DEDUP_TTL_SECONDS
from kp_database import grants
from kp_database.audit_store import AuditStore
from psycopg import sql
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

pytestmark = pytest.mark.postgres
ROOT = Path(__file__).resolve().parents[3]
SIGNATURE = "public." + grants.QUEUE_RECONCILE_FUNCTION


@pytest.fixture(scope="module")
def managed_database():
    source = make_url(os.environ.get("DATABASE_URL_TEST", "sqlite://"))
    if os.environ.get("KP_TEST_PROFILE") != "postgres":
        pytest.fail("queue qualification requires explicit PostgreSQL profile")
    if source.database != "kingphisher_test" and not (source.database or "").startswith("kp_reconcile_qualification_"):
        pytest.fail("queue qualification refuses a non-test source database")
    name = f"kp_reconcile_qualification_{uuid4().hex}"
    admin = create_engine(source.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.connection.driver_connection.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    admin.dispose()
    url = source.set(database=name)
    spec = importlib.util.spec_from_file_location("queue_qualification_bootstrap", ROOT / "scripts/azure_migrate.py")
    assert spec and spec.loader
    script = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(script)
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("DATABASE_URL", url.render_as_string(hide_password=False))
        patch.setenv("KP_DISABLE_DOTENV", "1")
        patch.setenv("KP_ALEMBIC_INI", str(ROOT / "packages/database/alembic.ini"))
        patch.setenv("AUDIT_ROOT_KEY", "0" * 64)
        audit_url = os.environ.get("AUDIT_DATABASE_URL_TEST")
        audit_password = make_url(audit_url).password if audit_url else "audit_writer"
        patch.setenv("AUDIT_WRITER_PASSWORD", audit_password)
        for workload in grants.RUNTIME_ROLES:
            patch.setenv(script._password_env(workload), f"effect-{workload}")
        script.main()
        engine = create_engine(url)
        with engine.begin() as connection:
            for topic in grants.QUEUE_RECONCILE_TOPICS.values():
                for i in range(3):
                    connection.execute(
                        text(
                            "INSERT INTO public.transactional_outbox "
                            "(outbox_id,kind,topic,payload,idempotency_key,status,dispatched_at) "
                            "VALUES (:id,'queue',:topic,CAST(:payload AS jsonb),:key,'dispatched',now())"
                        ),
                        {
                            "id": uuid4(),
                            "topic": topic,
                            "payload": '{"synthetic":true}',
                            "key": f"qualification:{topic}:{i}",
                        },
                    )
            connection.execute(
                text(
                    "INSERT INTO public.transactional_outbox "
                    "(outbox_id,kind,topic,payload,idempotency_key,status,dispatched_at) "
                    "VALUES (:id,'queue','mailbox','{}',:key,'dispatched',now()-interval '90 days')"
                ),
                {"id": uuid4(), "key": "qualification:expired"},
            )
        yield url, engine, script, audit_password
        engine.dispose()


def _login(url, workload):
    return create_engine(url.set(username=grants.RUNTIME_ROLES[workload], password=f"effect-{workload}"))


def _denied(connection, statement, parameters=None, *, state="42501"):
    with pytest.raises(DBAPIError) as caught:
        connection.execute(text(statement), parameters or {})
    assert caught.value.orig.sqlstate == state
    connection.rollback()


def test_each_real_worker_login_reads_only_its_authorized_topic(managed_database):
    url, _, _, _ = managed_database
    for workload, topic in grants.QUEUE_RECONCILE_TOPICS.items():
        engine = _login(url, workload)
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT session_user")) == grants.RUNTIME_ROLES[workload]
            assert not connection.scalar(text("SELECT rolinherit FROM pg_roles WHERE rolname=session_user"))
            rows = (
                connection.execute(
                    text("SELECT * FROM public.kp_reconcile_queue_outbox(:topic,86400,2)"), {"topic": topic}
                )
                .mappings()
                .all()
            )
            assert len(rows) == 2 and {row["topic"] for row in rows} == {topic}
            _denied(connection, "SELECT payload FROM public.transactional_outbox")
            for forbidden in ("unknown", None, "deliver" if topic != "deliver" else "mailbox"):
                _denied(
                    connection, "SELECT * FROM public.kp_reconcile_queue_outbox(:topic,86400,2)", {"topic": forbidden}
                )
            for window, limit in [(0, 1), (7689601, 1), (None, 1), (1, 0), (1, 5001), (1, None)]:
                _denied(
                    connection,
                    "SELECT * FROM public.kp_reconcile_queue_outbox(:topic,:window,:limit)",
                    {"topic": topic, "window": window, "limit": limit},
                    state="22023",
                )
        engine.dispose()


def test_unrelated_logins_and_shared_dispatcher_cannot_read_queue_payloads(managed_database):
    url, _, _, audit_password = managed_database
    engines = [_login(url, workload) for workload in ("operator", "tracking", "audit-anchor")]
    engines.append(create_engine(url.set(username="audit_writer", password=audit_password)))
    for engine in engines:
        with engine.connect() as connection:
            _denied(connection, "SELECT * FROM public.kp_reconcile_queue_outbox('mailbox',86400,2)")
        engine.dispose()


def test_function_has_fixed_owner_search_path_and_no_public_execute(managed_database):
    _, engine, _, _ = managed_database
    with engine.connect() as connection:
        row = (
            connection.execute(
                text(
                    "SELECT pg_get_userbyid(proowner) AS owner, prosecdef, proconfig, "
                    "pg_get_functiondef(oid) AS definition FROM pg_proc WHERE oid=CAST(:signature AS regprocedure)"
                ),
                {"signature": SIGNATURE},
            )
            .mappings()
            .one()
        )
        assert row["owner"] == "audit_owner" and row["prosecdef"]
        assert row["proconfig"] == ["search_path=pg_catalog"]
        assert "7689600" in row["definition"]
        assert MAX_QUEUE_RECONCILE_WINDOW_HOURS * 3600 == 7689600 < QUEUE_PUBLISH_DEDUP_TTL_SECONDS
        for workload, topic in grants.QUEUE_RECONCILE_TOPICS.items():
            assert f"WHEN '{grants.RUNTIME_ROLES[workload]}'" in row["definition"]
            assert f"THEN '{topic}'" in row["definition"]
        assert not connection.scalar(
            text(
                "SELECT EXISTS (SELECT 1 FROM pg_proc p, aclexplode(p.proacl) a "
                "WHERE p.oid=CAST(:signature AS regprocedure) AND a.grantee=0 AND a.privilege_type='EXECUTE')"
            ),
            {"signature": SIGNATURE},
        )


def test_mailbox_can_lock_without_updating_delivery_state(managed_database):
    url, _, _, _ = managed_database
    engine = _login(url, "mailbox")
    with engine.connect() as connection:
        connection.execute(text("SELECT recipient_assignment_id FROM public.recipient_assignments FOR UPDATE"))
        connection.rollback()
        assert connection.scalar(
            text("SELECT has_column_privilege('public.recipient_assignments','recipient_assignment_id','UPDATE')")
        )
        assert not connection.scalar(text("SELECT has_table_privilege('public.recipient_assignments','UPDATE')"))
        _denied(connection, "UPDATE public.recipient_assignments SET send_state=send_state WHERE false")
    engine.dispose()


def test_audit_store_reconciliation_uses_worker_login_not_dispatcher(managed_database):
    url, _, _, audit_password = managed_database
    audit = create_engine(url.set(username="audit_writer", password=audit_password))
    worker = _login(url, "mailbox")
    store = AuditStore(audit, intent_engine=worker)
    rows = store._dispatcher._claim_reconcilable_dispatched(topic="mailbox", window_seconds=86400, limit=500)
    assert len(rows) == 3 and {row["topic"] for row in rows} == {"mailbox"}
    assert store._dispatcher._engine is audit
    worker.dispose()
    audit.dispose()


def test_bootstrap_regrants_function_to_optional_role_enabled_after_upgrade(managed_database):
    _, engine, script, _ = managed_database
    with engine.begin() as connection:
        connection.execute(text(f"REVOKE EXECUTE ON FUNCTION {SIGNATURE} FROM kp_worker_curation"))
    script.main()
    with engine.connect() as connection:
        assert connection.scalar(
            text("SELECT has_function_privilege('kp_worker_curation',:signature,'EXECUTE')"), {"signature": SIGNATURE}
        )


def test_migration_works_for_nonsuperuser_noinherit_migrator(managed_database):
    url, _, _, _ = managed_database
    suffix = uuid4().hex
    role = f"kp_reconcile_migrator_{suffix}"
    name = f"kp_reconcile_qualification_{suffix}"
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
    spec = importlib.util.spec_from_file_location(
        "queue_migration_effect", ROOT / "packages/database/alembic/versions/0054_queue_reconcile_roles.py"
    )
    assert spec and spec.loader
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    with migrator.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE public.transactional_outbox (outbox_id uuid, kind text, topic text, "
                "payload jsonb, idempotency_key text, status text, available_at timestamptz, "
                "dispatched_at timestamptz)"
            )
        )
        connection.execute(text("GRANT USAGE, CREATE ON SCHEMA public TO audit_owner"))
        connection.execute(text("ALTER TABLE public.transactional_outbox OWNER TO audit_owner"))
        connection.execute(text("REVOKE CREATE ON SCHEMA public FROM audit_owner"))
        for table, columns in {
            "recipient_assignments": "recipient_assignment_id uuid",
            "awareness_ledger_entries": "tenant_scope text, recipient_pseudonym text, pseudonym_key_version text",
            "reported_mail_receipts": "recipient_assignment_id uuid",
            "reply_mail_receipts": "recipient_assignment_id uuid",
            "microsoft365_integration_states": (
                "pending_preview_id uuid, pending_preview_hash text, pending_payload text, "
                "pending_created_at timestamptz, "
                "pending_expires_at timestamptz, status text, last_error text, updated_at timestamptz"
            ),
        }.items():
            connection.execute(text(f"CREATE TABLE public.{table} ({columns})"))
        with Operations.context(MigrationContext.configure(connection)):
            migration.upgrade()
        assert connection.scalar(text("SELECT current_user")) == role
    worker = _login(url.set(database=name), "mailbox")
    with worker.connect() as connection:
        assert connection.execute(text("SELECT * FROM public.kp_reconcile_queue_outbox('mailbox',86400,2)")).all() == []
    worker.dispose()
    migrator.dispose()


def test_real_worker_cursor_recovers_older_rows_while_new_publications_arrive(managed_database):
    url, admin, _, audit_password = managed_database
    audit = create_engine(url.set(username="audit_writer", password=audit_password))
    worker = _login(url, "mailbox")
    store = AuditStore(audit, intent_engine=worker)

    class Queue:
        def __init__(self):
            self.present = set()
            self.published = []

        def job_published(self, topic, key):
            return key in self.present

        def publish(self, topic, payload, *, idempotency_key, available_at=None):
            self.present.add(idempotency_key)
            self.published.append(idempotency_key)

    queue = Queue()
    try:
        first = store.reconcile_queue_after_restore(
            queue, topic="mailbox", replay_safe=True, window_seconds=86400, limit=2
        )
        assert first["checked"] == first["replayed"] == 2
        with admin.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO public.transactional_outbox "
                    "(outbox_id,kind,topic,payload,idempotency_key,status,dispatched_at) "
                    "VALUES (:id,'queue','mailbox','{}','qualification:concurrent-new','dispatched',now())"
                ),
                {"id": uuid4()},
            )
        second = store.reconcile_queue_after_restore(
            queue, topic="mailbox", replay_safe=True, window_seconds=86400, limit=2
        )
        assert second["checked"] == second["replayed"] == 1
        assert queue.present == {f"qualification:mailbox:{i}" for i in range(3)}
        third = store.reconcile_queue_after_restore(
            queue, topic="mailbox", replay_safe=True, window_seconds=86400, limit=2
        )
        assert third["checked"] == 2 and third["replayed"] == 1
        assert queue.present == {f"qualification:mailbox:{i}" for i in range(3)} | {"qualification:concurrent-new"}
        assert len(queue.published) == 4
        with worker.connect() as connection:
            _denied(
                connection,
                "SELECT * FROM public.kp_reconcile_queue_outbox('mailbox',86400,2,NULL,:id)",
                {"id": uuid4()},
                state="22023",
            )
    finally:
        worker.dispose()
        audit.dispose()
