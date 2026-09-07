"""Live PostgreSQL proof for post-commit audit and queue dispatch."""

from __future__ import annotations

import os
import secrets
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from kp_database.audit_store import AuditStore
from kp_database.outbox import dispatch_after_commit, enqueue_queue
from kp_database.session import create_db_engine
from psycopg import sql
from sqlalchemy import text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.orm import Session

pytestmark = pytest.mark.postgres


TEST_URL = os.environ.get(
    "DATABASE_URL_TEST",
    "postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher_test",
)
DATABASE_ROOT = Path(__file__).resolve().parents[1]

#: Privileges the audit connection needs in the isolated database. Deliberately
#: no privilege at all on ``transactional_outbox``: the claim/complete path must
#: work through the SECURITY DEFINER functions or not at all.
_AUDIT_ROLE_GRANTS = (
    "GRANT USAGE ON SCHEMA public TO {}",
    "GRANT SELECT ON TABLE audit_events, audit_chain_head TO {}",
    "GRANT EXECUTE ON FUNCTION kp_dispatch_audit_outbox(uuid), "
    "kp_dispatch_pending_audit(integer), kp_claim_queue_outbox(integer), "
    "kp_complete_outbox(uuid), kp_fail_outbox(uuid,text), kp_outbox_health(), "
    "kp_verify_audit_head() TO {}",
)


def _eligible_database() -> bool:
    if os.environ.get("KP_TEST_PROFILE") != "postgres":
        return False
    engine = create_db_engine(TEST_URL)
    try:
        with engine.connect() as connection:
            return bool(
                connection.scalar(
                    text(
                        "SELECT rolsuper OR (rolcreatedb AND rolcreaterole) FROM pg_roles WHERE rolname = current_user"
                    )
                )
            )
    except Exception:
        return False
    finally:
        engine.dispose()


requires_outbox_database = pytest.mark.skipif(
    not _eligible_database(),
    reason="local Postgres with isolated-database and role-creation rights is not reachable",
)


@contextmanager
def _isolated_migrated_database(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[URL, URL]]:
    source_url = make_url(TEST_URL)
    server_engine = create_db_engine(source_url.set(database="postgres").render_as_string(hide_password=False))
    suffix = uuid.uuid4().hex
    database_name = f"kp_outbox_{suffix}"
    # The audit engine must be a SEPARATE, non-owning, least-privilege login
    # role — but it is provisioned per run rather than reusing the cluster's
    # ``audit_writer``. PostgreSQL roles are CLUSTER-WIDE, and this gate runs
    # scripts/azure_migrate.py (packages/database/tests/test_grant_matrix_effect.py),
    # which issues ``ALTER ROLE audit_writer LOGIN PASSWORD <test value>`` and
    # never restores it. Collection order puts that file before this one, so the
    # shared credential in AUDIT_DATABASE_URL_TEST is already stale by the time
    # this test connects; the post-commit dispatcher is best-effort and swallows
    # the resulting authentication error, which surfaced only as an empty queue.
    # Owning the role here makes the proof independent of that shared state.
    audit_role = f"kp_outbox_audit_{suffix}"
    audit_password = secrets.token_hex(16)
    database_url = source_url.set(database=database_name)
    audit_url = database_url.set(username=audit_role, password=audit_password)
    created_role = False
    created_database = False
    try:
        with server_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
            raw = connection.connection.driver_connection
            raw.execute(
                sql.SQL(
                    "CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB "
                    "NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS"
                ).format(sql.Identifier(audit_role), sql.Literal(audit_password))
            )
            created_role = True
            raw.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database_name)))
            created_database = True
        rendered_url = database_url.render_as_string(hide_password=False)
        monkeypatch.setenv("DATABASE_URL", rendered_url)
        config = Config(str(DATABASE_ROOT / "alembic.ini"))
        config.set_main_option("sqlalchemy.url", rendered_url)
        command.upgrade(config, "head")
        yield database_url, audit_url
    finally:
        if created_role or created_database:
            with server_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
                raw = connection.connection.driver_connection
                if created_database:
                    raw.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(database_name)))
                if created_role:
                    raw.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(audit_role)))
        server_engine.dispose()


class _RecordingQueue:
    def __init__(self) -> None:
        self.messages: list[tuple[str, dict[str, Any], str]] = []

    def publish(
        self,
        topic: str,
        payload: dict[str, Any],
        *,
        idempotency_key: str,
        available_at: float,
    ) -> None:
        assert available_at > 0
        self.messages.append((topic, payload, idempotency_key))


@requires_outbox_database
def test_post_commit_dispatch_completes_queue_and_audit_intents(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exercise the same separate business/audit engines used by services."""

    with _isolated_migrated_database(monkeypatch) as (database_url, audit_url):
        audit_role = audit_url.username
        assert audit_role is not None
        business_engine = create_db_engine(database_url.render_as_string(hide_password=False))
        audit_engine = create_db_engine(audit_url.render_as_string(hide_password=False))
        try:
            with business_engine.begin() as connection:
                connection.execute(
                    text(
                        "INSERT INTO audit_integrity_secret (singleton_id, key_hex) "
                        "VALUES (1, :key) ON CONFLICT (singleton_id) DO NOTHING"
                    ),
                    {"key": "0" * 64},
                )
                raw = connection.connection.driver_connection
                for statement in _AUDIT_ROLE_GRANTS:
                    raw.execute(sql.SQL(statement).format(sql.Identifier(audit_role)))

            # Fail loudly on a broken audit binding. The post-commit dispatcher
            # is deliberately best-effort, so a connection or privilege failure
            # would otherwise be swallowed and reported only as an empty queue.
            with audit_engine.connect() as connection:
                assert connection.scalar(text("SELECT current_user")) == audit_role

            # Match the service startup path: local legacy key support is
            # initially present, then the distinct business engine is bound.
            # Binding must revoke the owner-only direct-table fallback.
            store = AuditStore(audit_engine, hmac_key=b"0" * 32)
            store.bind_intent_engine(business_engine)
            queue = _RecordingQueue()
            with Session(business_engine) as session:
                enqueue_queue(
                    session,
                    topic="directory",
                    payload={"action": "preview", "job_id": "bounded-test-job"},
                    idempotency_key="directory:preview:bounded-test-job",
                )
                dispatch_after_commit(session, lambda: store.dispatch_pending_queue(queue))
                store.record(
                    session=session,
                    actor="test:operator",
                    action="directory.preview.request",
                    object_type="system",
                    object_id="bounded-test-job",
                    idempotency_key="audit:directory.preview.request:bounded-test-job",
                )
                session.commit()

            assert queue.messages == [
                (
                    "directory",
                    {"action": "preview", "job_id": "bounded-test-job"},
                    "directory:preview:bounded-test-job",
                )
            ]
            with business_engine.connect() as connection:
                statuses = connection.execute(
                    text(
                        "SELECT kind, status FROM transactional_outbox "
                        "WHERE idempotency_key IN (:queue_key, :audit_key) ORDER BY kind"
                    ),
                    {
                        "queue_key": "directory:preview:bounded-test-job",
                        "audit_key": "audit:directory.preview.request:bounded-test-job",
                    },
                ).all()
                event_count = int(
                    connection.scalar(
                        text(
                            "SELECT count(*) FROM audit_events "
                            "WHERE action = 'directory.preview.request' AND object_id = 'bounded-test-job'"
                        )
                    )
                    or 0
                )
            assert statuses == [("audit", "dispatched"), ("queue", "dispatched")]
            assert event_count == 1
            assert store.outbox_health() == {
                "pending": 0,
                "overdue_pending": 0,
                "scheduled_or_fresh": 0,
                "failed": 0,
                "dispatching_stale": 0,
            }
        finally:
            audit_engine.dispose()
            business_engine.dispose()
