"""Live PostgreSQL proof for post-commit audit and queue dispatch."""

from __future__ import annotations

import os
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
AUDIT_URL = os.environ.get(
    "AUDIT_DATABASE_URL_TEST",
    "postgresql+psycopg://audit_writer:audit_writer@localhost:5432/kingphisher_test",
)
DATABASE_ROOT = Path(__file__).resolve().parents[1]


def _eligible_database() -> bool:
    if os.environ.get("KP_TEST_PROFILE") != "postgres":
        return False
    engine = create_db_engine(TEST_URL)
    try:
        with engine.connect() as connection:
            return bool(
                connection.scalar(
                    text(
                        "SELECT (rolsuper OR rolcreatedb) AND "
                        "EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_writer') "
                        "FROM pg_roles WHERE rolname = current_user"
                    )
                )
            )
    except Exception:  # noqa: BLE001 - explicit live-Postgres capability gate
        return False
    finally:
        engine.dispose()


requires_outbox_database = pytest.mark.skipif(
    not _eligible_database(),
    reason="local Postgres with isolated-database rights and audit_writer is not reachable",
)


@contextmanager
def _isolated_migrated_database(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[URL, URL]]:
    source_url = make_url(TEST_URL)
    audit_source_url = make_url(AUDIT_URL)
    server_engine = create_db_engine(source_url.set(database="postgres").render_as_string(hide_password=False))
    database_name = f"kp_outbox_{uuid.uuid4().hex}"
    database_url = source_url.set(database=database_name)
    audit_url = audit_source_url.set(database=database_name)
    created = False
    try:
        with server_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
            raw = connection.connection.driver_connection
            raw.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database_name)))
        created = True
        rendered_url = database_url.render_as_string(hide_password=False)
        monkeypatch.setenv("DATABASE_URL", rendered_url)
        config = Config(str(DATABASE_ROOT / "alembic.ini"))
        config.set_main_option("sqlalchemy.url", rendered_url)
        command.upgrade(config, "head")
        yield database_url, audit_url
    finally:
        if created:
            with server_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
                raw = connection.connection.driver_connection
                raw.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(database_name)))
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
                connection.execute(text("GRANT USAGE ON SCHEMA public TO audit_writer"))
                connection.execute(
                    text(
                        "GRANT SELECT ON TABLE audit_events, audit_chain_head TO audit_writer; "
                        "GRANT EXECUTE ON FUNCTION kp_dispatch_audit_outbox(uuid), "
                        "kp_dispatch_pending_audit(integer), kp_claim_queue_outbox(integer), "
                        "kp_complete_outbox(uuid), kp_fail_outbox(uuid,text), kp_outbox_health(), "
                        "kp_verify_audit_head() TO audit_writer"
                    )
                )

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
