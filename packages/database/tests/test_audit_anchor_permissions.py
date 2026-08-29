"""Live PostgreSQL acceptance for the audit-anchor login boundary."""

from __future__ import annotations

import os
import secrets
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from kp_database.audit_store import AuditStore
from kp_database.session import create_db_engine
from psycopg import sql
from sqlalchemy import text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import ProgrammingError

pytestmark = pytest.mark.postgres


TEST_URL = os.environ.get(
    "DATABASE_URL_TEST", "postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher_test"
)
DATABASE_ROOT = Path(__file__).resolve().parents[1]

_AUDIT_EVENT_COLUMNS = (
    "actor",
    "action",
    "object_type",
    "object_id",
    "occurred_at",
    "detail",
    "prev_hash",
    "event_hash",
    "nonce",
    "canonical_payload",
    "chain_version",
)
_HEAD_COLUMNS = ("id", "event_hash", "signature", "signed_at")


def _eligible_database() -> bool:
    if os.environ.get("KP_TEST_PROFILE") != "postgres":
        return False
    engine = create_db_engine(TEST_URL)
    try:
        with engine.connect() as connection:
            can_create_role = bool(
                connection.scalar(text("SELECT rolsuper OR rolcreaterole FROM pg_roles WHERE rolname = current_user"))
            )
            can_create_database = bool(
                connection.scalar(text("SELECT rolsuper OR rolcreatedb FROM pg_roles WHERE rolname = current_user"))
            )
        return can_create_role and can_create_database
    except Exception:  # noqa: BLE001 - optional local PostgreSQL acceptance
        return False
    finally:
        engine.dispose()


requires_anchor_database = pytest.mark.skipif(
    not _eligible_database(),
    reason="local Postgres with isolated-database and role-creation rights is not reachable",
)


@contextmanager
def _isolated_migrated_database(monkeypatch: pytest.MonkeyPatch) -> Iterator[URL]:
    source_url = make_url(TEST_URL)
    server_url = source_url.set(database="postgres")
    database_name = f"kp_anchor_{uuid.uuid4().hex}"
    database_url = source_url.set(database=database_name)
    server_engine = create_db_engine(server_url.render_as_string(hide_password=False))
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
        yield database_url
    finally:
        if created:
            with server_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
                raw = connection.connection.driver_connection
                raw.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(database_name)))
        server_engine.dispose()


@requires_anchor_database
def test_anchor_role_can_verify_and_snapshot_but_cannot_mutate_or_read_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _isolated_migrated_database(monkeypatch) as database_url:
        role_name = f"kp_anchor_accept_{secrets.token_hex(6)}"
        password = secrets.token_hex(24)
        admin_engine = create_db_engine(database_url.render_as_string(hide_password=False))
        anchor_engine = None
        role_created = False
        try:
            with admin_engine.begin() as connection:
                connection.exec_driver_sql(
                    f"CREATE ROLE {role_name} LOGIN PASSWORD '{password}' "
                    "NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS"
                )
                role_created = True
                connection.exec_driver_sql(f"GRANT USAGE ON SCHEMA public TO {role_name}")
                connection.exec_driver_sql(
                    f"GRANT SELECT ({', '.join(_AUDIT_EVENT_COLUMNS)}) ON TABLE audit_events TO {role_name}"
                )
                connection.exec_driver_sql(
                    f"GRANT SELECT ({', '.join(_HEAD_COLUMNS)}) ON TABLE audit_chain_head TO {role_name}"
                )
                connection.exec_driver_sql(
                    f"GRANT EXECUTE ON FUNCTION kp_outbox_health(), kp_verify_audit_head() TO {role_name}"
                )

            anchor_url = database_url.set(username=role_name, password=password)
            anchor_engine = create_db_engine(anchor_url.render_as_string(hide_password=False))
            store = AuditStore(anchor_engine)

            # head_snapshot counts the explicitly granted, non-null event_hash
            # column rather than relying on table-level COUNT(*) privilege.
            store.head_snapshot()
            assert isinstance(store.verify(), list)

            forbidden = (
                "SELECT key_hex FROM audit_integrity_secret",
                "SELECT payload FROM transactional_outbox LIMIT 1",
                "SELECT * FROM campaigns LIMIT 1",
                "DELETE FROM audit_events WHERE false",
                "SELECT kp_dispatch_pending_audit(1)",
            )
            for statement in forbidden:
                with pytest.raises(ProgrammingError), anchor_engine.begin() as connection:
                    connection.execute(text(statement))
        finally:
            if anchor_engine is not None:
                anchor_engine.dispose()
            if role_created:
                with admin_engine.begin() as connection:
                    connection.exec_driver_sql(f"DROP OWNED BY {role_name}")
                    connection.exec_driver_sql(f"DROP ROLE {role_name}")
            admin_engine.dispose()
