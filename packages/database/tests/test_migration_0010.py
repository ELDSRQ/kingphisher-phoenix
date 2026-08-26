"""Migration 0010: DB-enforced audit ownership separation (CRIT-06).

The DDL assertions inspect the SQL the migration emits (no database needed).
The optional integration test executes the migration through a real Alembic
Operations context against the disposable dev Postgres and checks
ownership/privileges, skipping when the database or the audit_writer role is
unavailable.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from kp_database.session import create_db_engine
from sqlalchemy import text

# Shared dev-database helpers: same TEST_URL, same skip gate, and the
# table setup/teardown that later suites (e.g. operator-api test_privacy)
# depend on being runnable in this order.
from test_audit_store import TEST_URL, _create_tables, _drop_tables, requires_db

MIGRATION_PATH = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "0010_audit_ownership_separation.py"


def _load_migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("kp_migration_0010", MIGRATION_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _recorded_statements(monkeypatch: pytest.MonkeyPatch, func: str) -> list[str]:
    recorded: list[str] = []
    monkeypatch.setattr("alembic.op.execute", recorded.append)
    getattr(_load_migration(), func)()
    assert recorded, "migration emitted no SQL"
    return recorded


def test_upgrade_transfers_ownership_to_audit_writer(monkeypatch: pytest.MonkeyPatch) -> None:
    migration = _load_migration()
    sql = "\n".join(_recorded_statements(monkeypatch, "upgrade"))
    assert f"ALTER TABLE public.%I OWNER TO {migration.AUDIT_ROLE}" in sql
    for table in migration.AUDIT_TABLES:
        assert f"'{table}'" in sql


def test_upgrade_revokes_app_role_dml(monkeypatch: pytest.MonkeyPatch) -> None:
    migration = _load_migration()
    sql = "\n".join(_recorded_statements(monkeypatch, "upgrade"))
    assert f"REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.%I FROM {migration.APP_ROLE}" in sql


def test_upgrade_is_guarded_for_bare_dev_databases(monkeypatch: pytest.MonkeyPatch) -> None:
    sql = "\n".join(_recorded_statements(monkeypatch, "upgrade"))
    # Role-existence guards: skip with NOTICE instead of failing the upgrade
    assert "pg_roles" in sql
    assert sql.count("RAISE NOTICE") >= 4
    # Table-existence guards
    assert "to_regclass" in sql
    # Permission guards: skip rather than abort when the runner cannot take ownership
    assert "insufficient_privilege" in sql


def test_downgrade_restores_app_ownership(monkeypatch: pytest.MonkeyPatch) -> None:
    migration = _load_migration()
    sql = "\n".join(_recorded_statements(monkeypatch, "downgrade"))
    assert f"ALTER TABLE public.%I OWNER TO {migration.APP_ROLE}" in sql
    assert f"OWNER TO {migration.AUDIT_ROLE}" not in sql


@requires_db
def test_upgrade_sql_hardens_live_database() -> None:
    engine = create_db_engine(TEST_URL)
    with engine.connect() as conn:
        if not conn.execute(text("SELECT 1 FROM pg_roles WHERE rolname = 'audit_writer'")).scalar():
            engine.dispose()
            pytest.skip("audit_writer role not provisioned in dev cluster")
    engine.dispose()

    migration = _load_migration()
    engine = create_db_engine(TEST_URL)
    try:
        with engine.begin() as conn:
            # Pre-0010 dev state: app role owns fresh audit tables.
            conn.execute(text("DROP TABLE IF EXISTS audit_chain_head"))
            conn.execute(text("DROP TABLE IF EXISTS audit_events"))
            conn.execute(text("CREATE TABLE audit_events (audit_event_id UUID PRIMARY KEY)"))
            conn.execute(text("CREATE TABLE audit_chain_head (id INTEGER PRIMARY KEY)"))

        # Execute the migration exactly like `alembic upgrade` does: op.execute
        # proxies to a real Operations bound to this connection. Run twice to
        # prove idempotency.
        for _ in range(2):
            with engine.begin() as conn:
                context = MigrationContext.configure(conn)
                with Operations.context(context):
                    migration.upgrade()

        with engine.connect() as conn:
            owners = dict(
                conn.execute(
                    text(
                        "SELECT tablename, tableowner FROM pg_tables WHERE schemaname = 'public' "
                        "AND tablename IN ('audit_events', 'audit_chain_head')"
                    )
                ).all()
            )
            assert owners == {"audit_events": "audit_writer", "audit_chain_head": "audit_writer"}

            app_dml_grants = conn.execute(
                text(
                    "SELECT count(*) FROM information_schema.role_table_grants "
                    "WHERE grantee = 'kingphisher' "
                    "AND table_name IN ('audit_events', 'audit_chain_head') "
                    "AND privilege_type IN ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE')"
                )
            ).scalar()
            assert app_dml_grants == 0

            # Downgrade restores the pre-0010 dev state.
            with engine.begin() as conn2:
                context = MigrationContext.configure(conn2)
                with Operations.context(context):
                    migration.downgrade()
            owners = dict(
                conn.execute(
                    text(
                        "SELECT tablename, tableowner FROM pg_tables WHERE schemaname = 'public' "
                        "AND tablename IN ('audit_events', 'audit_chain_head')"
                    )
                ).all()
            )
            assert owners == {"audit_events": "kingphisher", "audit_chain_head": "kingphisher"}
    finally:
        # The disposable test database is shared in run order with
        # apps/operator-api/tests (test_privacy appends audit rows).
        # audit_chain_head is not in Base metadata, so drop it explicitly or
        # _create_tables' IF NOT EXISTS would keep this test's minimal stub
        # and later suites would fail on the missing columns.
        with engine.begin() as conn:
            conn.execute(text("DROP TABLE IF EXISTS audit_chain_head"))
        engine.dispose()
        _drop_tables()
        _create_tables()
