"""Effect-level (real-privilege) proofs of the AUD-002 grant matrix.

DRAFT (AUD-002, KP-008 structural root). These tests do NOT assert SQL strings.
They stand up an isolated, migrated PostgreSQL database, apply the grants the
way a deploy does, then connect AS each least-privilege role and check the
ACTUAL privileges PostgreSQL reports (``has_table_privilege`` /
``has_column_privilege`` / real DML / catalog ownership). The oracle for what
each role should and should not have is the single source of truth in
``kp_database.grants``.

They are marked ``postgres`` and run only under ``make test-postgres`` (a
migrated disposable database with role-creation rights). They cannot run in the
static-only environment; CI's PostgreSQL integration gate exercises them.

Cluster note: applying the azure bootstrap creates the fixed cluster-level
runtime roles (``kp_operator`` etc.). ``_ensure_login_role`` ALTERs them if they
already exist, so re-runs are safe; the isolated database is dropped in
teardown. On an ephemeral CI PostgreSQL this leaves nothing behind.
"""

from __future__ import annotations

import importlib.util
import os
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType

import pytest
from alembic import command
from alembic.config import Config
from kp_database import grants
from kp_database.session import create_db_engine
from psycopg import sql
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url

pytestmark = pytest.mark.postgres

DATABASE_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_INI = DATABASE_ROOT / "alembic.ini"
SCRIPT_PATH = DATABASE_ROOT.parents[1] / "scripts" / "azure_migrate.py"

TEST_URL = os.environ.get(
    "DATABASE_URL_TEST", "postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher_test"
)
_AUDIT_ROOT_KEY = "0" * 64


def _eligible() -> bool:
    if os.environ.get("KP_TEST_PROFILE") != "postgres":
        return False
    try:
        engine = create_db_engine(make_url(TEST_URL).set(database="postgres").render_as_string(hide_password=False))
        with engine.connect() as connection:
            can = bool(
                connection.scalar(
                    text(
                        "SELECT rolsuper OR (rolcreatedb AND rolcreaterole) FROM pg_roles WHERE rolname = current_user"
                    )
                )
            )
        engine.dispose()
        return can
    except Exception:
        return False


requires_privileged_db = pytest.mark.skipif(
    not _eligible(),
    reason="privileged local Postgres (CREATEDB + CREATEROLE) is required for the grant-matrix effect gate",
)


def _load_azure_migrate() -> ModuleType:
    spec = importlib.util.spec_from_file_location("kp_azure_migrate_effect", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@contextmanager
def _isolated_database() -> Iterator[URL]:
    source_url = make_url(TEST_URL)
    admin_engine = create_engine(
        source_url.set(database="postgres").render_as_string(hide_password=False),
        isolation_level="AUTOCOMMIT",
        pool_pre_ping=True,
    )
    database_name = f"kp_grants_{uuid.uuid4().hex}"
    database_url = source_url.set(database=database_name)
    created = False
    try:
        with admin_engine.connect() as connection:
            raw = connection.connection.driver_connection
            raw.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database_name)))
        created = True
        yield database_url
    finally:
        if created:
            with admin_engine.connect() as connection:
                raw = connection.connection.driver_connection
                raw.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(database_name)))
        admin_engine.dispose()


@contextmanager
def _upgraded_database() -> Iterator[URL]:
    """Isolated database taken to head with plain ``alembic upgrade`` only.

    This is the local / non-Azure path: no azure_migrate, just the migration
    chain, so it proves migration 0034 alone hardens audit ownership.
    """
    with _isolated_database() as database_url:
        rendered = database_url.render_as_string(hide_password=False)
        os.environ["DATABASE_URL"] = rendered
        try:
            config = Config(str(ALEMBIC_INI))
            config.set_main_option("sqlalchemy.url", rendered)
            command.upgrade(config, "head")
            yield database_url
        finally:
            os.environ.pop("DATABASE_URL", None)


def _suite_audit_writer_password() -> str:
    """The audit_writer password the rest of the postgres profile authenticates with."""
    configured = os.environ.get("AUDIT_DATABASE_URL_TEST", "")
    password = make_url(configured).password if configured else None
    return password or "audit_writer"


def _bootstrap_via_azure_migrate(database_url: URL, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Run the real azure bootstrap (roles + migrations + grants + probe)."""
    script = _load_azure_migrate()
    rendered = database_url.render_as_string(hide_password=False)
    monkeypatch.setenv("DATABASE_URL", rendered)
    monkeypatch.setenv("KP_ALEMBIC_INI", str(ALEMBIC_INI))
    # audit_writer is a CLUSTER-WIDE role shared with the rest of the postgres
    # profile, and azure_migrate issues `ALTER ROLE audit_writer LOGIN PASSWORD`.
    # A test-invented password therefore escapes this test's disposable database
    # and breaks every later test that logs in as audit_writer — which is exactly
    # how test_outbox_postgres failed in CI (pytest collects this file first
    # alphabetically), and how a gate run against a shared server repointed a
    # running application's credential. Reuse the password the suite already
    # expects so the ALTER is a no-op instead of pollution.
    monkeypatch.setenv("AUDIT_WRITER_PASSWORD", _suite_audit_writer_password())
    monkeypatch.setenv("AUDIT_ROOT_KEY", _AUDIT_ROOT_KEY)
    # Provision EVERY workload so the matrix-driven probe covers all roles.
    for workload in grants.RUNTIME_ROLES:
        monkeypatch.setenv(script._password_env(workload), f"effect-{workload}")
    script.main()
    return script


def _role_url(database_url: URL, role: str, password: str) -> str:
    return database_url.set(username=role, password=password).render_as_string(hide_password=False)


# ---------------------------------------------------------------------------
# Point 4: migration 0034 hardens audit ownership on the local/non-Azure path
# ---------------------------------------------------------------------------
@requires_privileged_db
def test_upgrade_head_transfers_audit_tables_to_nologin_audit_owner() -> None:
    with _upgraded_database() as database_url:
        engine = create_engine(database_url.render_as_string(hide_password=False))
        try:
            with engine.connect() as connection:
                for table in ("audit_events", "audit_chain_head"):
                    owner = connection.scalar(
                        text("SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = to_regclass(:t)"),
                        {"t": f"public.{table}"},
                    )
                    assert owner == "audit_owner", (table, owner)
                # audit_owner is NOLOGIN: no session can assume the owner.
                assert connection.scalar(text("SELECT NOT rolcanlogin FROM pg_roles WHERE rolname = 'audit_owner'"))
                # audit_writer must NOT be able to destroy audit evidence.
                for table in ("audit_events", "audit_chain_head"):
                    assert (
                        connection.scalar(
                            text("SELECT has_table_privilege('audit_writer', :t, 'DELETE')"),
                            {"t": f"public.{table}"},
                        )
                        is False
                    ), table
        finally:
            engine.dispose()


# ---------------------------------------------------------------------------
# Point 3: per-role EFFECT tests over the full azure bootstrap
# ---------------------------------------------------------------------------
@requires_privileged_db
def test_every_workload_role_matches_the_matrix_exactly(monkeypatch: pytest.MonkeyPatch) -> None:
    with _isolated_database() as database_url:
        _bootstrap_via_azure_migrate(database_url, monkeypatch)
        tables = sorted(grants.all_matrix_tables())
        for workload, role in grants.RUNTIME_ROLES.items():
            role_engine = create_engine(_role_url(database_url, role, f"effect-{workload}"))
            try:
                with role_engine.connect() as probe:
                    assert probe.exec_driver_sql("SELECT current_user").scalar() == role
                    for table in tables:
                        for verb in grants.TABLE_VERBS:
                            expected = grants.expected_table_privilege(workload, table, verb)
                            actual = bool(
                                probe.exec_driver_sql(
                                    "SELECT has_table_privilege(%(t)s, %(v)s)",
                                    {"t": f"public.{table}", "v": verb},
                                ).scalar()
                            )
                            assert actual == expected, (role, table, verb, expected)
            finally:
                role_engine.dispose()


@requires_privileged_db
def test_enqueue_roles_read_only_the_outbox_arbiter_not_the_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    with _isolated_database() as database_url:
        _bootstrap_via_azure_migrate(database_url, monkeypatch)
        for workload in sorted(grants.enqueue_workloads()):
            role = grants.RUNTIME_ROLES[workload]
            role_engine = create_engine(_role_url(database_url, role, f"effect-{workload}"))
            try:
                with role_engine.connect() as probe:
                    assert bool(
                        probe.exec_driver_sql(
                            "SELECT has_column_privilege('public.transactional_outbox', 'idempotency_key', 'SELECT')"
                        ).scalar()
                    ), role
                    assert not bool(
                        probe.exec_driver_sql(
                            "SELECT has_column_privilege('public.transactional_outbox', 'payload', 'SELECT')"
                        ).scalar()
                    ), role
            finally:
                role_engine.dispose()


@requires_privileged_db
def test_operator_can_actually_enqueue_but_not_read_others_payloads(monkeypatch: pytest.MonkeyPatch) -> None:
    with _isolated_database() as database_url:
        _bootstrap_via_azure_migrate(database_url, monkeypatch)
        role_engine = create_engine(_role_url(database_url, grants.RUNTIME_ROLES["operator"], "effect-operator"))
        try:
            with role_engine.connect() as probe:
                probe_id = str(uuid.uuid4())
                probe.exec_driver_sql(
                    "INSERT INTO transactional_outbox "
                    "(outbox_id, kind, payload, idempotency_key, available_at) "
                    "VALUES (%(id)s, 'audit', '{}'::jsonb, %(key)s, now()) "
                    "ON CONFLICT (idempotency_key) DO NOTHING",
                    {"id": probe_id, "key": f"kp008-effect:{probe_id}"},
                )
                probe.rollback()
                with pytest.raises(Exception):  # noqa: B017,PT011 - any denial proves payload is unreadable
                    probe.exec_driver_sql("SELECT payload FROM transactional_outbox LIMIT 1")
                probe.rollback()
        finally:
            role_engine.dispose()
