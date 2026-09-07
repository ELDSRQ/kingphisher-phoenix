"""AUD-004: migrating an EXISTING install past 0035 must not strip audit_writer.

`0035_audit_owner_separation` transfers ownership of the audit evidence tables to
the NOLOGIN ``audit_owner``. The migration's own comment reasoned that "explicit
audit_writer grants survive" — true, but beside the point on the installs that
matter: ``001-roles.sh`` made ``audit_writer`` the OWNER on every non-Azure
install, so its rights were IMPLICIT and there were no explicit grants to
survive. Transferring ownership left it with nothing.

Observed live on 2026-09-07 upgrading the .105 stack: every audit-chain
verification failed closed with ``permission denied for table audit_events`` and
the operator API returned 503. It is invisible on a FRESH install because
``001-roles.sh`` re-grants at container init, which is exactly why no existing
test caught it — they all start from a fresh schema.

This test therefore reproduces the *upgrade* shape specifically: stop at 0034,
make ``audit_writer`` the owner with no explicit grants, then migrate THROUGH
0035 and assert the append-only posture is intact.
"""

from __future__ import annotations

import os
import subprocess
import uuid
from pathlib import Path

import pytest
from sqlalchemy.engine import make_url

pytestmark = pytest.mark.postgres

DATABASE_PACKAGE = Path(__file__).resolve().parents[1]
ALEMBIC_INI = DATABASE_PACKAGE / "alembic.ini"
TEST_URL = os.environ.get(
    "DATABASE_URL_TEST", "postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher_test"
)

#: (table, privilege, expected). audit_writer appends evidence and advances the
#: head; it must never be able to destroy or rewrite an event.
_EXPECTED_POSTURE = (
    ("audit_events", "SELECT", True),
    ("audit_events", "INSERT", True),
    ("audit_events", "UPDATE", False),
    ("audit_events", "DELETE", False),
    ("audit_events", "TRUNCATE", False),
    ("audit_chain_head", "SELECT", True),
    ("audit_chain_head", "INSERT", True),
    ("audit_chain_head", "UPDATE", True),
    ("audit_chain_head", "DELETE", False),
)


def _alembic(database_url: str, revision: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, repository-owned migration runner
        ["python", "-m", "alembic", "upgrade", revision],  # noqa: S607
        cwd=DATABASE_PACKAGE,
        env={**os.environ, "DATABASE_URL": database_url, "KP_ALEMBIC_INI": str(ALEMBIC_INI)},
        capture_output=True,
        text=True,
        timeout=600,
    )


def test_upgrading_an_existing_install_through_0035_keeps_audit_writer_append_only() -> None:
    import psycopg

    source = make_url(TEST_URL)
    admin_dsn = (
        f"host={source.host} port={source.port or 5432} "
        f"user={source.username} password={source.password} dbname=postgres"
    )
    name = f"kp_aud004_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(admin_dsn, autocommit=True, connect_timeout=15) as admin:
        row = admin.execute("SELECT rolsuper OR rolcreatedb FROM pg_roles WHERE rolname = current_user").fetchone()
        if not (row and row[0]):
            pytest.skip("the test role needs CREATEDB to build a disposable upgrade database")
        admin.execute(f'CREATE DATABASE "{name}"')

    database_url = source.set(database=name).render_as_string(hide_password=False)
    try:
        # 1. The state BEFORE the ownership split.
        stopped = _alembic(database_url, "0034_reporting_filter_indexes")
        assert stopped.returncode == 0, stopped.stderr

        dsn = (
            f"host={source.host} port={source.port or 5432} "
            f"user={source.username} password={source.password} dbname={name}"
        )
        with psycopg.connect(dsn, autocommit=True, connect_timeout=15) as conn:
            conn.execute(
                "DO $$ BEGIN "
                "IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='audit_writer') "
                "THEN CREATE ROLE audit_writer LOGIN PASSWORD 'audit_writer'; END IF; END $$;"
            )
            # Reproduce the pre-0035 local shape: audit_writer OWNS the evidence
            # tables and holds NO explicit grants, so all of its rights are
            # implicit and vanish with the ownership transfer.
            for table in ("audit_events", "audit_chain_head"):
                conn.execute(f"ALTER TABLE public.{table} OWNER TO audit_writer")
                conn.execute(f"REVOKE ALL ON public.{table} FROM audit_writer")

            owner = conn.execute(
                "SELECT relowner::regrole::text FROM pg_class WHERE relname = 'audit_events'"
            ).fetchone()
            assert owner is not None and owner[0] == "audit_writer", "precondition: audit_writer must own it"

            # 2. Upgrade THROUGH 0035.
            upgraded = _alembic(database_url, "head")
            assert upgraded.returncode == 0, upgraded.stderr

            # 3. Ownership moved, and the append-only posture survived.
            owner_now = conn.execute(
                "SELECT relowner::regrole::text FROM pg_class WHERE relname = 'audit_events'"
            ).fetchone()
            assert owner_now is not None and owner_now[0] == "audit_owner"

            for table, privilege, expected in _EXPECTED_POSTURE:
                actual = conn.execute(
                    "SELECT has_table_privilege('audit_writer', %s, %s)", (table, privilege)
                ).fetchone()
                assert actual is not None
                assert actual[0] is expected, (
                    f"audit_writer {privilege} on {table}: expected {expected}, got {actual[0]}. "
                    "Losing SELECT/INSERT breaks audit-chain verification (AUD-004); "
                    "gaining DELETE/UPDATE defeats the ownership split."
                )
    finally:
        with psycopg.connect(admin_dsn, autocommit=True, connect_timeout=15) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
