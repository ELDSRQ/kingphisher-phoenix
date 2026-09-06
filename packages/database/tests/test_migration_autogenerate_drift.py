"""Alembic autogenerate drift gate (AUD-002, point 5).

After ``upgrade head`` on an isolated migrated database, an autogenerate compare
against the ORM metadata must find nothing the models declare that a migration
has not already created. This catches the classic drift where a model gains a
column/table/constraint but no migration was written.

DRAFT caveat: autogenerate only sees objects SQLAlchemy metadata models
(tables, columns, indexes, constraints). It does NOT see the DB-only artifacts
this schema also relies on — the audit/outbox PL/pgSQL functions, GRANT/REVOKE,
ownership, or the audit_integrity_secret trigger surface — so this gate ignores
``remove_*`` diffs (DB objects with no ORM counterpart) and asserts only that
the ORM has no *un-migrated additions or alterations*. Marked ``postgres``; runs
under ``make test-postgres``.
"""

from __future__ import annotations

import pytest
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from kp_database import models  # noqa: F401 - register tables on Base.metadata
from kp_database.base import Base
from sqlalchemy import create_engine
from test_grant_matrix_effect import _upgraded_database, requires_privileged_db

pytestmark = pytest.mark.postgres


def _flatten(diffs: list[object]) -> list[tuple]:
    flat: list[tuple] = []
    for diff in diffs:
        if isinstance(diff, list):
            flat.extend(item for item in diff if isinstance(item, tuple))
        elif isinstance(diff, tuple):
            flat.append(diff)
    return flat


@requires_privileged_db
def test_head_schema_has_no_pending_model_additions() -> None:
    with _upgraded_database() as database_url:
        engine = create_engine(database_url.render_as_string(hide_password=False))
        try:
            with engine.connect() as connection:
                context = MigrationContext.configure(
                    connection,
                    opts={"compare_type": True, "compare_server_default": False},
                )
                diffs = compare_metadata(context, Base.metadata)
        finally:
            engine.dispose()

    # Keep only additions/alterations the ORM declares but the DB lacks. Ignore
    # remove_* (DB-managed objects the models intentionally do not describe).
    pending = [op for op in _flatten(diffs) if op and isinstance(op[0], str) and not op[0].startswith("remove")]
    assert pending == [], f"ORM metadata has un-migrated changes: {pending}"
