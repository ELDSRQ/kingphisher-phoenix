"""Fixture plumbing (TST-002): rebuild the disposable Postgres test schema from
the real Alembic migration chain instead of ``Base.metadata.create_all()``.

Postgres-marked tests must exercise the *migrated* schema so that ORM/metadata
drift -- columns, constraints, indexes, and the ownership/grants that only
migrations apply -- is caught by the integration gate rather than hidden behind
``create_all()``. This module is imported only by ``postgres``-marked tests; the
hermetic suite never reaches its code path.

It is a sibling helper module (imported the same way the existing tests already
do ``from test_audit_store import TEST_URL``) rather than a ``conftest.py`` to
avoid the ``conftest`` basename collision with ``apps/operator-api/tests`` under
pytest's default (prepend) import mode.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from alembic import command
from alembic.config import Config
from kp_database.session import create_db_engine
from sqlalchemy import text

DATABASE_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_INI = DATABASE_ROOT / "alembic.ini"


@contextmanager
def _database_url_env(url: str) -> Iterator[None]:
    """Point Alembic's ``env.py`` at ``url`` for the duration of the upgrade.

    ``env.py`` prefers ``DATABASE_URL`` when set (which the postgres gate already
    exports as ``DATABASE_URL_TEST``) and otherwise falls back to the config's
    ``sqlalchemy.url``. Setting both keeps the target explicit and restores any
    prior value afterwards.
    """
    previous = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = url
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous


def rebuild_public_schema_via_migrations(url: str) -> None:
    """Reset the ``public`` schema on ``url`` and rebuild it with ``upgrade head``.

    Drop-in replacement for the ``Base.metadata.drop_all()`` /
    ``Base.metadata.create_all()`` fixture idiom, so the resulting schema is the
    one the migration chain produces.

    ``DROP SCHEMA public CASCADE`` needs no more privilege than the ``drop_all()``
    it replaces -- both require ownership of the objects being removed -- and the
    role-creating migrations (e.g. ``0035`` ``audit_owner``) guard with
    ``IF NOT EXISTS``, so repeating this against the shared disposable
    ``kingphisher_test`` database between tests is safe. Dropping the schema also
    removes ``alembic_version`` so the chain always runs from base to head.
    """
    engine = create_db_engine(url)
    try:
        with engine.begin() as connection:
            connection.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
    finally:
        engine.dispose()
    config = Config(str(ALEMBIC_INI))
    config.set_main_option("sqlalchemy.url", url)
    with _database_url_env(url):
        command.upgrade(config, "head")
