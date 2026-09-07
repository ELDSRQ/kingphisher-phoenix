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
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from alembic import command
from alembic.config import Config
from kp_database.session import create_db_engine
from psycopg import sql
from sqlalchemy import text
from sqlalchemy.engine import make_url

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

    A freshly ``CREATE``d schema carries only the owner's privileges, whereas the
    ``public`` schema ``initdb`` builds carries an explicit ``USAGE`` grant to
    ``PUBLIC``. Without restoring it this rebuild would silently strip schema
    access from every other role in the cluster for the rest of the run -- most
    visibly ``audit_writer``, whose ``USAGE`` is granted once at container init
    by ``infrastructure/containers/postgres-init/001-roles.sh``. Re-granting it
    keeps the rebuilt database equivalent to a stock one; it adds no privilege a
    real install does not already have.
    """
    engine = create_db_engine(url)
    try:
        with engine.begin() as connection:
            connection.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
            connection.execute(text("GRANT USAGE ON SCHEMA public TO PUBLIC"))
    finally:
        engine.dispose()
    config = Config(str(ALEMBIC_INI))
    config.set_main_option("sqlalchemy.url", url)
    with _database_url_env(url):
        command.upgrade(config, "head")


@contextmanager
def isolated_migrated_database(url: str, *, prefix: str = "kp_test") -> Iterator[str]:
    """Create a disposable database on ``url``'s server, upgrade it, drop it.

    Yields the rendered URL of a database that exists only for the duration of
    the block and whose schema was produced by ``alembic upgrade head``.

    Use this instead of :func:`rebuild_public_schema_via_migrations` when a test
    cannot share the ``public`` schema of the common disposable database --
    either because it needs per-test isolation that a schema-rebuild cannot give
    (the migrations hardcode ``public.``, so a custom ``search_path`` schema is
    never migrated), or because it connects as a role other than the migration
    role and therefore depends on the stock ``public`` schema ACL.

    Requires ``CREATEDB``; callers gate on it with their own skip marker so the
    failure mode is an actionable skip rather than an error.
    """
    source_url = make_url(url)
    database_name = f"{prefix}_{uuid.uuid4().hex}"
    database_url = source_url.set(database=database_name).render_as_string(hide_password=False)
    server_engine = create_db_engine(source_url.set(database="postgres").render_as_string(hide_password=False))
    created = False
    try:
        with server_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
            raw = connection.connection.driver_connection
            raw.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database_name)))
        created = True
        config = Config(str(ALEMBIC_INI))
        config.set_main_option("sqlalchemy.url", database_url)
        with _database_url_env(database_url):
            command.upgrade(config, "head")
        yield database_url
    finally:
        if created:
            with server_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
                raw = connection.connection.driver_connection
                raw.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(database_name)))
        server_engine.dispose()
