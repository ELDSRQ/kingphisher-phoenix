"""Provision the restricted audit role, then apply idempotent Alembic migrations."""

from __future__ import annotations

import os

from alembic import command
from alembic.config import Config
from psycopg import sql
from sqlalchemy import create_engine, text


def main() -> None:
    database_url = os.environ["DATABASE_URL"]
    audit_password = os.environ["AUDIT_WRITER_PASSWORD"]
    engine = create_engine(database_url, pool_pre_ping=True)
    with engine.begin() as connection:
        exists = connection.scalar(text("SELECT 1 FROM pg_roles WHERE rolname = 'audit_writer'"))
        raw = connection.connection.driver_connection
        statement = sql.SQL("{} ROLE audit_writer {} PASSWORD {}").format(
            sql.SQL("CREATE" if not exists else "ALTER"),
            sql.SQL("LOGIN" if not exists else ""),
            sql.Literal(audit_password),
        )
        raw.execute(statement)
        connection.execute(text("GRANT USAGE, CREATE ON SCHEMA public TO audit_writer"))
        connection.execute(
            text("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT INSERT, SELECT ON TABLES TO audit_writer")
        )

    config = Config("/app/packages/database/alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "head")

    with engine.begin() as connection:
        connection.execute(text("GRANT INSERT, SELECT ON TABLE audit_events TO audit_writer"))
        connection.execute(text("GRANT SELECT, UPDATE, INSERT ON TABLE audit_chain_heads TO audit_writer"))


if __name__ == "__main__":
    main()
