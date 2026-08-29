from __future__ import annotations

import os
from pathlib import Path

from alembic import context
from dotenv import load_dotenv
from kp_database import models  # noqa: F401 - register tables with metadata
from kp_database.base import Base
from sqlalchemy import engine_from_config, pool

# Load the same .env the application reads so migrations behave identically
# whether launched from the shell or from an installer that only wrote .env.
_load_env = Path(__file__).resolve().parents[3] / ".env"
if os.environ.get("KP_DISABLE_DOTENV") != "1" and _load_env.exists():
    load_dotenv(_load_env, override=False)

config = context.config
database_url = os.getenv("DATABASE_URL")
if database_url:
    config.set_main_option("sqlalchemy.url", database_url)
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
