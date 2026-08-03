"""Engine and session factory.

Services connect with their own scoped credentials. The audit store uses the
dedicated `audit_writer` connection string (INSERT-only grants) so that
application ORM sessions cannot mutate audit rows even if application code
misbehaves.
"""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker


def create_db_engine(database_url: str, *, pool_size: int = 5) -> Engine:
    return create_engine(
        database_url,
        pool_pre_ping=True,
        pool_size=pool_size,
        connect_args={"connect_timeout": 5},
    )


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, class_=Session)
