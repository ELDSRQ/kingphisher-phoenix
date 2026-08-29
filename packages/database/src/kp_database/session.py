"""Engine and session factory.

Services connect with their own scoped credentials. The audit store uses the
dedicated function-only `audit_writer` connection: workloads may stage intent
in their own transaction, while only constrained SECURITY DEFINER dispatchers
can append evidence or advance the signed chain head.
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
