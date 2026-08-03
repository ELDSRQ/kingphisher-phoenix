"""FastAPI dependencies: DB session + audit store from app state."""

from __future__ import annotations

from collections.abc import Iterator

from fastapi import Request
from kp_database.audit_store import AuditStore
from sqlalchemy.orm import Session


def get_session(request: Request) -> Iterator[Session]:
    session_factory = request.app.state.session_factory
    with session_factory() as session:
        yield session


def get_audit_store(request: Request) -> AuditStore:
    audit_store: AuditStore = request.app.state.audit_store
    return audit_store
