"""Serialize purge transactions against hold changes in this tenant database.

Purgers share a transaction advisory lock; set/release takes it exclusively.
The lock is acquired before querying active holds and retained through commit,
closing the check/delete race without serializing unrelated erasures. READ
COMMITTED is mandatory so an earlier transaction snapshot cannot hide a hold
that committed while this transaction waited. Other isolation levels fail
closed. No connection, schema or permission error permits a purge.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from kp_database.models import RetentionHold
from kp_database.reporting import SINGLE_TENANT_DATABASE_SCOPE


class RetentionHoldActive(RuntimeError):
    """An explicit hold blocks irreversible deletion."""


class RetentionHoldStateUnavailable(RuntimeError):
    """Preservation state cannot be safely verified."""


def lock_hold_state(session: Session, *, exclusive: bool = False) -> None:
    connection = session.connection()
    if connection.dialect.name != "postgresql" or connection.get_isolation_level() != "READ COMMITTED":
        raise RetentionHoldStateUnavailable("retention holds require PostgreSQL READ COMMITTED transactions")
    statement = (
        text("SELECT pg_advisory_xact_lock(1263551025)")
        if exclusive
        else text("SELECT pg_advisory_xact_lock_shared(1263551025)")
    )
    session.execute(statement)


def active_retention_hold(session: Session) -> UUID | None:
    lock_hold_state(session)
    return session.scalar(
        select(RetentionHold.retention_hold_id)
        .where(
            RetentionHold.scope == SINGLE_TENANT_DATABASE_SCOPE,
            RetentionHold.released_at.is_(None),
        )
        .order_by(RetentionHold.created_at, RetentionHold.retention_hold_id)
        .limit(1)
    )


def require_no_retention_hold(session: Session) -> None:
    if active_retention_hold(session) is not None:
        raise RetentionHoldActive("An active retention hold pauses erasure and retention purges.")


def create_retention_hold(
    session: Session, *, hold_id: UUID, reference: str, reason: str, actor: str, now: datetime
) -> tuple[RetentionHold, bool]:
    lock_hold_state(session, exclusive=True)
    existing = session.get(RetentionHold, hold_id)
    if existing is not None:
        if existing.reference != reference or existing.reason != reason or existing.created_by != actor:
            raise ValueError("hold identifier already belongs to a different request")
        return existing, False
    row = RetentionHold(
        retention_hold_id=hold_id,
        scope=SINGLE_TENANT_DATABASE_SCOPE,
        reference=reference,
        reason=reason,
        created_by=actor,
        created_at=now,
    )
    session.add(row)
    session.flush()
    return row, True


def release_retention_hold(
    session: Session, *, hold_id: UUID, reason: str, actor: str, now: datetime
) -> tuple[RetentionHold | None, bool]:
    lock_hold_state(session, exclusive=True)
    row = session.get(RetentionHold, hold_id)
    if row is None or row.released_at is not None:
        return row, False
    row.released_at = now
    row.released_by = actor
    row.release_reason = reason
    session.flush()
    return row, True
