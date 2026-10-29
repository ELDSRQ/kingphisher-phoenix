"""Transactional audit and queue intents with idempotent dispatch.

Callers add intents to the same SQLAlchemy ``Session`` as their business
mutation and own the commit.  Dispatch is deliberately separate: a process
crash can leave only a visible, retryable pending row, never an unrecorded
mutation or an in-memory-only queue request.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from kp_auditing.audit import GENESIS_HASH, AuditRecord
from sqlalchemy import DateTime, bindparam, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError, ProgrammingError
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import TextClause

logger = logging.getLogger(__name__)

_QUEUE_DISPATCH_FAILURE_CODE = "queue_dispatch_failed"
_UNKNOWN_SQLSTATE_CLASS = "unknown"


def _sqlstate_class(exc: BaseException) -> str:
    """Return only PostgreSQL's stable two-character error class.

    DBAPI exception text, statements and parameters can contain credentials or
    recipient data.  The SQLSTATE class is sufficient to distinguish access,
    integrity, transaction and programming failures without reflecting those
    values into an operational log.
    """

    if not isinstance(exc, DBAPIError):
        return _UNKNOWN_SQLSTATE_CLASS
    sqlstate = getattr(exc.orig, "sqlstate", None)
    if not isinstance(sqlstate, str) or len(sqlstate) != 5 or not sqlstate.isalnum():
        return _UNKNOWN_SQLSTATE_CLASS
    return sqlstate[:2].upper()


def _log_database_failure(event_name: str, exc: DBAPIError, *, outbox_id: Any | None = None) -> None:
    fields: tuple[Any, ...]
    message = f"{event_name} reason_code=database_operation_failed sqlstate_class=%s exception_type=%s"
    fields = (_sqlstate_class(exc), type(exc).__name__[:128])
    if outbox_id is not None:
        message += " outbox_id=%s"
        fields += (outbox_id,)
    logger.error(message, *fields)


def _outbox_insert(statement: str) -> TextClause:
    """Bind timestamps explicitly instead of relying on DBAPI adapters.

    Python's implicit SQLite datetime adapter is deprecated, and leaving this
    parameter untyped also makes behavior depend on the selected DBAPI. The
    production PostgreSQL path and lightweight SQLite contract tests now use
    SQLAlchemy's portable datetime processor.
    """
    return text(statement).bindparams(bindparam("available_at", type_=DateTime(timezone=True)))


def enqueue_audit(
    session: Session,
    *,
    actor: str,
    action: str,
    object_type: str,
    object_id: str,
    detail: dict[str, Any] | None = None,
    occurred_at: datetime | None = None,
    idempotency_key: str | None = None,
) -> tuple[uuid.UUID, AuditRecord]:
    """Stage an audit intent; the caller must commit or roll back the session."""
    occurred = occurred_at or datetime.now(UTC)
    outbox_id = uuid.uuid4()
    payload = {
        "actor": actor,
        "action": action,
        "object_type": object_type,
        "object_id": object_id,
        "detail": detail or {},
        "occurred_at": occurred.isoformat(),
    }
    session.execute(
        _outbox_insert(
            "INSERT INTO transactional_outbox "
            "(outbox_id, kind, payload, idempotency_key, available_at) "
            "VALUES (:id, 'audit', CAST(:payload AS jsonb), :key, :available_at) "
            "ON CONFLICT (idempotency_key) DO NOTHING"
        ),
        {
            "id": str(outbox_id),
            "payload": payload_json(payload),
            "key": idempotency_key or f"audit:{outbox_id}",
            "available_at": occurred,
        },
    )
    # Compatibility receipt. The authoritative hashes are produced by the
    # database dispatcher after commit and are never trusted from the caller.
    receipt = AuditRecord(
        actor=actor,
        action=action,
        object_type=object_type,
        object_id=object_id,
        occurred_at=occurred,
        detail=detail or {},
        outcome="pending",
        prev_hash=GENESIS_HASH,
        event_hash=GENESIS_HASH,
        nonce="",
        audit_event_id=outbox_id,
    )
    return outbox_id, receipt


def enqueue_queue(
    session: Session,
    *,
    topic: str,
    payload: dict[str, Any],
    idempotency_key: str,
    available_at: datetime | None = None,
) -> uuid.UUID:
    """Stage one queue request in the caller-owned business transaction."""
    outbox_id = uuid.uuid4()
    session.execute(
        _outbox_insert(
            "INSERT INTO transactional_outbox "
            "(outbox_id, kind, topic, payload, idempotency_key, available_at) "
            "VALUES (:id, 'queue', :topic, CAST(:payload AS jsonb), :key, :available_at) "
            "ON CONFLICT (idempotency_key) DO NOTHING"
        ),
        {
            "id": str(outbox_id),
            "topic": topic,
            "payload": payload_json(payload),
            "key": idempotency_key,
            "available_at": available_at or datetime.now(UTC),
        },
    )
    return outbox_id


class OutboxDispatcher:
    """Dispatch committed intents through the constrained database API."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine
        self._allow_owner_fallback = False

    def allow_owner_fallback_for_development(self) -> None:
        """Enable compatibility for metadata-only local test databases."""
        self.set_owner_fallback_for_development(True)

    def set_owner_fallback_for_development(self, enabled: bool) -> None:
        """Explicitly select or revoke the owner-only compatibility path."""
        self._allow_owner_fallback = bool(enabled)

    def dispatch_audit(self, *, limit: int = 100) -> int:
        try:
            with self._engine.begin() as connection:
                return int(
                    connection.scalar(
                        text("SELECT kp_dispatch_pending_audit(CAST(:limit AS integer))"),
                        {"limit": max(1, limit)},
                    )
                    or 0
                )
        except DBAPIError as exc:
            _log_database_failure("outbox_audit_dispatch_failed", exc)
            raise

    def dispatch_queue(self, queue: Any, *, limit: int = 100) -> int:
        sent = 0
        for _ in range(max(1, limit)):
            try:
                with self._engine.begin() as connection:
                    row = connection.execute(text("SELECT * FROM kp_claim_queue_outbox(1)")).mappings().one_or_none()
            except ProgrammingError as exc:
                if not self._allow_owner_fallback:
                    _log_database_failure("outbox_queue_claim_failed", exc)
                    raise
                with self._engine.begin() as connection:
                    row = (
                        connection.execute(
                            text(
                                "UPDATE transactional_outbox SET status = 'dispatching', "
                                "lease_until = now() + interval '60 seconds', attempts = attempts + 1 "
                                "WHERE outbox_id = (SELECT outbox_id FROM transactional_outbox "
                                "WHERE kind = 'queue' AND status IN ('pending', 'failed') AND available_at <= now() "
                                "ORDER BY created_at, outbox_id FOR UPDATE SKIP LOCKED LIMIT 1) "
                                "RETURNING outbox_id, topic, payload, idempotency_key, available_at"
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
            if row is None:
                break
            outbox_id = row["outbox_id"]
            try:
                queue.publish(
                    row["topic"],
                    dict(row["payload"]),
                    idempotency_key=row["idempotency_key"],
                    available_at=row["available_at"].timestamp(),
                )
            except Exception as exc:
                try:
                    with self._engine.begin() as connection:
                        if self._allow_owner_fallback:
                            connection.execute(
                                text(
                                    "UPDATE transactional_outbox SET status = 'failed', lease_until = NULL, "
                                    "available_at = now() + interval '30 seconds', "
                                    "last_error = :error WHERE outbox_id = :id"
                                ),
                                {"id": str(outbox_id), "error": _QUEUE_DISPATCH_FAILURE_CODE},
                            )
                        else:
                            connection.execute(
                                text("SELECT kp_fail_outbox(:id, :error)"),
                                {"id": outbox_id, "error": _QUEUE_DISPATCH_FAILURE_CODE},
                            )
                except DBAPIError as transition_exc:
                    _log_database_failure("outbox_queue_failure_transition_failed", transition_exc, outbox_id=outbox_id)
                    raise
                logger.error(
                    "outbox_queue_dispatch_failed exception_type=%s outbox_id=%s",
                    type(exc).__name__[:128],
                    outbox_id,
                )
                continue
            try:
                with self._engine.begin() as connection:
                    if self._allow_owner_fallback:
                        connection.execute(
                            text(
                                "UPDATE transactional_outbox SET status = 'dispatched', dispatched_at = now(), "
                                "lease_until = NULL WHERE outbox_id = :id"
                            ),
                            {"id": str(outbox_id)},
                        )
                    else:
                        # Preserve the driver's native UUID binding returned by
                        # the claim function. This is portable across psycopg
                        # prepare modes and avoids a varchar-only signature.
                        connection.execute(text("SELECT kp_complete_outbox(:id)"), {"id": outbox_id})
            except DBAPIError as exc:
                _log_database_failure("outbox_queue_completion_failed", exc, outbox_id=outbox_id)
                raise
            sent += 1
        return sent

    def reconcile_queue(
        self,
        queue: Any,
        *,
        topic: str,
        replay_safe: bool,
        window_seconds: int,
        limit: int = 500,
    ) -> dict[str, int]:
        """Audit recently-``dispatched`` queue rows against live queue existence.

        KP-AUD-007: ``dispatch_queue`` moves a row to the terminal ``dispatched``
        state the instant Redis accepts the publish. If Redis later loses that
        job (data loss / un-restored node), nothing reconstructs it — the health
        counter in ``reconcile`` deliberately excludes ``dispatched`` rows. This
        audit compares each recent ``dispatched`` row (identified by its stable
        ``idempotency_key``) against ``queue.job_published`` and, for rows the
        queue no longer remembers, applies a SAFE per-role replay rule:

        * ``replay_safe`` topics (reminder/alert and internal maintenance roles,
          all idempotent by key/token) are re-enqueued with their original
          idempotency key, preserving at-least-once semantics.
        * review-only topics (delivery/reply — an external send whose provider
          acceptance is unknown) are NEVER auto re-enqueued, because that could
          re-send an employee a duplicate simulated-phishing email. They are
          counted and surfaced for a human decision; no row is mutated.

        ``window_seconds`` bounds the audit to rows dispatched recently so a
        long-completed job whose dedup key has aged out of Redis is not mistaken
        for a loss. Returns non-sensitive counts only. This reads the outbox and
        may re-publish to the queue; it makes no external provider call and does
        not touch the PostgreSQL assignment-claim fence.
        """
        rows = self._claim_reconcilable_dispatched(topic=topic, window_seconds=window_seconds, limit=limit)
        checked = replayed = review_required = already_present = 0
        for row in rows:
            checked += 1
            idempotency_key = row["idempotency_key"]
            try:
                present = queue.job_published(topic, idempotency_key)
            except Exception:
                logger.error("outbox_queue_reconcile_lookup_failed topic=%s", topic)
                raise
            if present:
                already_present += 1
                continue
            if not replay_safe:
                review_required += 1
                logger.warning(
                    "outbox_queue_reconcile_review_required topic=%s outbox_id=%s",
                    topic,
                    row["outbox_id"],
                )
                continue
            available_at = row["available_at"]
            queue.publish(
                topic,
                dict(row["payload"]),
                idempotency_key=idempotency_key,
                available_at=available_at.timestamp() if available_at is not None else None,
            )
            replayed += 1
        if replayed or review_required:
            logger.warning(
                "outbox_queue_reconcile_completed topic=%s checked=%s replayed=%s review_required=%s present=%s",
                topic,
                checked,
                replayed,
                review_required,
                already_present,
            )
        return {
            "checked": checked,
            "replayed": replayed,
            "review_required": review_required,
            "present": already_present,
        }

    def _claim_reconcilable_dispatched(self, *, topic: str, window_seconds: int, limit: int) -> list[dict[str, Any]]:
        """Return recently-dispatched queue rows for one topic.

        Mirrors the ``dispatch_queue``/``reconcile`` access pattern: a future
        SECURITY DEFINER function (``kp_reconcile_queue_outbox``) is preferred so
        the least-privilege managed role never reads the restricted table
        directly; absent it, the owner/development fallback reads the table
        directly. The managed function + EXECUTE grant does not exist yet (it
        needs a migration — see the W1-03 report), so in a managed topology this
        raises ``ProgrammingError`` until that migration lands.
        """
        bounded_limit = max(1, min(limit, 5000))
        try:
            with self._engine.connect() as connection:
                return [
                    dict(row)
                    for row in connection.execute(
                        text(
                            "SELECT * FROM kp_reconcile_queue_outbox("
                            "CAST(:topic AS text), CAST(:window AS integer), CAST(:limit AS integer))"
                        ),
                        {"topic": topic, "window": max(1, window_seconds), "limit": bounded_limit},
                    )
                    .mappings()
                    .all()
                ]
        except ProgrammingError:
            if not self._allow_owner_fallback:
                raise
            with self._engine.connect() as connection:
                return [
                    dict(row)
                    for row in connection.execute(
                        text(
                            "SELECT outbox_id, topic, payload, idempotency_key, available_at, dispatched_at "
                            "FROM transactional_outbox "
                            "WHERE kind = 'queue' AND status = 'dispatched' AND topic = :topic "
                            "AND dispatched_at IS NOT NULL "
                            "AND dispatched_at >= now() - make_interval(secs => :window) "
                            "ORDER BY dispatched_at DESC, outbox_id LIMIT :limit"
                        ),
                        {"topic": topic, "window": max(1, window_seconds), "limit": bounded_limit},
                    )
                    .mappings()
                    .all()
                ]

    def reconcile(self) -> dict[str, int]:
        try:
            with self._engine.connect() as connection:
                row = connection.execute(text("SELECT * FROM kp_outbox_health()")).mappings().one()
        except ProgrammingError:
            if not self._allow_owner_fallback:
                raise
            with self._engine.connect() as connection:
                row = (
                    connection.execute(
                        text(
                            "SELECT count(*) FILTER (WHERE status = 'pending') AS pending, "
                            "count(*) FILTER (WHERE status = 'pending' "
                            "AND available_at <= now() - interval '1 minute') AS overdue_pending, "
                            "count(*) FILTER (WHERE status = 'pending' "
                            "AND available_at > now() - interval '1 minute') AS scheduled_or_fresh, "
                            "count(*) FILTER (WHERE status = 'failed') AS failed, "
                            "count(*) FILTER (WHERE status = 'dispatching' AND lease_until < now()) "
                            "AS dispatching_stale FROM transactional_outbox WHERE status <> 'dispatched'"
                        )
                    )
                    .mappings()
                    .one()
                )
        return {key: int(value or 0) for key, value in row.items()}


def dispatch_after_commit(session: Session, callback: Any) -> None:
    """Run a best-effort dispatcher once after this transaction commits."""

    # Lightweight unit-test doubles do not implement SQLAlchemy's event
    # target protocol. Production call sites are typed/constrained to Session.
    if not isinstance(session, Session):
        return

    def _dispatch(_session: Session) -> None:
        try:
            callback()
        except Exception as exc:
            logger.error(
                "post_commit_outbox_dispatch_failed reason_code=callback_failed sqlstate_class=%s exception_type=%s",
                _sqlstate_class(exc),
                type(exc).__name__[:128],
            )

    event.listen(session, "after_commit", _dispatch, once=True)


def payload_json(payload: dict[str, Any]) -> str:
    """Stable helper retained for database-driver fakes in focused tests."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
