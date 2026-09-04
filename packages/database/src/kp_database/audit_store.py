"""Append-only audit facade backed by a transactional database outbox."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from kp_auditing.audit import GENESIS_HASH, AuditRecord, AuditWriter, canonical_bytes, chain_hash, sign_head
from kp_telemetry.errors import AuditFailureError
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.orm import Session

from kp_database.outbox import OutboxDispatcher, dispatch_after_commit, enqueue_audit


@dataclass(frozen=True)
class AuditHeadSnapshot:
    """Minimal non-PII state needed to witness the signed audit head."""

    sequence: int
    event_hash: str
    signed_at: datetime


class AuditStore:
    """Stages caller-authenticated intent and reads immutable audit evidence."""

    def __init__(
        self,
        engine: Engine,
        hmac_key: bytes | None = None,
        *,
        intent_engine: Engine | None = None,
    ) -> None:
        self._engine = engine
        self._legacy_hmac_key = hmac_key
        self._intent_engine = intent_engine or engine
        self._dispatcher = OutboxDispatcher(engine)
        self._allow_owner_fallback = hmac_key is not None and intent_engine is None
        self._dispatcher.set_owner_fallback_for_development(self._allow_owner_fallback)

    def bind_intent_engine(self, engine: Engine) -> None:
        """Bind the least-privilege business connection used to stage intent."""
        self._intent_engine = engine
        # Metadata-only tests and the offline demo historically use one owner
        # URL and create tables without Alembic functions. Managed deployments
        # use distinct URLs and never enable this compatibility path.
        self._allow_owner_fallback = bool(self._legacy_hmac_key) and engine.url == self._engine.url
        # Construction can temporarily enable the metadata-only path before a
        # service binds its distinct business engine. Revoke that capability as
        # soon as the managed/migrated topology is known; otherwise queue
        # completion bypasses the SECURITY DEFINER function and fails against
        # the intentionally privilege-revoked outbox table.
        self._dispatcher.set_owner_fallback_for_development(self._allow_owner_fallback)

    def record(
        self,
        *,
        actor: str,
        action: str,
        object_type: str,
        object_id: str,
        detail: dict[str, Any] | None = None,
        occurred_at: datetime | None = None,
        session: Session | None = None,
        idempotency_key: str | None = None,
    ) -> AuditRecord:
        """Stage audit intent; pass the business session for atomic mutation."""
        try:
            if session is not None:
                _, receipt = enqueue_audit(
                    session,
                    actor=actor,
                    action=action,
                    object_type=object_type,
                    object_id=object_id,
                    detail=detail,
                    occurred_at=occurred_at,
                    idempotency_key=idempotency_key,
                )
                dispatch_after_commit(session, self.dispatch_pending_audit)
                return receipt
            from kp_database.session import make_session_factory

            with make_session_factory(self._intent_engine)() as owned:
                outbox_id, receipt = enqueue_audit(
                    owned,
                    actor=actor,
                    action=action,
                    object_type=object_type,
                    object_id=object_id,
                    detail=detail,
                    occurred_at=occurred_at,
                    idempotency_key=idempotency_key,
                )
                owned.commit()
            self.dispatch_pending_audit()
            return self._record_for_outbox(outbox_id) or receipt
        except Exception as exc:
            # TEMP DIAGNOSTIC (staging KP-008): the mapped 503 handler does not
            # log the chained cause, so surface a bounded DB error string here to
            # pin the audit-intent write failure. Remove after diagnosis.
            try:
                from kp_telemetry.logging import get_logger

                get_logger("kp_database.audit").error(
                    "audit_intent_write_failed_detail",
                    error_type=type(exc).__name__[:64],
                    error_detail=str(exc)[:400],
                )
            except Exception:  # noqa: S110 - diagnostic logging must never mask the real error
                pass
            raise AuditFailureError("audit intent write failed") from exc

    def dispatch_pending_audit(self) -> int:
        try:
            return self._dispatcher.dispatch_audit()
        except ProgrammingError:
            if not self._allow_owner_fallback or self._legacy_hmac_key is None:
                raise
            return self._dispatch_development_audit()

    def _dispatch_development_audit(self) -> int:
        """Legacy owner-only fallback for metadata-created local test DBs."""
        signing_key = self._legacy_hmac_key
        if signing_key is None:
            raise RuntimeError("development audit fallback requires an HMAC key")
        dispatched = 0
        with self._engine.begin() as connection:
            connection.execute(text("SELECT pg_advisory_xact_lock(1263551049)"))
            head = (
                connection.scalar(
                    text(
                        "SELECT h.event_hash FROM audit_chain_head h WHERE h.id = 1 "
                        "AND EXISTS (SELECT 1 FROM audit_events e WHERE e.event_hash = h.event_hash)"
                    )
                )
                or GENESIS_HASH
            )
            writer = AuditWriter(head)
            rows = (
                connection.execute(
                    text(
                        "SELECT outbox_id, origin_role, payload FROM transactional_outbox "
                        "WHERE kind = 'audit' AND status IN ('pending', 'failed') "
                        "ORDER BY created_at, outbox_id FOR UPDATE SKIP LOCKED LIMIT 100"
                    )
                )
                .mappings()
                .all()
            )
            for row in rows:
                payload = row["payload"]
                record = writer.append(
                    actor=payload["actor"],
                    action=payload["action"],
                    object_type=payload["object_type"],
                    object_id=payload["object_id"],
                    detail=payload.get("detail") or {},
                    occurred_at=datetime.fromisoformat(payload["occurred_at"]),
                )
                connection.execute(
                    text(
                        "INSERT INTO audit_events (audit_event_id, actor, action, object_type, object_id, outcome, "
                        "occurred_at, detail, prev_hash, event_hash, nonce, outbox_id, origin_role, chain_version) "
                        "VALUES (:event_id, :actor, :action, :object_type, :object_id, 'success', :occurred_at, "
                        "CAST(:detail AS jsonb), :prev_hash, :event_hash, :nonce, :outbox_id, :origin_role, 1)"
                    ),
                    {
                        **record.as_row(),
                        "event_id": str(record.audit_event_id),
                        "detail": json.dumps(record.detail, default=str),
                        "outbox_id": str(row["outbox_id"]),
                        "origin_role": row["origin_role"],
                    },
                )
                connection.execute(
                    text(
                        "INSERT INTO audit_chain_head (id, event_hash, signature, signed_at) "
                        "VALUES (1, :hash, :signature, now()) ON CONFLICT (id) DO UPDATE SET "
                        "event_hash = excluded.event_hash, signature = excluded.signature, signed_at = now()"
                    ),
                    {"hash": record.event_hash, "signature": sign_head(record.event_hash, signing_key)},
                )
                connection.execute(
                    text(
                        "UPDATE transactional_outbox SET status = 'dispatched', dispatched_at = now() "
                        "WHERE outbox_id = :id"
                    ),
                    {"id": str(row["outbox_id"])},
                )
                dispatched += 1
        return dispatched

    def dispatch_pending_queue(self, queue: Any) -> int:
        return self._dispatcher.dispatch_queue(queue)

    def _record_for_outbox(self, outbox_id: Any) -> AuditRecord | None:
        with self._engine.connect() as connection:
            row = (
                connection.execute(
                    text(
                        "SELECT audit_event_id, actor, action, object_type, object_id, occurred_at, detail, "
                        "outcome, prev_hash, event_hash, nonce FROM audit_events WHERE outbox_id = :id"
                    ),
                    {"id": str(outbox_id)},
                )
                .mappings()
                .one_or_none()
            )
        return AuditRecord(**dict(row)) if row is not None else None

    def outbox_health(self) -> dict[str, int]:
        return self._dispatcher.reconcile()

    def list_events(self, limit: int = 500) -> list[dict[str, Any]]:
        with self._engine.connect() as conn:
            rows = (
                conn.execute(
                    text(
                        "SELECT actor, action, object_type, object_id, occurred_at, detail, origin_role "
                        "FROM audit_events ORDER BY occurred_at DESC, event_hash DESC LIMIT :limit"
                    ),
                    {"limit": limit},
                )
                .mappings()
                .all()
            )
        return [dict(row) for row in rows]

    def head_snapshot(self) -> AuditHeadSnapshot | None:
        """Return the persisted signed-head coordinates without event data."""

        with self._engine.connect() as connection:
            row = (
                connection.execute(
                    text(
                        "SELECT (SELECT count(event_hash) FROM audit_events) AS sequence, "
                        "head.event_hash, head.signed_at FROM audit_chain_head AS head WHERE head.id = 1"
                    )
                )
                .mappings()
                .one_or_none()
            )
        if row is None:
            return None
        return AuditHeadSnapshot(
            sequence=int(row["sequence"]),
            event_hash=row["event_hash"],
            signed_at=row["signed_at"],
        )

    def is_chain_empty(self) -> bool:
        """True when no audit event and no signed head exist yet.

        This is the valid initial state before any evidence has been recorded;
        callers use it to distinguish "nothing to anchor yet" from a corrupt
        chain that is missing its head. Counts a granted column so a least-
        privilege reader (the audit-anchor role) can run it.
        """

        with self._engine.connect() as conn:
            events = conn.scalar(text("SELECT count(event_hash) FROM audit_events"))
            heads = conn.scalar(text("SELECT count(event_hash) FROM audit_chain_head WHERE id = 1"))
        return (events or 0) == 0 and (heads or 0) == 0

    def verify(self) -> list[str]:
        """Verify both chain generations and surface failed/stale intents."""
        problems: list[str] = []
        with self._engine.connect() as conn:
            rows = (
                conn.execute(
                    text(
                        "SELECT actor, action, object_type, object_id, occurred_at, detail, prev_hash, "
                        "event_hash, nonce, canonical_payload, chain_version FROM audit_events"
                    )
                )
                .mappings()
                .all()
            )
            head = (
                conn.execute(text("SELECT event_hash, signature FROM audit_chain_head WHERE id = 1"))
                .mappings()
                .one_or_none()
            )
            try:
                database_head_valid = conn.scalar(text("SELECT kp_verify_audit_head()"))
            except ProgrammingError:
                if not self._allow_owner_fallback:
                    raise
                database_head_valid = None
        by_prev: dict[str, list[Any]] = {}
        for row in rows:
            by_prev.setdefault(row["prev_hash"], []).append(row)
            if row["chain_version"] == 2:
                canonical = row["canonical_payload"]
                recomputed = hashlib.sha256((row["prev_hash"] + canonical + row["nonce"]).encode("utf-8")).hexdigest()
            else:
                body = canonical_bytes(
                    actor=row["actor"],
                    action=row["action"],
                    object_type=row["object_type"],
                    object_id=row["object_id"],
                    occurred_at=row["occurred_at"],
                    detail=row["detail"],
                )
                recomputed = chain_hash(prev_hash=row["prev_hash"], body=body, nonce=row["nonce"])
            if recomputed != row["event_hash"]:
                problems.append(f"hash mismatch at {row['occurred_at']} {row['actor']}:{row['action']}")

        current = GENESIS_HASH
        visited: set[str] = set()
        while True:
            children = by_prev.get(current, [])
            if not children:
                break
            if len(children) != 1:
                problems.append(f"audit chain fork after {current}: {len(children)} children")
                break
            child = children[0]
            if child["event_hash"] in visited:
                problems.append(f"audit chain cycle at {child['event_hash']}")
                break
            visited.add(child["event_hash"])
            current = child["event_hash"]
        if len(visited) != len(rows):
            problems.append(f"audit chain has {len(rows) - len(visited)} disconnected row(s)")
        if database_head_valid is False:
            problems.append("audit head signature verification failed")
        if rows and head is None:
            problems.append("no persisted signed audit head")
        elif head is not None:
            if head["event_hash"] != current:
                problems.append(f"audit head references {head['event_hash']} but chain ends at {current}")
            if head["signature"] is None:
                problems.append("audit head signature missing")
            elif (
                database_head_valid is None
                and self._legacy_hmac_key is not None
                and all(row["chain_version"] == 1 for row in rows)
            ):
                expected = hmac.new(
                    self._legacy_hmac_key, head["event_hash"].encode("ascii"), hashlib.sha256
                ).hexdigest()
                if not hmac.compare_digest(expected, head["signature"]):
                    problems.append("audit head signature verification failed")
        try:
            health = self.outbox_health()
        except Exception as exc:
            problems.append(f"outbox reconciliation unavailable: {type(exc).__name__}")
        else:
            if health["overdue_pending"]:
                problems.append(f"outbox has {health['overdue_pending']} overdue pending intent(s)")
            if health["failed"]:
                problems.append(f"outbox has {health['failed']} failed intent(s)")
            if health["dispatching_stale"]:
                problems.append(f"outbox has {health['dispatching_stale']} stale dispatch(es)")
        return problems
