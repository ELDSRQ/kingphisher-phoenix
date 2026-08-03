"""Append-only audit store.

Writes flow through the dedicated AUDIT_DATABASE_URL connection which is
granted INSERT-only on `audit_events` (see infrastructure/terraform and the
Alembic migration for role/grants). The application ORM session never touches
this table. Chaining + head signing come from kp-auditing; this module only
owns persistence.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from kp_auditing.audit import (
    GENESIS_HASH,
    AuditRecord,
    AuditWriter,
    canonical_bytes,
    chain_hash,
    sign_head,
)
from kp_telemetry.errors import AuditFailureError
from sqlalchemy import text
from sqlalchemy.engine import Engine


class AuditStore:
    def __init__(self, engine: Engine, hmac_key: bytes | None = None) -> None:
        self._engine = engine
        self._writer = AuditWriter()
        self._hmac_key = hmac_key

    def _resume_chain(self) -> None:
        """Link into the persisted chain head so multiple processes (operator
        API + each worker) append to the same hash chain instead of each
        starting from genesis."""
        head: str | None = None
        with self._engine.connect() as conn:
            head = conn.execute(
                text("SELECT event_hash FROM audit_events ORDER BY occurred_at DESC, event_hash DESC LIMIT 1")
            ).scalar()
        if head is not None:
            self._writer.reset_to(head)

    def record(self, *, actor: str, action: str, object_type: str, object_id: str,
               detail: dict[str, Any] | None = None, occurred_at: datetime | None = None) -> AuditRecord:
        self._resume_chain()
        detail = detail or {}
        occurred_at = occurred_at or datetime.now(UTC)
        record = self._writer.append(
            actor=actor,
            action=action,
            object_type=object_type,
            object_id=object_id,
            outcome="success",
            detail=detail,
            occurred_at=occurred_at,
        )
        try:
            with self._engine.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO audit_events "
                        "(audit_event_id, actor, action, object_type, object_id, outcome, "
                        " occurred_at, detail, prev_hash, event_hash, nonce) "
                        "VALUES (:id, :actor, :action, :object_type, :object_id, :outcome, "
                        " :occurred_at, CAST(:detail AS jsonb), :prev_hash, :event_hash, :nonce)"
                    ),
                    {
                        "id": str(record.audit_event_id),
                        "actor": record.actor,
                        "action": record.action,
                        "object_type": record.object_type,
                        "object_id": record.object_id,
                        "outcome": record.outcome,
                        "occurred_at": record.occurred_at,
                        "detail": json.dumps(record.detail, default=str),
                        "prev_hash": record.prev_hash,
                        "event_hash": record.event_hash,
                        "nonce": record.nonce,
                    },
                )
        except Exception as exc:  # noqa: BLE001 - convert to domain error
            raise AuditFailureError("audit write failed") from exc
        return record

    def sign_head(self, event_hash: str) -> str:
        if self._hmac_key is None:
            raise RuntimeError("audit HMAC key not configured")
        return sign_head(event_hash, self._hmac_key)

    def verify(self) -> list[str]:
        """Recompute the chain and report mismatches.

        Rows are ordered by `occurred_at, event_hash` as a deterministic proxy
        for insertion order (there is no monotonic column). Checks that the
        first row links to the genesis hash, every row's `prev_hash` equals the
        prior row's `event_hash`, and every row's `event_hash` is recomputable.
        """
        problems: list[str] = []
        with self._engine.connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT actor, action, object_type, object_id, occurred_at, detail, "
                    "prev_hash, event_hash, nonce FROM audit_events ORDER BY occurred_at, event_hash"
                )
            ).mappings().all()
        if not rows:
            return problems
        prev = GENESIS_HASH
        for row in rows:
            if row["prev_hash"] != prev:
                problems.append(
                    f"prev_hash mismatch at {row['occurred_at']} {row['actor']}:{row['action']} "
                    f"(expected {prev}, got {row['prev_hash']})"
                )
            body = canonical_bytes(
                actor=row["actor"],
                action=row["action"],
                object_type=row["object_type"],
                object_id=row["object_id"],
                occurred_at=row["occurred_at"],
                detail=row["detail"],
            )
            recomputed = chain_hash(
                prev_hash=row["prev_hash"],
                body=body,
                nonce=row["nonce"],
            )
            if recomputed != row["event_hash"]:
                problems.append(f"hash mismatch at {row['occurred_at']} {row['actor']}:{row['action']}")
            prev = row["event_hash"]
        return problems
