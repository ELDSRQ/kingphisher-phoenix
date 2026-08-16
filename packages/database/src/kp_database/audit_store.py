"""Append-only audit store.

Writes flow through the dedicated AUDIT_DATABASE_URL connection which is
granted INSERT-only on `audit_events` (see infrastructure/terraform and the
Alembic migration for role/grants). The application ORM session never touches
this table. Chaining + head signing come from kp-auditing; this module owns
persistence, including the persisted HMAC-signed chain head.
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
    verify_head_signature,
)
from kp_telemetry.errors import AuditFailureError
from sqlalchemy import text
from sqlalchemy.engine import Engine


class AuditStore:
    def __init__(self, engine: Engine, hmac_key: bytes | None = None) -> None:
        self._engine = engine
        self._writer = AuditWriter()
        self._hmac_key = hmac_key

    def record(
        self,
        *,
        actor: str,
        action: str,
        object_type: str,
        object_id: str,
        detail: dict[str, Any] | None = None,
        occurred_at: datetime | None = None,
    ) -> AuditRecord:
        detail = detail or {}
        occurred_at = occurred_at or datetime.now(UTC)
        try:
            with self._engine.begin() as conn:
                # All API and worker processes share this transaction-scoped
                # lock. Reading the head and appending while holding it prevents
                # concurrent writers from creating two children of one head.
                conn.execute(text("SELECT pg_advisory_xact_lock(1263551049)"))
                head = conn.execute(
                    text(
                        "SELECT h.event_hash FROM audit_chain_head h WHERE h.id = 1 "
                        "AND EXISTS (SELECT 1 FROM audit_events e WHERE e.event_hash = h.event_hash)"
                    )
                ).scalar()
                self._writer.reset_to(head or GENESIS_HASH)
                record = self._writer.append(
                    actor=actor,
                    action=action,
                    object_type=object_type,
                    object_id=object_id,
                    outcome="success",
                    detail=detail,
                    occurred_at=occurred_at,
                )
                signature = self.sign_head(record.event_hash) if self._hmac_key is not None else None
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
                conn.execute(
                    text(
                        "INSERT INTO audit_chain_head (id, event_hash, signature, signed_at) "
                        "VALUES (1, :event_hash, :signature, now()) "
                        "ON CONFLICT (id) DO UPDATE SET "
                        "event_hash = EXCLUDED.event_hash, "
                        "signature = EXCLUDED.signature, "
                        "signed_at = EXCLUDED.signed_at"
                    ),
                    {"event_hash": record.event_hash, "signature": signature},
                )
        except Exception as exc:  # noqa: BLE001 - convert to domain error
            raise AuditFailureError("audit write failed") from exc
        return record

    def sign_head(self, event_hash: str) -> str:
        if self._hmac_key is None:
            raise RuntimeError("audit HMAC key not configured")
        return sign_head(event_hash, self._hmac_key)

    def list_events(self, limit: int = 500) -> list[dict[str, Any]]:
        """Recent events newest-first, for the operator audit view."""
        with self._engine.connect() as conn:
            rows = (
                conn.execute(
                    text(
                        "SELECT actor, action, object_type, object_id, occurred_at, detail "
                        "FROM audit_events ORDER BY occurred_at DESC, event_hash DESC LIMIT :limit"
                    ),
                    {"limit": limit},
                )
                .mappings()
                .all()
            )
        return [dict(row) for row in rows]

    def verify(self) -> list[str]:
        """Recompute the chain and report mismatches, including a missing or
        tampered persisted head signature.

        Chain order is reconstructed from hash links rather than timestamps.
        This detects forks, disconnected rows, cycles, and missing ancestors
        without assuming clocks provide insertion order.
        """
        problems: list[str] = []
        with self._engine.connect() as conn:
            rows = (
                conn.execute(
                    text(
                        "SELECT actor, action, object_type, object_id, occurred_at, detail, "
                        "prev_hash, event_hash, nonce FROM audit_events"
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
        if not rows:
            return problems
        by_prev: dict[str, list[Any]] = {}
        for row in rows:
            by_prev.setdefault(row["prev_hash"], []).append(row)
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
        if head is None:
            problems.append("no persisted signed audit head")
        elif head["signature"] is None:
            problems.append("audit head signature missing")
        else:
            if head["event_hash"] != current:
                problems.append(f"audit head references {head['event_hash']} but chain ends at {current}")
            if self._hmac_key is not None and not verify_head_signature(
                head["event_hash"], head["signature"], self._hmac_key
            ):
                problems.append("audit head signature verification failed")
        return problems
