"""Hash chaining for the append-only audit trail.

Implements the reconstructed spec §14:
- INSERT-only storage (the caller enforces DB grants; this module never edits).
- Each event carries prev_hash + event_hash where
    event_hash = sha256(prev_hash || canonical_event_bytes || nonce)
- A verifier recomputes the chain and reports the first break.
- The chain head can be signed for offline verification (used by the daily
  integrity job).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

GENESIS_HASH = "0" * 64
_HMAC_KEY_LEN = 32


def canonical_bytes(actor: str, action: str, object_type: str, object_id: str,
                    occurred_at: datetime, detail: dict[str, Any]) -> bytes:
    """Deterministic canonical encoding for hashing (field order fixed)."""
    occurred = occurred_at if occurred_at.tzinfo else occurred_at.replace(tzinfo=UTC)
    parts = [
        actor,
        action,
        object_type,
        object_id,
        occurred.astimezone(UTC).isoformat(timespec="microseconds"),
    ]
    for key in sorted(detail):
        parts.append(f"{key}={_stable_str(detail[key])}")
    return "\x1f".join(parts).encode("utf-8")


def _stable_str(value: Any) -> str:
    import json

    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    if isinstance(value, UUID):
        return str(value)
    return str(value)


def chain_hash(prev_hash: str, body: bytes, nonce: str) -> str:
    digest = hashlib.sha256()
    digest.update(prev_hash.encode("ascii"))
    digest.update(body)
    digest.update(nonce.encode("ascii"))
    return digest.hexdigest()


def make_nonce() -> str:
    return secrets.token_hex(16)


@dataclass
class AuditRecord:
    """A single chained audit entry as produced by the writer."""

    actor: str
    action: str
    object_type: str
    object_id: str
    occurred_at: datetime
    detail: dict[str, Any]
    outcome: str
    prev_hash: str
    event_hash: str
    nonce: str
    audit_event_id: UUID = field(default_factory=uuid4)

    @property
    def body_bytes(self) -> bytes:
        return canonical_bytes(
            self.actor, self.action, self.object_type, self.object_id,
            self.occurred_at, self.detail,
        )

    def as_row(self) -> dict[str, Any]:
        return {
            "audit_event_id": self.audit_event_id,
            "actor": self.actor,
            "action": self.action,
            "object_type": self.object_type,
            "object_id": self.object_id,
            "outcome": self.outcome,
            "occurred_at": self.occurred_at,
            "detail": self.detail,
            "prev_hash": self.prev_hash,
            "event_hash": self.event_hash,
            "nonce": self.nonce,
        }


class AuditWriter:
    """Produces hash-chained audit records. The caller owns persistence; this
    object only constructs records. Persisting via an INSERT-only DB path is
    enforced at the storage layer (see kp_database.audit_store)."""

    def __init__(self, prev_hash: str = GENESIS_HASH) -> None:
        self._prev_hash = prev_hash
        self._hmac_key: bytes | None = None

    def enable_hmac(self, key: bytes) -> None:
        if len(key) < _HMAC_KEY_LEN:
            raise ValueError("HMAC key must be at least 32 bytes")
        self._hmac_key = key

    def reset_to(self, prev_hash: str) -> None:
        self._prev_hash = prev_hash

    @property
    def prev_hash(self) -> str:
        return self._prev_hash

    def append(self, actor: str, action: str, object_type: str, object_id: str,
               outcome: str = "success", detail: dict[str, Any] | None = None,
               occurred_at: datetime | None = None) -> AuditRecord:
        detail = dict(detail or {})
        occurred_at = occurred_at or datetime.now(UTC)
        nonce = make_nonce()
        body = canonical_bytes(actor, action, object_type, object_id, occurred_at, detail)
        event_hash = chain_hash(self._prev_hash, body, nonce)
        record = AuditRecord(
            actor=actor,
            action=action,
            object_type=object_type,
            object_id=object_id,
            occurred_at=occurred_at,
            detail=detail,
            outcome=outcome,
            prev_hash=self._prev_hash,
            event_hash=event_hash,
            nonce=nonce,
        )
        self._prev_hash = event_hash
        return record


@dataclass
class VerificationResult:
    ok: bool
    checked: int
    first_break_at: int | None = None
    message: str = ""


class AuditVerifier:
    """Recomputes the chain from a sequence of records and finds the first break.

    Records must be supplied in insertion order (by `audit_event_id` as persisted).
    """

    def verify(self, records: Sequence[AuditRecord] | Iterable[dict[str, Any]],
               genesis: str = GENESIS_HASH) -> VerificationResult:
        expected = genesis
        count = 0
        for raw in records:
            record = raw if isinstance(raw, AuditRecord) else _record_from_dict(raw)
            body = record.body_bytes
            computed = chain_hash(expected, body, record.nonce)
            if computed != record.event_hash:
                return VerificationResult(
                    ok=False,
                    checked=count,
                    first_break_at=count,
                    message=f"chain broken at index {count} (expected {record.event_hash}, got {computed})",
                )
            if record.prev_hash != expected:
                return VerificationResult(
                    ok=False,
                    checked=count,
                    first_break_at=count,
                    message=f"prev_hash mismatch at index {count}",
                )
            expected = record.event_hash
            count += 1
        return VerificationResult(ok=True, checked=count)


def sign_head(event_hash: str, signing_key: bytes) -> str:
    """HMAC-SHA256 signature of the latest chain head (used by the daily job)."""
    return hmac.new(signing_key, event_hash.encode("ascii"), hashlib.sha256).hexdigest()


def verify_head_signature(event_hash: str, signature: str, signing_key: bytes) -> bool:
    expected = sign_head(event_hash, signing_key)
    return hmac.compare_digest(expected, signature)


def _record_from_dict(raw: dict[str, Any]) -> AuditRecord:
    return AuditRecord(
        actor=raw["actor"],
        action=raw["action"],
        object_type=raw["object_type"],
        object_id=raw["object_id"],
        occurred_at=raw["occurred_at"],
        detail=dict(raw.get("detail") or {}),
        outcome=raw.get("outcome", "success"),
        prev_hash=raw["prev_hash"],
        event_hash=raw["event_hash"],
        nonce=raw["nonce"],
        audit_event_id=raw.get("audit_event_id", UUID(int=0)),
    )
