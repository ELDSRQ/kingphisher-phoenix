#!/usr/bin/env python3
"""Initialize the database audit root for a verified local legacy chain.

Migration 0020 moved audit signing into PostgreSQL.  A local database upgraded
from an earlier revision can already contain version-1 events signed by the
development HMAC key, while the new database-resident root is still empty.
This bootstrap adopts that key only after independently verifying every event,
the single unbroken genesis chain, its persisted head, and the head signature.
It never repairs, rewrites, or resets audit evidence.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from dotenv import load_dotenv
from kp_auditing.audit import GENESIS_HASH, canonical_bytes, chain_hash
from kp_database.session import create_db_engine
from sqlalchemy import text

ROOT = Path(__file__).resolve().parents[1]
if os.environ.get("KP_DISABLE_DOTENV") != "1":
    load_dotenv(ROOT / ".env", override=False)


class LocalAuditBootstrapError(RuntimeError):
    """The local audit root cannot be initialized without trusting bad evidence."""


def _converge_local_audit_writer(connection: Any) -> None:
    """Apply the minimum local dispatcher grants revoked by migration 0020."""
    connection.execute(text("GRANT USAGE ON SCHEMA public TO audit_writer"))
    connection.execute(text("GRANT SELECT ON TABLE audit_events, audit_chain_head TO audit_writer"))
    connection.execute(
        text(
            "GRANT EXECUTE ON FUNCTION kp_dispatch_audit_outbox(uuid), "
            "kp_dispatch_pending_audit(integer), kp_claim_queue_outbox(integer), "
            "kp_complete_outbox(uuid), kp_fail_outbox(uuid,text), kp_outbox_health(), "
            "kp_verify_audit_head() TO audit_writer"
        )
    )
    connection.execute(
        text("REVOKE ALL PRIVILEGES ON TABLE audit_integrity_secret, transactional_outbox FROM audit_writer")
    )


def _configured_key() -> tuple[str, bytes]:
    key_hex = os.environ.get("OPERATOR_API_AUDIT_HMAC_KEY", "")
    try:
        key = bytes.fromhex(key_hex)
    except ValueError as exc:
        raise LocalAuditBootstrapError("local audit HMAC key must be hexadecimal") from exc
    if len(key) != 32 or len(key_hex) != 64:
        raise LocalAuditBootstrapError("local audit HMAC key must be 256-bit")
    return key_hex.lower(), key


def _require_local_database(database_url: str) -> None:
    engine = create_db_engine(database_url)
    url = engine.url
    engine.dispose()
    host = (url.host or "").lower()
    database = unquote(url.database or "")
    if host not in {"localhost", "127.0.0.1", "::1"} or database != "kingphisher":
        raise LocalAuditBootstrapError(
            "audit-root bootstrap is restricted to the loopback kingphisher development database"
        )


def verify_legacy_chain(
    rows: Sequence[Mapping[str, Any]],
    head: Mapping[str, Any] | None,
    signing_key: bytes,
) -> None:
    """Reject any legacy evidence that cannot be proven under ``signing_key``."""
    if not rows:
        if head is not None:
            raise LocalAuditBootstrapError("empty audit chain has an unexpected persisted head")
        return

    by_previous: dict[str, list[Mapping[str, Any]]] = {}
    for row in rows:
        if row["chain_version"] != 1:
            raise LocalAuditBootstrapError("unrooted audit evidence contains a non-legacy chain version")
        body = canonical_bytes(
            actor=row["actor"],
            action=row["action"],
            object_type=row["object_type"],
            object_id=row["object_id"],
            occurred_at=row["occurred_at"],
            detail=row["detail"],
        )
        expected = chain_hash(prev_hash=row["prev_hash"], body=body, nonce=row["nonce"])
        if not hmac.compare_digest(expected, row["event_hash"]):
            raise LocalAuditBootstrapError("legacy audit event hash verification failed")
        by_previous.setdefault(row["prev_hash"], []).append(row)

    current = GENESIS_HASH
    visited: set[str] = set()
    while children := by_previous.get(current, []):
        if len(children) != 1:
            raise LocalAuditBootstrapError("legacy audit chain is forked")
        event_hash = children[0]["event_hash"]
        if event_hash in visited:
            raise LocalAuditBootstrapError("legacy audit chain contains a cycle")
        visited.add(event_hash)
        current = event_hash
    if len(visited) != len(rows):
        raise LocalAuditBootstrapError("legacy audit chain contains disconnected evidence")
    if head is None or not hmac.compare_digest(head["event_hash"], current):
        raise LocalAuditBootstrapError("legacy audit head does not match the verified chain")
    expected_signature = hmac.new(signing_key, current.encode("ascii"), hashlib.sha256).hexdigest()
    signature = head.get("signature")
    if not isinstance(signature, str) or not hmac.compare_digest(signature, expected_signature):
        raise LocalAuditBootstrapError("legacy audit head signature verification failed")


def main() -> int:
    database_url = os.environ.get("DATABASE_URL", "")
    if not database_url:
        raise LocalAuditBootstrapError("DATABASE_URL is required")
    _require_local_database(database_url)
    key_hex, signing_key = _configured_key()
    engine = create_db_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(text("SELECT pg_advisory_xact_lock(1263551050)"))
            installed = connection.scalar(
                text("SELECT key_hex FROM audit_integrity_secret WHERE singleton_id = 1 FOR UPDATE")
            )
            if installed is not None:
                if not connection.scalar(text("SELECT kp_verify_audit_head()")):
                    raise LocalAuditBootstrapError("installed local audit root does not verify the audit head")
                _converge_local_audit_writer(connection)
                print("local audit root already initialized and verified")
                return 0

            rows = (
                connection.execute(
                    text(
                        "SELECT actor, action, object_type, object_id, occurred_at, detail, prev_hash, "
                        "event_hash, nonce, chain_version FROM audit_events"
                    )
                )
                .mappings()
                .all()
            )
            head = (
                connection.execute(text("SELECT event_hash, signature FROM audit_chain_head WHERE id = 1"))
                .mappings()
                .one_or_none()
            )
            verify_legacy_chain(rows, head, signing_key)
            connection.execute(
                text(
                    "INSERT INTO audit_integrity_secret (singleton_id, key_hex) VALUES (1, :key) "
                    "ON CONFLICT (singleton_id) DO NOTHING"
                ),
                {"key": key_hex},
            )
            if not connection.scalar(text("SELECT kp_verify_audit_head()")):
                raise LocalAuditBootstrapError("new local audit root did not verify the audit head")
            _converge_local_audit_writer(connection)
        print("local audit root initialized after legacy evidence verification")
        return 0
    finally:
        engine.dispose()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LocalAuditBootstrapError as exc:
        raise SystemExit(
            f"local audit bootstrap refused: {exc}; preserve the database for investigation or reset the "
            "explicitly disposable local kingphisher database"
        ) from None
