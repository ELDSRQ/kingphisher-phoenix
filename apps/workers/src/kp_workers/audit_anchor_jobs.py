"""Periodic publication of a stable, verified, read-back-checked audit head."""

from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime
from typing import Any, Protocol

from kp_database.audit_store import AuditHeadSnapshot
from kp_telemetry.logging import get_logger

from kp_workers.config import AuditAnchorProviderKind
from kp_workers.jobs import WorkerContext
from kp_workers.providers.audit_anchor import (
    AuditAnchor,
    AzureBlobAuditAnchorProvider,
    LocalWormAuditAnchorProvider,
)

logger = get_logger("kp_workers.audit_anchor")

#: How many recently-published anchors to re-verify against the live chain
#: before publishing a new one.
_READ_BACK_ANCHORS = 8


class AuditIntegrityUnhealthyError(RuntimeError):
    """The audit chain cannot safely be anchored."""


class AuditAnchorReadBackError(RuntimeError):
    """A previously published anchor no longer matches the live audit chain.

    This means either the chain was rewritten under a witnessed head or the
    anchor store was tampered with. Neither is transient, so the worker
    supervisor must dead-letter this rather than retry it.
    """

    retryable = False


class _AnchorProvider(Protocol):
    def publish(self, anchor: AuditAnchor) -> str: ...

    def read_recent(self, limit: int) -> list[AuditAnchor]: ...

    def __enter__(self) -> _AnchorProvider: ...

    def __exit__(self, *args: object) -> None: ...


def ensure_audit_anchor_configured(ctx: WorkerContext) -> None:
    """Validate static configuration without claiming live provider readiness."""

    ctx.settings.require_audit_anchor_provider_ready()


def _as_anchor(snapshot: AuditHeadSnapshot) -> AuditAnchor:
    return AuditAnchor(snapshot.sequence, snapshot.event_hash, snapshot.signed_at)


#: How many times to re-verify when the head advances mid-check before giving up.
_VERIFY_STABILITY_ATTEMPTS = 6


def verified_audit_head(ctx: WorkerContext) -> AuditAnchor:
    """Return only a chain head that remained stable throughout verification.

    Concurrent audit appends (e.g. the API's periodic outbox dispatch) can advance
    the head between the two snapshots. That is healthy activity, not corruption,
    so retry a bounded number of times to catch a window where the head is briefly
    stable rather than failing the anchor on the first race. A genuine integrity
    problem or a missing head still fails closed immediately.
    """

    for _ in range(_VERIFY_STABILITY_ATTEMPTS):
        before = ctx.audit_store.head_snapshot()
        problems = ctx.audit_store.verify()
        after = ctx.audit_store.head_snapshot()
        if problems:
            raise AuditIntegrityUnhealthyError(f"audit integrity verification failed ({len(problems)} problem(s))")
        if before is None or after is None:
            raise AuditIntegrityUnhealthyError("no signed audit head is available")
        if before == after:
            return _as_anchor(after)
    raise AuditIntegrityUnhealthyError("audit head did not stabilize during verification")


def _anchor_digest(anchor: AuditAnchor) -> str:
    """Stable hash binding a new anchor to its predecessor."""

    return hashlib.sha256(anchor.canonical_bytes()).hexdigest()


def _assert_recent_anchors_consistent(ctx: WorkerContext, recent: list[AuditAnchor]) -> None:
    """Fail closed (non-retryable) unless every recent anchor still holds.

    Two independent checks:
      1. Each anchored ``(sequence, event_hash)`` must still be reachable at
         exactly that position on the live chain — a witnessed head cannot later
         move or disappear without tampering.
      2. Where the fetched window is contiguous, each anchor's
         ``previous_anchor_hash`` must match the digest of its predecessor, so
         the anchor chain itself is intact.
    """

    checkable = [anchor for anchor in recent if anchor.sequence >= 1]
    if checkable:
        positions = ctx.audit_store.hashes_by_sequence({anchor.sequence for anchor in checkable})
        for anchor in checkable:
            chain_hash = positions.get(anchor.sequence)
            if chain_hash is None or not hmac.compare_digest(chain_hash, anchor.event_hash):
                raise AuditAnchorReadBackError("a previously anchored head is no longer on the audit chain")

    # ``recent`` is the newest contiguous run of anchors; sort ascending so each
    # neighbour is the other's immediate predecessor.
    ordered = sorted(recent, key=lambda anchor: anchor.sequence)
    for predecessor, successor in zip(ordered, ordered[1:], strict=False):
        expected = successor.previous_anchor_hash
        if expected is not None and not hmac.compare_digest(expected, _anchor_digest(predecessor)):
            raise AuditAnchorReadBackError("published audit anchor chain is broken")


def anchor_verified_head(ctx: WorkerContext, provider: _AnchorProvider) -> str:
    try:
        head = verified_audit_head(ctx)
    except AuditIntegrityUnhealthyError:
        # An entirely empty chain (no events, no signed head) is the valid initial
        # state — there is simply nothing to witness yet — so treat it as a healthy
        # no-op rather than a failure. A non-empty but head-less/inconsistent chain
        # is genuine corruption and still raises.
        if ctx.audit_store.is_chain_empty():
            logger.info("audit_anchor_skipped", reason="empty_chain")
            return "empty"
        raise

    # Read-back: re-verify already-published anchors against the live chain
    # BEFORE witnessing a new head. A mismatch is tamper-relevant and fails
    # closed without publishing (non-retryable).
    recent = list(provider.read_recent(_READ_BACK_ANCHORS))
    _assert_recent_anchors_consistent(ctx, recent)

    # The newest published anchor already witnesses this exact head.
    # Rebuilding it would chain the anchor to itself (previous_anchor_hash =
    # digest of the anchor for this same head), producing the same immutable
    # key with different content — a permanent, non-retryable collision.
    # An unchanged head is a successful verified anchoring pass, so record
    # the freshness heartbeat and return the idempotent "exists" outcome.
    if recent and recent[0].sequence == head.sequence and hmac.compare_digest(recent[0].event_hash, head.event_hash):
        logger.info("audit_anchor_published", outcome="exists")
        _record_anchor_heartbeat(ctx)
        return "exists"

    # Chain the new anchor to the newest existing one so the anchors themselves
    # form a tamper-evident sequence (``None`` for the very first anchor).
    previous_anchor_hash = _anchor_digest(recent[0]) if recent else None
    anchor = AuditAnchor(
        sequence=head.sequence,
        event_hash=head.event_hash,
        signed_at=head.signed_at,
        previous_anchor_hash=previous_anchor_hash,
    )
    result = provider.publish(anchor)
    logger.info("audit_anchor_published", outcome=result)
    # Witness-freshness heartbeat (AUD-003). Written for both provider backends
    # via this shared path, on both "created" and "exists" (an unchanged head is
    # still a successful verified anchoring pass). Best-effort: the durable
    # witness is already published, so a Redis blip must never fail the job.
    if result in ("created", "exists"):
        _record_anchor_heartbeat(ctx)
    return result


def _record_anchor_heartbeat(ctx: WorkerContext) -> None:
    record = getattr(ctx.queue, "record_audit_anchor_heartbeat", None)
    if record is None:
        return
    try:
        record(datetime.now(UTC))
    except Exception:  # noqa: BLE001 - heartbeat is advisory; never fail a published anchor
        logger.warning("audit_anchor_heartbeat_write_failed")


def _select_anchor_provider(ctx: WorkerContext) -> _AnchorProvider:
    if ctx.settings.audit_anchor_provider_kind is AuditAnchorProviderKind.LOCAL_WORM:
        return LocalWormAuditAnchorProvider(ctx.settings.require_local_audit_anchor_dir())
    container_url, client_id = ctx.settings.require_audit_anchor_configured()
    return AzureBlobAuditAnchorProvider(
        container_url,
        managed_identity_client_id=client_id,
        timeout=ctx.settings.provider_timeout_seconds,
    )


def process_audit_anchor(ctx: WorkerContext, _message: dict[str, Any]) -> None:
    provider = _select_anchor_provider(ctx)
    with provider:
        anchor_verified_head(ctx, provider)


def maybe_publish_audit_anchor(ctx: WorkerContext, now: datetime) -> None:
    interval = ctx.settings.audit_anchor_interval_seconds
    bucket = int(now.timestamp()) // interval
    ctx.queue.publish("audit-anchor", {}, idempotency_key=f"audit-anchor:{bucket}")
