"""Periodic publication of a stable, verified audit-chain head."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol

from kp_database.audit_store import AuditHeadSnapshot
from kp_telemetry.logging import get_logger

from kp_workers.jobs import WorkerContext
from kp_workers.providers.audit_anchor import AuditAnchor, AzureBlobAuditAnchorProvider

logger = get_logger("kp_workers.audit_anchor")


class AuditIntegrityUnhealthyError(RuntimeError):
    """The audit chain cannot safely be anchored."""


class _AnchorProvider(Protocol):
    def publish(self, anchor: AuditAnchor) -> str: ...


def ensure_audit_anchor_configured(ctx: WorkerContext) -> None:
    """Validate static configuration without claiming live Azure readiness."""

    ctx.settings.require_audit_anchor_configured()


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


def anchor_verified_head(ctx: WorkerContext, provider: _AnchorProvider) -> str:
    try:
        anchor = verified_audit_head(ctx)
    except AuditIntegrityUnhealthyError:
        # An entirely empty chain (no events, no signed head) is the valid initial
        # state — there is simply nothing to witness yet — so treat it as a healthy
        # no-op rather than a failure. A non-empty but head-less/inconsistent chain
        # is genuine corruption and still raises.
        if ctx.audit_store.is_chain_empty():
            logger.info("audit_anchor_skipped", reason="empty_chain")
            return "empty"
        raise
    result = provider.publish(anchor)
    logger.info("audit_anchor_published", outcome=result)
    return result


def process_audit_anchor(ctx: WorkerContext, _message: dict[str, Any]) -> None:
    container_url, client_id = ctx.settings.require_audit_anchor_configured()
    with AzureBlobAuditAnchorProvider(
        container_url,
        managed_identity_client_id=client_id,
        timeout=ctx.settings.provider_timeout_seconds,
    ) as provider:
        anchor_verified_head(ctx, provider)


def maybe_publish_audit_anchor(ctx: WorkerContext, now: datetime) -> None:
    interval = ctx.settings.audit_anchor_interval_seconds
    bucket = int(now.timestamp()) // interval
    ctx.queue.publish("audit-anchor", {}, idempotency_key=f"audit-anchor:{bucket}")
