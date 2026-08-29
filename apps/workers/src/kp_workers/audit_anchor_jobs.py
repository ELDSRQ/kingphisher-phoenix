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


def verified_audit_head(ctx: WorkerContext) -> AuditAnchor:
    """Return only a chain head that remained stable throughout verification."""

    before = ctx.audit_store.head_snapshot()
    problems = ctx.audit_store.verify()
    after = ctx.audit_store.head_snapshot()
    if problems:
        raise AuditIntegrityUnhealthyError(f"audit integrity verification failed ({len(problems)} problem(s))")
    if before is None or after is None:
        raise AuditIntegrityUnhealthyError("no signed audit head is available")
    if before != after:
        raise AuditIntegrityUnhealthyError("audit head changed during verification")
    return _as_anchor(after)


def anchor_verified_head(ctx: WorkerContext, provider: _AnchorProvider) -> str:
    result = provider.publish(verified_audit_head(ctx))
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
