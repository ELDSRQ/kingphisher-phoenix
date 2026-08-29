"""Retention and campaign-lifecycle worker jobs.

The retention worker projects the awareness ledger, prunes aged linked data
(assignments, tokens, events, receipts, expired directory previews, and
expired ledger entries), and self-publishes a fresh run on a cadence. The
lifecycle reconciler closes elapsed campaigns and settles stale QUEUED/SENDING
assignments — deliberately never auto-resent, and never making an uncertain
SENDING claim retryable. All outcomes are recorded in the same transaction as
the mutations they describe; projection failures fail closed and never permit
a purge.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from kp_database.awareness_ledger import (
    AWARENESS_LEDGER_TERMINAL_CAMPAIGN_STATES,
    project_awareness_ledger_batch,
)
from kp_database.models import (
    AwarenessLedgerEntry,
    Campaign,
    Microsoft365IntegrationState,
    RecipientAssignment,
    ReportedMailReceipt,
    RetentionAction,
    RetentionPolicy,
    TrackingEvent,
    TrackingToken,
)
from kp_database.reporting import SINGLE_TENANT_DATABASE_SCOPE
from kp_domain_models import models as dm
from sqlalchemy import and_, delete, select
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

from kp_workers.jobs import (
    _DEFAULT_RETENTION_DAYS,
    _RETENTION_ASSIGNMENT_BATCH_SIZE,
    _RETENTION_BATCH_SIZE,
    AwarenessLedgerRetentionError,
    RetentionPolicyConfigurationError,
    WorkerContext,
)


def _resolve_retention_policy(session: Session, policy_id: object) -> tuple[RetentionPolicy | None, int]:
    if policy_id == "default":
        policies = list(
            session.scalars(
                select(RetentionPolicy)
                .where(RetentionPolicy.is_default.is_(True))
                .order_by(RetentionPolicy.retention_policy_id)
                .limit(2)
            )
        )
        if len(policies) > 1:
            raise RetentionPolicyConfigurationError("retention policy configuration is invalid")
        policy = policies[0] if policies else None
    else:
        try:
            requested_policy_id = uuid.UUID(str(policy_id))
        except (AttributeError, ValueError):
            raise RetentionPolicyConfigurationError("retention policy configuration is invalid") from None
        policy = session.get(RetentionPolicy, requested_policy_id)
        if policy is None:
            raise RetentionPolicyConfigurationError("retention policy configuration is invalid")
    retention_days = policy.retention_days if policy is not None else _DEFAULT_RETENTION_DAYS
    if isinstance(retention_days, bool) or not isinstance(retention_days, int) or not 1 <= retention_days <= 365:
        raise RetentionPolicyConfigurationError("retention policy configuration is invalid")
    return policy, retention_days


def process_retention(ctx: WorkerContext, message: dict[str, Any]) -> None:
    payload = message["payload"]
    policy_id = payload.get("retention_policy_id", "default")
    idempotency_key = message["idempotency_key"]
    with ctx.session_factory() as session:
        if (
            session.scalar(
                select(RetentionAction.retention_action_id).where(RetentionAction.idempotency_key == idempotency_key)
            )
            is not None
        ):
            return
        now = datetime.now(UTC)
        lifecycle = reconcile_campaign_lifecycle(session, now, queued_stale_hours=ctx.settings.queued_stale_hours)
        policy, retention_days = _resolve_retention_policy(session, policy_id)
        cutoff = now - timedelta(days=retention_days)
        rows = list(
            session.scalars(
                select(RecipientAssignment)
                .join(Campaign, Campaign.campaign_id == RecipientAssignment.campaign_id)
                .where(
                    RecipientAssignment.created_at < cutoff,
                    Campaign.state.in_(AWARENESS_LEDGER_TERMINAL_CAMPAIGN_STATES),
                )
                .order_by(RecipientAssignment.created_at, RecipientAssignment.recipient_assignment_id)
                .limit(_RETENTION_ASSIGNMENT_BATCH_SIZE)
                .with_for_update(of=RecipientAssignment, skip_locked=True)
            )
        )
        assignment_ids = [row.recipient_assignment_id for row in rows]
        token_ids: list[uuid.UUID] = []
        if assignment_ids:
            token_ids = list(
                session.scalars(
                    select(TrackingToken.token_id).where(TrackingToken.recipient_assignment_id.in_(assignment_ids))
                )
            )
        pseudonym_key, pseudonym_key_version = ctx.settings.require_awareness_pseudonym_config()
        try:
            project_awareness_ledger_batch(
                session,
                tenant_scope=SINGLE_TENANT_DATABASE_SCOPE,
                pseudonym_key=pseudonym_key,
                pseudonym_key_version=pseudonym_key_version,
                assignment_ids=assignment_ids,
                projected_at=now,
            )
        except Exception:
            session.rollback()
            raise AwarenessLedgerRetentionError(
                "awareness ledger projection failed; raw retention was not applied"
            ) from None

        # Truly unlinked events retain the existing age-based cleanup. Events
        # linked to an assignment are deleted only when that exact assignment
        # is in the successfully projected bounded batch.
        event_filter = and_(
            TrackingEvent.occurred_at < cutoff,
            TrackingEvent.recipient_assignment_id.is_(None),
            TrackingEvent.token_id.is_(None),
        )
        if assignment_ids:
            event_filter = event_filter | TrackingEvent.recipient_assignment_id.in_(assignment_ids)
        if token_ids:
            # A recipient may also participate in a recent campaign, so do not
            # purge by recipient_id here.  The token is the assignment-scoped
            # linkage; truly unlinked events are retained strictly by occurred_at.
            event_filter = event_filter | TrackingEvent.token_id.in_(token_ids)
        events_deleted = (
            cast(CursorResult[Any], session.execute(delete(TrackingEvent).where(event_filter))).rowcount or 0
        )
        receipt_ids = list(
            session.scalars(
                select(ReportedMailReceipt.reported_mail_receipt_id)
                .where(ReportedMailReceipt.received_at < cutoff)
                .order_by(ReportedMailReceipt.received_at, ReportedMailReceipt.reported_mail_receipt_id)
                .limit(_RETENTION_BATCH_SIZE)
            )
        )
        receipts_deleted = 0
        if receipt_ids:
            receipts_deleted = (
                cast(
                    CursorResult[Any],
                    session.execute(
                        delete(ReportedMailReceipt).where(ReportedMailReceipt.reported_mail_receipt_id.in_(receipt_ids))
                    ),
                ).rowcount
                or 0
            )
        expired_previews = list(
            session.scalars(
                select(Microsoft365IntegrationState)
                .where(
                    Microsoft365IntegrationState.kind == "directory",
                    Microsoft365IntegrationState.pending_expires_at.is_not(None),
                    Microsoft365IntegrationState.pending_expires_at <= now,
                )
                .order_by(
                    Microsoft365IntegrationState.pending_expires_at,
                    Microsoft365IntegrationState.integration_state_id,
                )
                .limit(_RETENTION_BATCH_SIZE)
                .with_for_update(skip_locked=True)
            )
        )
        for integration_state in expired_previews:
            integration_state.pending_preview_id = None
            integration_state.pending_preview_hash = None
            integration_state.pending_payload = None
            integration_state.pending_created_at = None
            integration_state.pending_expires_at = None
            integration_state.status = "expired"
            integration_state.last_error = "preview_expired"
            integration_state.updated_at = now
        tokens_deleted = 0
        assignments_deleted = 0
        if assignment_ids:
            tokens_deleted = (
                cast(
                    CursorResult[Any],
                    session.execute(
                        delete(TrackingToken).where(TrackingToken.recipient_assignment_id.in_(assignment_ids))
                    ),
                ).rowcount
                or 0
            )
            assignments_deleted = (
                cast(
                    CursorResult[Any],
                    session.execute(
                        delete(RecipientAssignment).where(
                            RecipientAssignment.recipient_assignment_id.in_(assignment_ids)
                        )
                    ),
                ).rowcount
                or 0
            )
        expired_ledger_entry_ids = list(
            session.scalars(
                select(AwarenessLedgerEntry.awareness_ledger_entry_id)
                .where(
                    AwarenessLedgerEntry.tenant_scope == SINGLE_TENANT_DATABASE_SCOPE,
                    AwarenessLedgerEntry.retain_until < now.date(),
                )
                .order_by(
                    AwarenessLedgerEntry.retain_until,
                    AwarenessLedgerEntry.awareness_ledger_entry_id,
                )
                .limit(_RETENTION_BATCH_SIZE)
                .with_for_update(skip_locked=True)
            )
        )
        if expired_ledger_entry_ids:
            session.execute(
                delete(AwarenessLedgerEntry).where(
                    AwarenessLedgerEntry.awareness_ledger_entry_id.in_(expired_ledger_entry_ids)
                )
            )
        action = RetentionAction(
            retention_action_id=uuid.uuid4(),
            retention_policy_id=policy.retention_policy_id if policy is not None else None,
            executed_at=now,
            target_table="linked_campaign_data",
            row_count_deleted=assignments_deleted + tokens_deleted + events_deleted + receipts_deleted,
            idempotency_key=idempotency_key,
        )
        session.add(action)
        ctx.audit_store.record(
            session=session,
            actor="worker:retention",
            action="retention.run",
            object_type="system",
            object_id=str(policy_id),
            detail={
                "assignments_deleted": assignments_deleted,
                "tokens_deleted": tokens_deleted,
                "events_deleted": events_deleted,
                "reported_receipts_deleted": receipts_deleted,
                "directory_previews_expired": len(expired_previews),
                "retention_days": retention_days,
                "campaigns_completed": lifecycle["completed"],
                "campaigns_expired": lifecycle["expired"],
                "stale_queued_failed": lifecycle["stale_queued"],
                "stale_sending_indeterminate": lifecycle["indeterminate"],
            },
        )
        session.commit()


def reconcile_campaign_lifecycle(session: Session, now: datetime, *, queued_stale_hours: int = 24) -> dict[str, int]:
    """Close campaigns whose assessment window ended, and settle stale sends.

    An assignment left QUEUED after its campaign closed means the delivery
    message was lost or never ran. Those are marked FAILED with a reason so the
    funnel stops counting them as in-flight forever. Deliberately never
    auto-resent: re-mailing people after a campaign closed is a decision for a
    human, not a reconciler. A stale SENDING claim is even more sensitive: the
    provider may have accepted it before the worker disappeared, so it moves
    to INDETERMINATE and is never made retryable automatically.
    """
    rows = list(
        session.scalars(
            select(Campaign)
            .where(
                Campaign.schedule_end.is_not(None),
                Campaign.schedule_end <= now,
                Campaign.state.in_(
                    [
                        dm.CampaignState.SCHEDULED,
                        dm.CampaignState.SENDING,
                        dm.CampaignState.ACTIVE,
                    ]
                ),
            )
            .order_by(Campaign.schedule_end, Campaign.campaign_id)
            .limit(_RETENTION_BATCH_SIZE)
        )
    )
    completed = 0
    expired = 0
    for campaign in rows:
        if campaign.state == dm.CampaignState.SCHEDULED:
            campaign.state = dm.CampaignState.EXPIRED
            expired += 1
        else:
            campaign.state = dm.CampaignState.COMPLETED
            completed += 1

    cutoff = now - timedelta(hours=queued_stale_hours)
    stale_rows = list(
        session.scalars(
            select(RecipientAssignment)
            .join(Campaign, Campaign.campaign_id == RecipientAssignment.campaign_id)
            .where(
                RecipientAssignment.send_state == dm.SendState.QUEUED,
                RecipientAssignment.delivery_attempt_id.is_(None),
                RecipientAssignment.created_at <= cutoff,
                Campaign.state.in_(
                    [
                        dm.CampaignState.COMPLETED,
                        dm.CampaignState.EXPIRED,
                        dm.CampaignState.CANCELLED,
                    ]
                ),
            )
            .order_by(RecipientAssignment.created_at, RecipientAssignment.recipient_assignment_id)
            .limit(_RETENTION_BATCH_SIZE)
        )
    )
    for assignment in stale_rows:
        assignment.send_state = dm.SendState.FAILED
        assignment.failure_reason = "stale_queued_reconcile"

    uncertain_rows = list(
        session.scalars(
            select(RecipientAssignment)
            .where(
                RecipientAssignment.send_state == dm.SendState.SENDING,
                RecipientAssignment.delivery_claimed_at.is_not(None),
                RecipientAssignment.delivery_claimed_at <= cutoff,
            )
            .order_by(RecipientAssignment.delivery_claimed_at, RecipientAssignment.recipient_assignment_id)
            .limit(_RETENTION_BATCH_SIZE)
        )
    )
    for assignment in uncertain_rows:
        assignment.send_state = dm.SendState.INDETERMINATE
        assignment.failure_reason = "worker_lost_after_claim"
    return {
        "completed": completed,
        "expired": expired,
        "stale_queued": len(stale_rows),
        "indeterminate": len(uncertain_rows),
    }


def maybe_publish_retention(ctx: WorkerContext, now: datetime) -> None:
    """Self-publish a retention run on a cadence (CRIT-07 / WS-6).

    Nothing else publishes to the retention topic; without this the retention
    worker would idle forever. A fresh idempotency key lets each run be
    processed exactly once.
    """
    # All replicas share one cadence bucket, so restarts or horizontal scale
    # cannot enqueue several logically identical retention runs a few seconds
    # apart. The durable outbox enforces this key across publishers.
    bucket = int(now.timestamp()) // ctx.settings.retention_interval_seconds
    key = f"retention-self-{bucket}"
    # enqueue_queue / dispatch_after_commit are resolved through the kp_workers.jobs
    # module object so the operator tests' monkeypatch on kp_workers.jobs.* keeps
    # intercepting exactly as it did when this code lived in jobs.py. Cast to Any
    # because mypy's implicit_reexport=False treats those names as non-public.
    from kp_workers import jobs as _jobs_module

    _jobs: Any = _jobs_module
    with ctx.session_factory() as session:
        _jobs.enqueue_queue(
            session,
            topic="retention",
            payload={
                "retention_policy_id": "default",
                "scheduled_at": now.isoformat(),
                "idempotency_key": key,
            },
            idempotency_key=key,
        )
        _jobs.dispatch_after_commit(session, lambda: ctx.audit_store.dispatch_pending_queue(ctx.queue))
        session.commit()
