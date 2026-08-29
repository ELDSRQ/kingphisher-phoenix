"""Reminder and alert worker jobs.

Follow-up jobs: training reminders drive the no-retry training follow-up claim
and the single per-recipient transport; outbound security alerts deliver
signed webhook/ntfy events for a subscription. Both persist their audit records
in the same transaction as their mutations, and both fail closed on invalid
message shape rather than silently continuing.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from kp_database.models import (
    AlertSubscription,
    Recipient,
    RecipientAssignment,
    TrackingToken,
    TrainingAssignment,
)
from kp_database.training import TrainingBearerPurpose, training_bearer, training_bearer_verifier
from kp_domain_models import models as dm
from sqlalchemy import select

from kp_workers.observability import provider_call
from kp_workers.providers.alerts import SignedWebhookSender
from kp_workers.providers.reminders import Reminder

# Kept behind TYPE_CHECKING to mirror the other ``*_jobs`` domain modules: the
# workers package imports this module lazily (see the facades in kp_workers.jobs),
# and that facade is what resolves ``_reminder_sender`` at call time, so
# operator tests that monkeypatch ``kp_workers.jobs._reminder_sender`` keep
# intercepting through the module object rather than a stale copy.
if TYPE_CHECKING:
    from kp_workers.jobs import WorkerContext


def process_reminder(ctx: WorkerContext, message: dict[str, Any]) -> None:
    training_key = ctx.settings.require_training_token_hmac_key()
    now = datetime.now(UTC)
    campaign_id_raw = message.get("payload", {}).get("campaign_id")
    campaign_id = uuid.UUID(str(campaign_id_raw)) if campaign_id_raw else None
    sent = 0
    skipped = 0
    with ctx.session_factory() as session:
        criteria = [
            TrainingAssignment.completed_at.is_(None),
            TrainingAssignment.followup_sent_at.is_(None),
            TrainingAssignment.due_at <= now,
            TrainingAssignment.access_expires_at > now,
            TrainingAssignment.recipient_assignment_id.is_not(None),
        ]
        if campaign_id is not None:
            criteria.append(TrainingAssignment.campaign_id == campaign_id)
        for _ in range(ctx.settings.reminder_batch_size):
            # Claim one row per transaction. Committing a whole preselected
            # batch would release locks on rows not yet sent and let another
            # replica deliver the same reminder concurrently.
            assignment = session.scalar(
                select(TrainingAssignment)
                .where(*criteria)
                .order_by(TrainingAssignment.due_at, TrainingAssignment.training_assignment_id)
                .limit(1)
                .with_for_update(skip_locked=True)
            )
            if assignment is None:
                break
            if (
                assignment.completed_at is not None
                or assignment.followup_sent_at is not None
                or assignment.due_at > now
                or assignment.access_expires_at <= now
            ):
                skipped += 1
                continue
            recipient = session.get(Recipient, assignment.recipient_id)
            recipient_assignment = session.get(RecipientAssignment, assignment.recipient_assignment_id)
            token = (
                session.get(TrackingToken, recipient_assignment.token_id)
                if recipient_assignment is not None and recipient_assignment.token_id is not None
                else None
            )
            if (
                recipient is None
                or recipient.status != dm.RecipientStatus.ACTIVE
                or recipient.deleted_at is not None
                or not recipient.mailbox
                or recipient_assignment is None
                or token is None
                or token.status != dm.TokenStatus.ACTIVE
            ):
                skipped += 1
                assignment.followup_sent_at = now
                session.commit()
                continue
            raw_bearer = training_bearer(
                assignment.training_assignment_id,
                assignment.access_expires_at,
                training_key,
                purpose=TrainingBearerPurpose.OPEN,
            )
            completion_bearer = training_bearer(
                assignment.training_assignment_id,
                assignment.access_expires_at,
                training_key,
                purpose=TrainingBearerPurpose.COMPLETE,
            )
            open_verifier = training_bearer_verifier(
                raw_bearer,
                training_key,
                purpose=TrainingBearerPurpose.OPEN,
            )
            completion_verifier = training_bearer_verifier(
                completion_bearer,
                training_key,
                purpose=TrainingBearerPurpose.COMPLETE,
            )
            if (
                assignment.training_token_hash is None
                or assignment.training_completion_token_hash is None
                or not secrets.compare_digest(assignment.training_token_hash, open_verifier)
                or not secrets.compare_digest(assignment.training_completion_token_hash, completion_verifier)
            ):
                skipped += 1
                assignment.followup_sent_at = now
                session.commit()
                continue
            training_url = f"{ctx.settings.tracking_base_url.rstrip('/')}/v1/training/{raw_bearer}"
            # Persist the no-retry claim before the external side effect. If
            # the provider result is lost, retrying could send a duplicate.
            assignment.followup_sent_at = datetime.now(UTC)
            session.commit()
            try:
                # Reminder transports are single-use and close after send.
                # Construct one per recipient so a batch cannot reuse a closed
                # ACS client. A deterministic construction failure happens
                # before submission, so release the claim for a safe retry.
                from kp_workers import jobs as _jobs  # resolve the patched facade

                sender = _jobs._reminder_sender(ctx)  # noqa: SLF001
            except Exception:
                assignment.followup_sent_at = None
                ctx.audit_store.record(
                    session=session,
                    actor="worker:reminder",
                    action="training.remind.failed",
                    object_type="training_assignment",
                    object_id=str(assignment.training_assignment_id),
                    detail={"outcome": "pre_submission_failure"},
                )
                session.commit()
                raise
            try:
                provider_name = ctx.settings.email_provider_kind.metrics_name
                with provider_call(provider_name, "send"):
                    sender.send(
                        Reminder(
                            recipient=recipient.mailbox,
                            subject="Security awareness training reminder",
                            text=f"Please complete your assigned security awareness training: {training_url}",
                        )
                    )
            except Exception:
                ctx.audit_store.record(
                    actor="worker:reminder",
                    action="training.remind.failed",
                    object_type="training_assignment",
                    object_id=str(assignment.training_assignment_id),
                    detail={"outcome": "provider_result_unknown"},
                )
                raise
            sent += 1
        ctx.audit_store.record(
            session=session,
            actor="worker:reminder",
            action="training.remind",
            object_type="system",
            object_id="training",
            detail={"sent": sent, "skipped": skipped},
        )
        session.commit()


def process_alert(ctx: WorkerContext, message: dict[str, Any]) -> None:
    payload = message.get("payload", {})
    subscription_id = payload.get("subscription_id")
    if not subscription_id:
        raise ValueError("alert message missing subscription_id")
    with ctx.session_factory() as session:
        subscription = session.get(AlertSubscription, uuid.UUID(subscription_id))
        if subscription is None or not subscription.active:
            return
        if payload.get("campaign_id") != str(subscription.campaign_id):
            raise ValueError("alert campaign does not match subscription")
        if payload.get("event_type") not in {
            "campaign.scheduled",
            "campaign.recalled",
            "campaign.kill_switch",
        }:
            raise ValueError("unsupported alert event type")
        if not subscription.destination_url or not subscription.signing_secret:
            raise ValueError("outbound alert subscription is missing delivery configuration")
        sender = SignedWebhookSender(
            ctx.settings.alert_webhook_domain_set(), timeout=ctx.settings.provider_timeout_seconds
        )
        try:
            alert_payload = {
                "event_type": payload.get("event_type"),
                "campaign_id": payload.get("campaign_id"),
                "occurred_at": payload.get("occurred_at"),
                "subscription_id": subscription_id,
            }
            if subscription.channel == "ntfy":
                with provider_call("ntfy", "send"):
                    sender.send_ntfy(
                        subscription.destination_url,
                        subscription.signing_secret,
                        alert_payload,
                    )
            else:
                with provider_call("webhook", "send"):
                    sender.send(subscription.destination_url, subscription.signing_secret, alert_payload)
        except Exception:
            subscription.consecutive_failures += 1
            session.commit()
            raise
        subscription.last_delivery_at = datetime.now(UTC)
        subscription.consecutive_failures = 0
        ctx.audit_store.record(
            session=session,
            actor="worker:alert",
            action="alert.deliver",
            object_type="alert_subscription",
            object_id=subscription_id,
            detail={"event_type": payload.get("event_type")},
        )
        session.commit()