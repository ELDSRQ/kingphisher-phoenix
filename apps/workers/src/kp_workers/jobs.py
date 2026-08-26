"""Six worker job implementations.

Each worker consumes one queue topic, processes with an idempotency-key guard,
and writes an audit event. All failure paths are logged and surfaced; nothing
is swallowed. Delivery is the only worker that performs an external mutation,
and it always targets the sandboxed SMTP relay (mailpit in dev).
"""

from __future__ import annotations

import hashlib
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from email.utils import formataddr
from typing import Any, Protocol, cast
from urllib.parse import urlparse

from kp_campaign_patterns.builder import build_pattern_candidate
from kp_contracts.generation import GenerationRequest, GenerationResponse, PatternContext
from kp_contracts.queue import JobQueue
from kp_database.audit_store import AuditStore
from kp_database.models import (
    AlertSubscription,
    Campaign,
    CampaignApproval,
    CampaignPattern,
    Recipient,
    RecipientAssignment,
    RetentionAction,
    RetentionPolicy,
    RulesOfEngagement,
    SourceItem,
    TemplateVersion,
    TrackingEvent,
    TrackingToken,
    TrainingAssignment,
)
from kp_database.models import (
    Source as SourceRow,
)
from kp_database.privacy import hash_mailbox
from kp_domain_models import models as dm
from kp_domain_models.policy import ApprovalPolicy, is_recipient_allowed, resolve_sender
from kp_domain_models.roe import (
    recipient_domain_roe_covered,
    roe_active_at,
    verify_roe_signature,
)
from kp_safety_validation.validator import SafetyValidator
from kp_sanitization.neutralize import neutralize
from kp_source_adapters import BulkDownloadAdapter, RssAdapter, SourceAdapter, StixAdapter
from kp_telemetry.errors import SafetyRejectionError
from kp_telemetry.logging import get_logger
from kp_templating.ics import generate_invite
from kp_templating.render import CampaignContext, MessageRenderer, RecipientContext, TrackingContext
from kp_templating.spf import check_spf_for_mailbox
from sqlalchemy import delete, select
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

from kp_workers.config import WorkerSettings
from kp_workers.providers.alerts import SignedWebhookSender
from kp_workers.providers.graph import GraphDirectoryProvider
from kp_workers.providers.mailpit import MailpitReportedMessageProvider
from kp_workers.providers.reminders import ProviderReminderSender, Reminder, ReminderSender
from kp_workers.providers.smtp import EmailSender, make_email_sender

logger = get_logger("kp_workers.jobs")


def _retry_delay(consecutive_errors: int) -> float:
    """Return bounded exponential backoff for repeated infrastructure errors."""
    return float(min(30.0, 0.5 * (2 ** min(max(consecutive_errors - 1, 0), 6))))


_renderer = MessageRenderer()
_DEFAULT_RETENTION_DAYS = 365


class _SessionFactory(Protocol):
    def __call__(self) -> Session: ...


class WorkerContext:
    def __init__(
        self, settings: WorkerSettings, session_factory: _SessionFactory, audit_store: AuditStore, queue: JobQueue
    ) -> None:
        self.settings = settings
        self.session_factory = session_factory
        self.audit_store = audit_store
        self.queue = queue


def process_ingestion(ctx: WorkerContext, message: dict[str, Any]) -> None:
    payload = message["payload"]
    source_id = payload.get("source_id")
    if not source_id:
        logger.error("ingest message missing source_id")
        return
    with ctx.session_factory() as session:
        source = session.get(SourceRow, uuid.UUID(source_id))
        if source is None:
            logger.error("source %s not found", source_id)
            return
        if not source.enabled:
            logger.info("source %s disabled; skipping", source_id)
            return
        fetcher = _make_fetcher(source)
        source_model = dm.Source(
            source_id=source.source_id,
            source_key=source.source_key,
            name=source.name,
            source_type=source.source_type,
            base_domain=source.base_domain,
            fetch_path=source.fetch_path,
            license_state_id=source.license_state_id,
            enabled=source.enabled,
            last_success_at=source.last_success_at,
            last_attempt_at=source.last_attempt_at,
            consecutive_failures=source.consecutive_failures,
        )
        adapter = _source_adapter(source_model, fetcher)
        try:
            items = adapter.fetch()
        except Exception:
            # NEW-10: the counter existed but nothing ever incremented it, so a
            # permanently broken feed retried forever. Count the failure, trip
            # the breaker at the threshold, and let the error propagate so the
            # queue's own retry/DLQ handling is unchanged.
            source.consecutive_failures += 1
            source.last_attempt_at = datetime.now(UTC)
            tripped = source.consecutive_failures >= ctx.settings.source_failure_threshold
            if tripped:
                source.enabled = False
            session.commit()
            ctx.audit_store.record(
                actor="worker:ingestion",
                action="ingest.source.disabled" if tripped else "ingest.fetch.failed",
                object_type="source",
                object_id=source_id,
                detail={
                    "consecutive_failures": source.consecutive_failures,
                    "threshold": ctx.settings.source_failure_threshold,
                    "disabled": tripped,
                },
            )
            if tripped:
                logger.error("source %s disabled after %s consecutive failures", source_id, source.consecutive_failures)
            raise
        inserted = 0
        patterns = 0
        for item in items:
            dup = session.scalar(
                select(SourceItem).where(
                    SourceItem.source_id == source.source_id,
                    SourceItem.content_hash == item.content_hash,
                )
            )
            if dup is not None:
                continue
            session.add(SourceItem(**item.model_dump()))
            inserted += 1
            pattern = build_pattern_candidate(item)
            session.add(pattern)
            patterns += 1
        session.commit()
        source.last_attempt_at = datetime.now(UTC)
        source.last_success_at = source.last_attempt_at
        source.consecutive_failures = 0
        session.commit()
    ctx.audit_store.record(
        actor="worker:ingestion",
        action="ingest.run",
        object_type="source",
        object_id=source_id,
        detail={"inserted": inserted, "patterns": patterns},
    )


def process_generation(ctx: WorkerContext, message: dict[str, Any]) -> None:
    payload = message["payload"]
    pattern_id = payload.get("pattern_id")
    campaign_id = payload.get("campaign_id")
    if not pattern_id:
        logger.error("generate message missing pattern_id")
        return
    with ctx.session_factory() as session:
        existing = session.scalar(
            select(TemplateVersion).where(TemplateVersion.idempotency_key == message["idempotency_key"])
        )
        if existing is not None:
            return
        pattern = session.get(CampaignPattern, uuid.UUID(pattern_id))
        if pattern is None:
            logger.error("generate message references unknown pattern %s", pattern_id)
            return
        if pattern.approval_state != dm.PatternApprovalState.APPROVED:
            # Only human-approved patterns are worth building content from, and
            # this also stops a revoked pattern from being generated against.
            logger.info("pattern %s is not approved; skipping generation", pattern_id)
            return

        as_of = datetime.now(UTC)
        generation_request = _build_generation_request(ctx, pattern, as_of=as_of)
        response = _call_ai(ctx, generation_request)

        validator = SafetyValidator(training_domains=ctx.settings.training_domain_set())
        verdict = validator.validate(response.subject, response.plain_text, response.safe_html)
        if not verdict.allowed:
            # The model's output is never trusted: it is re-validated here, and
            # a human still has to approve whatever survives.
            raise SafetyRejectionError(f"generation rejected: {verdict.reasons}")

        proposal: dict[str, Any] = response.model_dump()
        # Carried onto the draft so the reviewer sees who asked for it (they may
        # not approve it) and whether the source context was flagged.
        proposal["requested_by"] = payload.get("requested_by")
        proposal["context_untrusted"] = generation_request.context_untrusted
        proposal["neutralization_reasons"] = generation_request.neutralization_reasons
        proposal["as_of"] = generation_request.as_of

        template = TemplateVersion(
            template_version_id=uuid.uuid4(),
            campaign_id=uuid.UUID(campaign_id) if campaign_id else None,
            generator_version="0.1.0",
            prompt_template_version="0.1.0",
            model_id=response.model_id,
            input_hash=hashlib.sha256(pattern_id.encode()).hexdigest(),
            raw_proposal=proposal,
            approval_state=dm.TemplateApprovalState.DRAFT,
        )
        session.add(template)
        session.commit()
        template_id = template.template_version_id
    ctx.audit_store.record(
        actor="worker:generation", action="template.generate", object_type="template", object_id=str(template_id)
    )


def effective_sender_address(ctx: WorkerContext, campaign: Campaign) -> tuple[str, bool]:
    """The address mail will actually leave from, and whether the campaign's
    requested persona was honored.

    Three cases:

    * Azure Communication Services only accepts a From on its own verified
      sending domain, so the campaign's configured sender_mailbox is always
      overridden there.
    * With a configured sending-domain pool, the persona's mailbox is honored
      only when it sits in the pool (a registered/verified lookalike or owned
      domain); otherwise the message falls back to the default sender because
      sending as an unauthenticated domain does not deliver.
    * With an empty pool the request is honored as given — the operator owns
      the relay and has authorized the sender address directly.

    Anything reasoning about the sender — SPF preflight, logs, the operator's
    expectations — has to use this rather than sender_mailbox, or it is
    describing a domain that never appears in the envelope.
    """
    if ctx.settings.email_provider == "azure_communication_services":
        return ctx.settings.effective_smtp_sender, False
    return resolve_sender(
        campaign.sender_mailbox,
        sending_domains=ctx.settings.sending_domain_pool(),
        default_sender=ctx.settings.effective_smtp_sender,
    )


def _make_batch_sender(ctx: WorkerContext) -> EmailSender:
    """Build the transport once so a delivery batch can hold one connection."""
    return make_email_sender(
        provider=ctx.settings.email_provider,
        smtp_address=ctx.settings.effective_smtp_address,
        smtp_username=ctx.settings.smtp_username,
        smtp_password=ctx.settings.smtp_password,
        smtp_starttls=ctx.settings.effective_smtp_starttls,
        smtp_ssl=ctx.settings.smtp_ssl,
        acs_endpoint=ctx.settings.acs_email_endpoint,
        acs_connection_string=ctx.settings.acs_email_connection_string,
        timeout=ctx.settings.provider_timeout_seconds,
    )


def process_delivery(ctx: WorkerContext, message: dict[str, Any]) -> None:
    payload = message["payload"]
    assignment_ids = payload.get("recipient_assignment_ids", [])
    template_hash = payload.get("template_hash")
    campaign_id = payload.get("campaign_id")
    test_send = bool(payload.get("test_send", False))
    with ctx.session_factory() as session:
        campaign = session.get(Campaign, uuid.UUID(campaign_id)) if campaign_id else None
        if campaign is None:
            logger.error("delivery message references unknown campaign")
            return
        if not test_send and campaign.state not in (
            dm.CampaignState.SCHEDULED,
            dm.CampaignState.ACTIVE,
            dm.CampaignState.SENDING,
        ):
            logger.info("campaign %s not deliverable (state=%s); skipping", campaign_id, campaign.state.value)
            return
        template = session.get(TemplateVersion, campaign.current_template_id) if campaign.current_template_id else None
        if template is None:
            logger.error("campaign %s has no approved template; refusing to deliver", campaign_id)
            return
        if not test_send and template.approval_state != dm.TemplateApprovalState.APPROVED:
            raise SafetyRejectionError("delivery requires an approved template")
        if template_hash != campaign.manifest_hash:
            raise SafetyRejectionError("delivery manifest does not match the approved campaign")
        pattern = session.get(CampaignPattern, campaign.pattern_id) if campaign.pattern_id else None
        # Re-check the two-person rule here, not just at scheduling: a message
        # queued before the policy tightened must not still go out under the
        # old rules.
        if not test_send and ctx.settings.approval_policy is ApprovalPolicy.ENFORCE:
            granted = {
                row.approval_type
                for row in session.scalars(
                    select(CampaignApproval).where(
                        CampaignApproval.campaign_id == campaign.campaign_id,
                        CampaignApproval.decision == dm.ApprovalDecision.APPROVED,
                    )
                ).all()
            }
            if not {dm.ApprovalType.SECURITY, dm.ApprovalType.PRIVACY} <= granted:
                ctx.audit_store.record(
                    actor="worker:delivery",
                    action="campaign.deliver.blocked",
                    object_type="campaign",
                    object_id=campaign_id,
                    detail={"reason": "missing_approvals"},
                )
                logger.error("campaign %s lacks required approvals; refusing to deliver", campaign_id)
                return
        # Signed Rules-of-Engagement gate. Delivery is impossible without an
        # active, validly-signed RoE attached at scheduling: the RoE names the
        # verified target domains recipients are confined to. Every failure
        # mode here returns without sending anything.
        roe = session.get(RulesOfEngagement, campaign.roe_id) if campaign.roe_id is not None else None
        if roe is None:
            ctx.audit_store.record(
                actor="worker:delivery",
                action="campaign.deliver.blocked",
                object_type="campaign",
                object_id=campaign_id,
                detail={"reason": "no_roe"},
            )
            logger.error("campaign %s has no Rules-of-Engagement; refusing to deliver", campaign_id)
            return
        try:
            roe_key = ctx.settings.require_roe_signing_key()
        except RuntimeError as exc:
            ctx.audit_store.record(
                actor="worker:delivery",
                action="campaign.deliver.blocked",
                object_type="campaign",
                object_id=campaign_id,
                detail={"reason": "roe_key_unconfigured"},
            )
            logger.error("campaign %s RoE cannot be verified: %s", campaign_id, exc)
            return
        if not verify_roe_signature(roe.terms_hash, roe.signer, roe.signed_at, roe.signature, signing_key=roe_key):
            ctx.audit_store.record(
                actor="worker:delivery",
                action="campaign.deliver.blocked",
                object_type="campaign",
                object_id=campaign_id,
                detail={"reason": "roe_signature_invalid"},
            )
            logger.error("campaign %s RoE signature is invalid; refusing to deliver", campaign_id)
            return
        if not roe_active_at(
            revoked_at=roe.revoked_at,
            window_start=roe.window_start,
            window_end=roe.window_end,
            when=datetime.now(UTC),
        ):
            ctx.audit_store.record(
                actor="worker:delivery",
                action="campaign.deliver.blocked",
                object_type="campaign",
                object_id=campaign_id,
                detail={"reason": "roe_not_active"},
            )
            logger.error("campaign %s RoE is not active; refusing to deliver", campaign_id)
            return
        roe_targets = frozenset(roe.target_domains or [])
        allowlist = ctx.settings.recipient_domain_allowlist()
        # Mirror the import rule: unset is fail-closed under OIDC-shaped
        # deployments and allow-all only for the offline dev stack.
        unrestricted = not allowlist and ctx.settings.approval_policy is ApprovalPolicy.SINGLE_ADMIN
        # Check the domain that will actually send, not the one configured on
        # the campaign: under ACS they differ, and checking the wrong one gave
        # an SPF verdict about a domain absent from the message.
        sender_address, sender_honored = effective_sender_address(ctx, campaign)
        spf = check_spf_for_mailbox(sender_address)
        if not spf.has_spf:
            logger.warning("SPF pre-flight: %s publishes no SPF record; delivery may be flagged", spf.domain)
        if sender_address != campaign.sender_mailbox:
            if ctx.settings.email_provider == "azure_communication_services":
                logger.info(
                    "sender override: campaign requests %s but the %s provider sends as %s",
                    campaign.sender_mailbox,
                    ctx.settings.email_provider,
                    sender_address,
                )
            else:
                logger.warning(
                    "sender fallback: %s is not in the sending-domain pool; sending as %s",
                    campaign.sender_mailbox,
                    sender_address,
                )
        sent = 0
        failed = 0
        blocked = 0
        sender = _make_batch_sender(ctx)
        # One held SMTP/ACS connection for the whole batch (ARCH-1).
        with sender:
            for assignment_id in assignment_ids:
                assignment = session.get(RecipientAssignment, uuid.UUID(assignment_id))
                if (
                    assignment is None
                    or assignment.campaign_id != campaign.campaign_id
                    or assignment.send_state != dm.SendState.QUEUED
                ):
                    continue
                token = session.scalar(
                    select(TrackingToken).where(
                        TrackingToken.recipient_assignment_id == assignment.recipient_assignment_id
                    )
                )
                recipient = session.get(Recipient, assignment.recipient_id)
                if token is None or recipient is None or recipient.status != dm.RecipientStatus.ACTIVE:
                    assignment.send_state = dm.SendState.FAILED
                    assignment.failure_reason = "recipient_unavailable"
                    failed += 1
                    continue
                if not unrestricted and not is_recipient_allowed(recipient.mailbox or "", allowlist):
                    # Policy refusal, not a transport error: never attempt the send.
                    assignment.send_state = dm.SendState.FAILED
                    assignment.failure_reason = "domain_not_allowed"
                    blocked += 1
                    session.commit()
                    continue
                if not recipient_domain_roe_covered(recipient.mailbox or "", roe_targets):
                    # The authorization boundary: recipients may only be in the
                    # verified target domains the signed RoE names. This is
                    # independent of the recipient allowlist and cannot be
                    # switched off by config.
                    assignment.send_state = dm.SendState.FAILED
                    assignment.failure_reason = "target_domain_not_roe_covered"
                    blocked += 1
                    session.commit()
                    continue
                try:
                    _send_email(ctx, campaign, template, pattern, assignment, recipient, token, sender=sender)
                    assignment.send_state = dm.SendState.DELIVERED
                    sent += 1
                except Exception:  # noqa: BLE001 - per-recipient isolation: one bad
                    # recipient must not roll back the whole batch or drop the message
                    logger.exception("delivery failed for recipient %s; marking FAILED", recipient.mailbox)
                    assignment.send_state = dm.SendState.FAILED
                    assignment.failure_reason = "send_error"
                    failed += 1
                session.commit()
        if not test_send:
            campaign.state = dm.CampaignState.ACTIVE
        session.commit()
    ctx.audit_store.record(
        actor="worker:delivery",
        action="campaign.deliver",
        object_type="campaign",
        object_id=campaign_id,
        detail={
            "blocked": blocked,
            "sent": sent,
            "failed": failed,
            "template_hash": template_hash,
            "spf_has_record": spf.has_spf,
            "spf_domain": spf.domain,
            "roe_id": str(roe.roe_id),
            "roe_signer": roe.signer,
            "sender_address": sender_address,
            "sender_persona_honored": sender_honored,
        },
    )


def process_retention(ctx: WorkerContext, message: dict[str, Any]) -> None:
    payload = message["payload"]
    policy_id = payload.get("retention_policy_id", "default")
    with ctx.session_factory() as session:
        now = datetime.now(UTC)
        lifecycle = reconcile_campaign_lifecycle(session, now, queued_stale_hours=ctx.settings.queued_stale_hours)
        if policy_id != "default":
            policy = session.get(RetentionPolicy, uuid.UUID(policy_id))
        else:
            policy = session.scalar(select(RetentionPolicy).where(RetentionPolicy.is_default.is_(True)).limit(1))
        retention_days = policy.retention_days if policy is not None else _DEFAULT_RETENTION_DAYS
        cutoff = now - timedelta(days=retention_days)
        rows = list(
            session.execute(
                select(RecipientAssignment).where(
                    RecipientAssignment.created_at < cutoff,
                )
            )
            .scalars()
            .all()[:1000]
        )
        assignment_ids = [row.recipient_assignment_id for row in rows]
        token_ids: list[uuid.UUID] = []
        if assignment_ids:
            token_ids = list(
                session.scalars(
                    select(TrackingToken.token_id).where(TrackingToken.recipient_assignment_id.in_(assignment_ids))
                )
            )
        event_filter = TrackingEvent.occurred_at < cutoff
        if token_ids:
            # A recipient may also participate in a recent campaign, so do not
            # purge by recipient_id here.  The token is the assignment-scoped
            # linkage; unlinked events are retained strictly by occurred_at.
            event_filter = event_filter | TrackingEvent.token_id.in_(token_ids)
        events_deleted = (
            cast(CursorResult[Any], session.execute(delete(TrackingEvent).where(event_filter))).rowcount or 0
        )
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
        action = RetentionAction(
            retention_action_id=uuid.uuid4(),
            retention_policy_id=policy.retention_policy_id if policy is not None else None,
            executed_at=now,
            target_table="linked_campaign_data",
            row_count_deleted=assignments_deleted + tokens_deleted + events_deleted,
            idempotency_key=message["idempotency_key"],
        )
        session.add(action)
        session.commit()
    ctx.audit_store.record(
        actor="worker:retention",
        action="retention.run",
        object_type="system",
        object_id=str(policy_id),
        detail={
            "assignments_deleted": assignments_deleted,
            "tokens_deleted": tokens_deleted,
            "events_deleted": events_deleted,
            "retention_days": retention_days,
            "campaigns_completed": lifecycle["completed"],
            "campaigns_expired": lifecycle["expired"],
        },
    )


def reconcile_campaign_lifecycle(session: Session, now: datetime, *, queued_stale_hours: int = 24) -> dict[str, int]:
    """Close campaigns whose assessment window ended, and settle stale sends.

    An assignment left QUEUED after its campaign closed means the delivery
    message was lost or never ran. Those are marked FAILED with a reason so the
    funnel stops counting them as in-flight forever. Deliberately never
    auto-resent: re-mailing people after a campaign closed is a decision for a
    human, not a reconciler.
    """
    rows = list(
        session.scalars(
            select(Campaign).where(
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
                RecipientAssignment.created_at <= cutoff,
                Campaign.state.in_(
                    [
                        dm.CampaignState.COMPLETED,
                        dm.CampaignState.EXPIRED,
                        dm.CampaignState.CANCELLED,
                    ]
                ),
            )
        )
    )
    for assignment in stale_rows:
        assignment.send_state = dm.SendState.FAILED
        assignment.failure_reason = "stale_queued_reconcile"
    return {"completed": completed, "expired": expired, "stale_queued": len(stale_rows)}


def maybe_publish_retention(ctx: WorkerContext, now: datetime) -> None:
    """Self-publish a retention run on a cadence (CRIT-07 / WS-6).

    Nothing else publishes to the retention topic; without this the retention
    worker would idle forever. A fresh idempotency key lets each run be
    processed exactly once.
    """
    ctx.queue.publish(
        "retention",
        {
            "retention_policy_id": "default",
            "scheduled_at": now.isoformat(),
            "idempotency_key": f"retention-self-{int(now.timestamp())}",
        },
    )


def process_mailbox(ctx: WorkerContext, message: dict[str, Any]) -> None:
    provider = _mailbox_provider(ctx)
    reports = provider.poll()
    recorded = 0
    unknown = 0
    with ctx.session_factory() as session:
        for report in reports:
            token = session.scalar(select(TrackingToken).where(TrackingToken.token_hash == report.token_hash))
            if token is None:
                unknown += 1
                continue
            existing = session.scalar(
                select(TrackingEvent).where(
                    TrackingEvent.token_id == token.token_id,
                    TrackingEvent.event_type == dm.EventType.MESSAGE_REPORTED,
                )
            )
            if existing is not None:
                continue
            assignment = session.get(RecipientAssignment, token.recipient_assignment_id)
            session.add(
                TrackingEvent(
                    event_id=uuid.uuid4(),
                    event_type=dm.EventType.MESSAGE_REPORTED,
                    token_id=token.token_id,
                    recipient_id=assignment.recipient_id if assignment is not None else None,
                    campaign_id=token.campaign_id,
                    confidence=dm.Confidence.HIGH,
                    occurred_at=report.reported_at,
                    payload={"provider": "mailpit", "external_id": report.external_id[:128]},
                )
            )
            recorded += 1
        session.commit()
    ctx.audit_store.record(
        actor="worker:mailbox",
        action="mailbox.poll",
        object_type="system",
        object_id="training-mailbox",
        detail={"polled": len(reports), "recorded": recorded, "unknown_tokens": unknown},
    )


def process_directory_sync(ctx: WorkerContext, message: dict[str, Any]) -> None:
    payload = message.get("payload", {})
    job_id = str(payload.get("job_id") or "graph")
    provider = GraphDirectoryProvider(
        ctx.settings.effective_graph_base_url,
        bearer_token=ctx.settings.graph_bearer_token,
        api_key=ctx.settings.graph_api_key,
        timeout=ctx.settings.provider_timeout_seconds,
        max_users=ctx.settings.graph_max_users,
        max_pages=ctx.settings.graph_max_pages,
    )
    users = provider.users()
    salt = ctx.settings.require_recipient_hash_salt()
    created = 0
    updated = 0
    with ctx.session_factory() as session:
        for user in users:
            digest = hash_mailbox(user.mailbox, salt)
            recipient = session.scalar(
                select(Recipient).where(Recipient.mailbox_sha256 == digest, Recipient.deleted_at.is_(None))
            )
            if recipient is None:
                recipient = Recipient(
                    recipient_id=uuid.uuid4(),
                    employee_key=user.employee_key,
                    mailbox=user.mailbox,
                    mailbox_sha256=digest,
                    display_name=user.display_name,
                    department=user.department,
                    status=dm.RecipientStatus.ACTIVE,
                    last_snapshot_source="graph",
                )
                session.add(recipient)
                created += 1
            else:
                recipient.employee_key = user.employee_key
                recipient.mailbox = user.mailbox
                recipient.display_name = user.display_name
                recipient.department = user.department
                recipient.last_snapshot_source = "graph"
                updated += 1
        session.commit()
    ctx.audit_store.record(
        actor="worker:directory",
        action="directory.sync",
        object_type="system",
        object_id=job_id,
        detail={"fetched": len(users), "created": created, "updated": updated},
    )


def process_reminder(ctx: WorkerContext, message: dict[str, Any]) -> None:
    sender = _reminder_sender(ctx)
    cutoff = datetime.now(UTC) - timedelta(hours=ctx.settings.reminder_after_hours)
    sent = 0
    skipped = 0
    with ctx.session_factory() as session:
        assignments = list(
            session.scalars(
                select(TrainingAssignment)
                .where(
                    TrainingAssignment.status.in_(
                        [dm.TrainingAssignmentStatus.ASSIGNED, dm.TrainingAssignmentStatus.STARTED]
                    ),
                    TrainingAssignment.completed_at.is_(None),
                    TrainingAssignment.followup_sent_at.is_(None),
                    TrainingAssignment.assigned_at <= cutoff,
                )
                .limit(ctx.settings.reminder_batch_size)
            )
        )
        for assignment in assignments:
            recipient = session.get(Recipient, assignment.recipient_id)
            if recipient is None or recipient.status != dm.RecipientStatus.ACTIVE or not recipient.mailbox:
                skipped += 1
                continue
            sender.send(
                Reminder(
                    recipient=recipient.mailbox,
                    subject="Security awareness training reminder",
                    text=f"Please complete your assigned security awareness training: {ctx.settings.training_base_url}",
                )
            )
            assignment.followup_sent_at = datetime.now(UTC)
            assignment.status = dm.TrainingAssignmentStatus.REMINDED
            sent += 1
            session.commit()
    ctx.audit_store.record(
        actor="worker:reminder",
        action="training.remind",
        object_type="system",
        object_id="training",
        detail={"sent": sent, "skipped": skipped},
    )


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
                sender.send_ntfy(
                    subscription.destination_url,
                    subscription.signing_secret,
                    alert_payload,
                )
            else:
                sender.send(subscription.destination_url, subscription.signing_secret, alert_payload)
        except Exception:
            subscription.consecutive_failures += 1
            session.commit()
            raise
        subscription.last_delivery_at = datetime.now(UTC)
        subscription.consecutive_failures = 0
        session.commit()
    ctx.audit_store.record(
        actor="worker:alert",
        action="alert.deliver",
        object_type="alert_subscription",
        object_id=subscription_id,
        detail={"event_type": payload.get("event_type")},
    )


def _mailbox_provider(ctx: WorkerContext) -> MailpitReportedMessageProvider:
    return MailpitReportedMessageProvider(
        ctx.settings.effective_reported_mailbox_url,
        timeout=ctx.settings.provider_timeout_seconds,
        limit=ctx.settings.mailbox_poll_limit,
        bearer_token=ctx.settings.reported_mailbox_bearer_token,
        basic_username=ctx.settings.reported_mailbox_basic_username,
        basic_password=ctx.settings.reported_mailbox_basic_password,
    )


def _reminder_sender(ctx: WorkerContext) -> ReminderSender:
    return ProviderReminderSender(
        make_email_sender(
            provider=ctx.settings.email_provider,
            smtp_address=ctx.settings.effective_smtp_address,
            smtp_username=ctx.settings.smtp_username,
            smtp_password=ctx.settings.smtp_password,
            smtp_starttls=ctx.settings.effective_smtp_starttls,
            smtp_ssl=ctx.settings.smtp_ssl,
            acs_endpoint=ctx.settings.acs_email_endpoint,
            acs_connection_string=ctx.settings.acs_email_connection_string,
            timeout=ctx.settings.provider_timeout_seconds,
        ),
        sender=ctx.settings.effective_smtp_sender,
    )


def _make_fetcher(source: SourceRow) -> Any:
    from kp_sanitization.fetcher import SecureFetcher

    return SecureFetcher(allowlist={source.base_domain.lower()})


def _source_adapter(source: dm.Source, fetcher: Any) -> SourceAdapter:
    if source.source_type in {dm.SourceType.RSS, dm.SourceType.ADVISORY, dm.SourceType.CURATED}:
        return RssAdapter(source=source, fetcher=fetcher)
    if source.source_type == dm.SourceType.STIX:
        return StixAdapter(source=source, fetcher=fetcher)
    if source.source_type == dm.SourceType.BULK_DOWNLOAD:
        return BulkDownloadAdapter(source=source, fetcher=fetcher)
    raise ValueError(f"unsupported source type: {source.source_type}")


def _clean(text: str | None, *, brand_allowlist: set[str] | None = None) -> tuple[str, list[str]]:
    """Neutralize one free-text field, returning the text and why it was flagged."""
    if not text:
        return "", []
    verdict = neutralize(str(text), brand_allowlist=brand_allowlist)
    return verdict.cleaned_text, list(verdict.reasons)


def _build_generation_request(ctx: WorkerContext, pattern: CampaignPattern, *, as_of: datetime) -> GenerationRequest:
    """Assemble the sanitized threat context sent to the generation gateway.

    NEW-6: the neutralizer existed but nothing on the AI path called it, so
    attacker-influenced text from a threat feed reached the model verbatim.
    Every free-text field is neutralized HERE, before it leaves the process —
    doing it at the gateway would be too late, and doing it in the gateway's
    own code would put the control outside this repository's review.
    """
    reasons: list[str] = []

    # The operator's own brands (sending domains + brand allowlist) are the
    # ones legitimate lures imitate; a lookalike-domain template referencing
    # them must not be flagged as attacker content.
    brands = ctx.settings.brand_allowlist_set() | ctx.settings.sending_domain_pool()

    def field(value: str | None) -> str:
        cleaned, why = _clean(value, brand_allowlist=brands)
        reasons.extend(why)
        return cleaned

    def string_list(values: list[Any] | None) -> list[str]:
        out: list[str] = []
        for value in (values or [])[:12]:
            cleaned = field(str(value))
            if cleaned:
                out.append(cleaned)
        return out

    excerpts: list[str] = []
    for evidence in (pattern.supporting_evidence or [])[:5]:
        text = evidence.get("excerpt") if isinstance(evidence, dict) else str(evidence)
        cleaned = field(text)
        if cleaned:
            # Bounded: a gateway does not need the whole report to write a lure.
            excerpts.append(cleaned[:500])

    context = PatternContext(
        pattern_id=str(pattern.campaign_pattern_id),
        lure_category=pattern.lure_category.value,
        impersonation_category=field(pattern.impersonation_category),
        target_role_category=field(pattern.target_role_category),
        requested_action=field(pattern.requested_action),
        delivery_method=field(pattern.delivery_method),
        emotional_triggers=string_list(pattern.emotional_triggers),
        warning_cues=string_list(pattern.warning_cues),
        attack_mapping=dict(pattern.attack_mapping or {}),
        confidence=pattern.confidence.value,
        source_excerpts=excerpts,
    )
    return GenerationRequest(
        pattern=context,
        as_of=as_of.isoformat(),
        context_untrusted=bool(reasons),
        neutralization_reasons=sorted(set(reasons))[:20],
        training_url=ctx.settings.training_base_url,
    )


def _call_ai(ctx: WorkerContext, request: GenerationRequest) -> GenerationResponse:
    import httpx

    resp = httpx.post(
        f"{ctx.settings.effective_ai_base_url.rstrip('/')}/propose",
        json=request.model_dump(mode="json"),
        headers=_provider_headers(ctx.settings.ai_bearer_token, ctx.settings.ai_api_key),
        timeout=ctx.settings.provider_timeout_seconds,
    )
    resp.raise_for_status()
    # Parsed through the contract, so a gateway cannot return extra fields and
    # have them silently persisted onto the draft.
    return GenerationResponse.model_validate(resp.json())


def _send_email(
    ctx: WorkerContext,
    campaign: Campaign,
    template: TemplateVersion,
    pattern: CampaignPattern | None,
    assignment: RecipientAssignment,
    recipient: Recipient,
    token: TrackingToken,
    *,
    sender: EmailSender | None = None,
) -> None:
    tracking_base = ctx.settings.tracking_base_url.rstrip("/")
    tracking = TrackingContext(
        open_url=f"{tracking_base}/v1/track/open/{token.token_hash}",
        click_url=f"{tracking_base}/v1/track/click/{token.token_hash}",
        training_url=ctx.settings.training_base_url,
    )
    recipient_ctx = RecipientContext(
        first_name=recipient.display_name or "",
        department=recipient.department or "",
        email=recipient.mailbox or "",
    )
    campaign_ctx = CampaignContext(
        title=campaign.title,
        sender_display=(
            pattern.impersonation_category if pattern and pattern.impersonation_category else campaign.sender_mailbox
        ),
        training_domain=campaign.training_domain,
    )
    subject = _render_or_plain(
        ctx, template.subject or campaign.title, recipient_ctx, campaign_ctx, tracking, recipient.mailbox or ""
    )
    plain_text = _render_or_plain(
        ctx, template.plain_text or "", recipient_ctx, campaign_ctx, tracking, recipient.mailbox or ""
    )
    html = _render_or_plain(
        ctx,
        template.safe_html or "",
        recipient_ctx,
        campaign_ctx,
        tracking,
        recipient.mailbox or "",
        html_context=True,
    )
    allowed_domains = ctx.settings.training_domain_set()
    for configured_url in (ctx.settings.tracking_base_url, ctx.settings.training_base_url):
        host = urlparse(configured_url).hostname
        if host:
            allowed_domains.add(host)
    verdict = SafetyValidator(training_domains=allowed_domains).validate(subject, plain_text, html)
    if not verdict.allowed:
        raise SafetyRejectionError(f"final rendered message rejected: {verdict.reasons}")
    pixel_tag = f'<img src="{tracking.open_url}" width="1" height="1" style="display:none" alt="" />'
    if html and "</body>" in html.lower():
        html = html.replace("</body>", f"{pixel_tag}</body>", 1)
    elif html:
        html = f"{html}{pixel_tag}"

    msg = EmailMessage()
    msg["Subject"] = subject
    sender_address, _ = effective_sender_address(ctx, campaign)
    if campaign.sender_display_name and ctx.settings.email_provider != "azure_communication_services":
        # The display name is the persona vector ("Account Security"); ACS is
        # excluded because it parses the From header as the bare senderAddress.
        msg["From"] = formataddr((campaign.sender_display_name, sender_address))
    else:
        msg["From"] = sender_address
    msg["To"] = recipient.mailbox or f"recipient-{assignment.recipient_id}@example.com"
    msg.set_content(plain_text or subject)
    if html:
        msg.add_alternative(html, subtype="html")
    if pattern is not None and pattern.lure_category == dm.LureCategory.CALENDAR_INVITE:
        ics_text, uid = generate_invite(
            organizer_email=campaign.sender_mailbox,
            attendee_email=recipient.mailbox or "",
            event_title=subject or "Security awareness session",
            description=f"Training session for {campaign.title}.",
        )
        msg.add_attachment(
            ics_text.encode("utf-8"), maintype="text", subtype="calendar", filename=f"invite-{uid[:12]}.ics"
        )
    # Reuse the batch connection when one was supplied; single-message callers
    # (reminders, ad-hoc sends) still get a self-contained transport.
    (sender if sender is not None else _make_batch_sender(ctx)).send(msg)


def _provider_headers(bearer_token: str | None, api_key: str | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    if api_key:
        headers["X-API-Key"] = api_key
    return headers


def _render_or_plain(
    ctx: WorkerContext,
    source: str,
    recipient_ctx: RecipientContext,
    campaign_ctx: CampaignContext,
    tracking: TrackingContext,
    sender_email: str,
    *,
    html_context: bool = False,
) -> str:
    try:
        return _renderer.render(
            source,
            recipient=recipient_ctx,
            campaign=campaign_ctx,
            tracking=tracking,
            sender_email=sender_email,
            html_context=html_context,
        )
    except Exception as exc:  # noqa: BLE001 - surfaced to the delivery loop, which
        # marks the recipient FAILED and continues; never silently dropped
        logger.error("template rendering failed: %s", exc)
        raise


def run_loop(ctx: WorkerContext, topic: str, process: Callable[[WorkerContext, dict[str, Any]], None]) -> None:
    logger.info("worker %s listening on %s", ctx.settings.worker_name, topic)
    polls_since_recovery = 0
    last_self_publish = 0.0
    consecutive_errors = 0
    while True:
        now_monotonic = time.monotonic()
        if topic == "retention" and (now_monotonic - last_self_publish >= ctx.settings.retention_interval_seconds):
            maybe_publish_retention(ctx, datetime.now(UTC))
            last_self_publish = now_monotonic
        message: dict[str, Any] | None = None
        try:
            message = ctx.queue.pop(topic, timeout=ctx.settings.poll_seconds)
            if message is None:
                polls_since_recovery += 1
                if polls_since_recovery >= ctx.settings.recovery_every_polls:
                    recovered = ctx.queue.recover_stale(
                        topic,
                        visibility_seconds=ctx.settings.visibility_seconds,
                        max_retries=ctx.settings.max_retries,
                    )
                    if recovered:
                        logger.warning("recovered %d stale claims on %s", recovered, topic)
                    polls_since_recovery = 0
                continue
            process(ctx, message)
            ctx.queue.ack(topic, message)
            consecutive_errors = 0
        except SafetyRejectionError:
            logger.error("safety rejection in %s; rejecting message", topic, exc_info=True)
            if message is not None:
                ctx.queue.reject(topic, message, max_retries=ctx.settings.max_retries)
        except Exception:  # noqa: BLE001 - keep the worker alive, surface the failure
            consecutive_errors += 1
            retry_delay = _retry_delay(consecutive_errors)
            logger.exception(
                "unhandled error in %s; retrying in %.1fs",
                topic,
                retry_delay,
            )
            if message is not None:
                ctx.queue.reject(topic, message, max_retries=ctx.settings.max_retries)
            time.sleep(retry_delay)
            continue
        time.sleep(0.1)
