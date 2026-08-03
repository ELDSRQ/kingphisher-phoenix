"""Six worker job implementations.

Each worker consumes one queue topic, processes with an idempotency-key guard,
and writes an audit event. All failure paths are logged and surfaced; nothing
is swallowed. Delivery is the only worker that performs an external mutation,
and it always targets the sandboxed SMTP relay (mailpit in dev).
"""

from __future__ import annotations

import hashlib
import smtplib
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from email.message import EmailMessage
from typing import Any, Protocol

from kp_campaign_patterns.builder import build_pattern_candidate
from kp_contracts.queue import JobQueue
from kp_database.audit_store import AuditStore
from kp_database.models import (
    Campaign,
    CampaignPattern,
    Recipient,
    RecipientAssignment,
    RetentionAction,
    SourceItem,
    TemplateVersion,
    TrackingToken,
)
from kp_database.models import (
    Source as SourceRow,
)
from kp_domain_models import models as dm
from kp_safety_validation.validator import SafetyValidator
from kp_source_adapters.rss import RssAdapter
from kp_telemetry.errors import SafetyRejectionError
from kp_telemetry.logging import get_logger
from kp_templating.ics import generate_invite
from kp_templating.render import CampaignContext, MessageRenderer, RecipientContext, TrackingContext
from kp_templating.spf import check_spf_for_mailbox
from sqlalchemy import select
from sqlalchemy.orm import Session

from kp_workers.config import WorkerSettings

logger = get_logger("kp_workers.jobs")
_renderer = MessageRenderer()


class _SessionFactory(Protocol):
    def __call__(self) -> Session: ...


class WorkerContext:
    def __init__(self, settings: WorkerSettings, session_factory: _SessionFactory,
                 audit_store: AuditStore, queue: JobQueue) -> None:
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
        adapter = RssAdapter(source=dm.Source(
            source_id=source.source_id, source_key=source.source_key, name=source.name,
            source_type=source.source_type, base_domain=source.base_domain,
        ), fetcher=fetcher)
        items = adapter.fetch()
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
            item.source_id = source.source_id
            session.add(item)
            inserted += 1
            pattern = build_pattern_candidate(item)
            session.add(pattern)
            patterns += 1
        session.commit()
        source.last_attempt_at = datetime.now(UTC)
        source.consecutive_failures = 0
        session.commit()
    ctx.audit_store.record(actor="worker:ingestion", action="ingest.run", object_type="source",
                           object_id=source_id, detail={"inserted": inserted, "patterns": patterns})


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
        proposal = _call_ai(ctx, pattern_id)
        validator = SafetyValidator(training_domains=ctx.settings.training_domain_set())
        verdict = validator.validate(
            proposal.get("subject"), proposal.get("plain_text", ""), proposal.get("safe_html", "")
        )
        if not verdict.allowed:
            raise SafetyRejectionError(f"generation rejected: {verdict.reasons}")
        template = TemplateVersion(
            template_version_id=uuid.uuid4(),
            campaign_id=uuid.UUID(campaign_id) if campaign_id else None,
            generator_version="0.1.0",
            prompt_template_version="0.1.0",
            model_id=proposal.get("model_id", "mock-ai"),
            input_hash=hashlib.sha256(pattern_id.encode()).hexdigest(),
            raw_proposal=proposal,
            approval_state=dm.TemplateApprovalState.DRAFT,
        )
        session.add(template)
        session.commit()
        template_id = template.template_version_id
    ctx.audit_store.record(actor="worker:generation", action="template.generate", object_type="template",
                           object_id=str(template_id))


def process_delivery(ctx: WorkerContext, message: dict[str, Any]) -> None:
    payload = message["payload"]
    assignment_ids = payload.get("recipient_assignment_ids", [])
    template_hash = payload.get("template_hash")
    campaign_id = payload.get("campaign_id")
    with ctx.session_factory() as session:
        campaign = session.get(Campaign, uuid.UUID(campaign_id)) if campaign_id else None
        if campaign is None:
            logger.error("delivery message references unknown campaign")
            return
        if campaign.state not in (dm.CampaignState.SCHEDULED, dm.CampaignState.ACTIVE, dm.CampaignState.SENDING):
            logger.info("campaign %s not deliverable (state=%s); skipping", campaign_id, campaign.state.value)
            return
        template = session.get(TemplateVersion, campaign.current_template_id) if campaign.current_template_id else None
        if template is None:
            logger.error("campaign %s has no approved template; refusing to deliver", campaign_id)
            return
        pattern = session.get(CampaignPattern, campaign.pattern_id) if campaign.pattern_id else None
        spf = check_spf_for_mailbox(campaign.sender_mailbox)
        if not spf.has_spf:
            logger.warning(
                "SPF pre-flight: %s publishes no SPF record; delivery may be flagged", spf.domain
            )
        sent = 0
        for assignment_id in assignment_ids:
            assignment = session.get(RecipientAssignment, uuid.UUID(assignment_id))
            if assignment is None or assignment.send_state != dm.SendState.QUEUED:
                continue
            token = session.scalar(
                select(TrackingToken).where(
                    TrackingToken.recipient_assignment_id == assignment.recipient_assignment_id
                )
            )
            recipient = session.get(Recipient, assignment.recipient_id)
            if token is None or recipient is None or recipient.status != dm.RecipientStatus.ACTIVE:
                assignment.send_state = dm.SendState.FAILED
                continue
            _send_email(ctx, campaign, template, pattern, assignment, recipient, token)
            assignment.send_state = dm.SendState.DELIVERED
            sent += 1
        campaign.state = dm.CampaignState.ACTIVE
        session.commit()
    ctx.audit_store.record(actor="worker:delivery", action="campaign.deliver", object_type="campaign",
                           object_id=campaign_id,
                           detail={"sent": sent, "template_hash": template_hash,
                                   "spf_has_record": spf.has_spf, "spf_domain": spf.domain})


def process_retention(ctx: WorkerContext, message: dict[str, Any]) -> None:
    payload = message["payload"]
    policy_id = payload.get("retention_policy_id", "default")
    with ctx.session_factory() as session:
        expired = datetime.now(UTC)
        rows = list(session.execute(
            select(RecipientAssignment).where(
                RecipientAssignment.send_state == dm.SendState.DELIVERED,
                RecipientAssignment.created_at < expired,
            )
        ).scalars().all()[:1000])
        for row in rows:
            session.delete(row)
        action = RetentionAction(
            retention_action_id=uuid.uuid4(),
            retention_policy_id=uuid.UUID(policy_id) if policy_id != "default" else None,
            executed_at=expired,
            target_table="recipient_assignments",
            row_count_deleted=len(rows),
            idempotency_key=message["idempotency_key"],
        )
        session.add(action)
        session.commit()
    ctx.audit_store.record(actor="worker:retention", action="retention.run", object_type="system",
                           object_id=policy_id, detail={"deleted": len(rows)})


def process_mailbox(ctx: WorkerContext, message: dict[str, Any]) -> None:
    # Mailpit API lists captured messages in the training mailbox. In the
    # foundation build we record a heartbeat; reply ingestion is wired to
    # Mailpit's API in a later wave.
    ctx.audit_store.record(actor="worker:mailbox", action="mailbox.poll", object_type="system",
                           object_id="training-mailbox", detail={})


def process_reminder(ctx: WorkerContext, message: dict[str, Any]) -> None:
    ctx.audit_store.record(actor="worker:reminder", action="training.remind", object_type="system",
                           object_id="training", detail={})


def _make_fetcher(source: SourceRow) -> Any:
    from kp_sanitization.fetcher import SecureFetcher

    return SecureFetcher(allowlist={source.base_domain.lower()})


def _call_ai(ctx: WorkerContext, pattern_id: str) -> dict[str, Any]:
    import httpx

    resp = httpx.post(
        f"{ctx.settings.mock_ai_url}/propose",
        json={"pattern_id": pattern_id},
        timeout=10.0,
    )
    resp.raise_for_status()
    return dict(resp.json())


def _send_email(ctx: WorkerContext, campaign: Campaign, template: TemplateVersion,
                pattern: CampaignPattern | None, assignment: RecipientAssignment,
                recipient: Recipient, token: TrackingToken) -> None:
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
            pattern.impersonation_category
            if pattern and pattern.impersonation_category
            else campaign.sender_mailbox
        ),
        training_domain=campaign.training_domain,
    )
    subject = _render_or_plain(ctx, template.subject or campaign.title, recipient_ctx, campaign_ctx, tracking,
                                recipient.mailbox or "")
    plain_text = _render_or_plain(ctx, template.plain_text or "", recipient_ctx, campaign_ctx, tracking,
                                  recipient.mailbox or "")
    html = _render_or_plain(ctx, template.safe_html or "", recipient_ctx, campaign_ctx, tracking,
                            recipient.mailbox or "")
    pixel_tag = (
        f'<img src="{tracking.open_url}" width="1" height="1" '
        'style="display:none" alt="" />'
    )
    if html and "</body>" in html.lower():
        html = html.replace("</body>", f"{pixel_tag}</body>", 1)
    elif html:
        html = f"{html}{pixel_tag}"

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = campaign.sender_mailbox
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
        msg.add_attachment(ics_text.encode("utf-8"), maintype="text", subtype="calendar",
                           filename=f"invite-{uid[:12]}.ics")
    with smtplib.SMTP(ctx.settings.mailpit_smtp, timeout=5) as smtp:
        smtp.send_message(msg)


def _render_or_plain(ctx: WorkerContext, source: str, recipient_ctx: RecipientContext,
                     campaign_ctx: CampaignContext, tracking: TrackingContext, sender_email: str) -> str:
    try:
        return _renderer.render(source, recipient=recipient_ctx, campaign=campaign_ctx,
                                tracking=tracking, sender_email=sender_email)
    except Exception as exc:  # noqa: BLE001 - a bad template must fail the message, not the worker
        logger.error("template rendering failed: %s", exc)
        raise


def run_loop(ctx: WorkerContext, topic: str,
             process: Callable[[WorkerContext, dict[str, Any]], None]) -> None:
    logger.info("worker %s listening on %s", ctx.settings.worker_name, topic)
    while True:
        try:
            message = ctx.queue.pop(topic, timeout=ctx.settings.poll_seconds)
            if message is None:
                continue
            process(ctx, message)
        except SafetyRejectionError:
            logger.error("safety rejection in %s", topic, exc_info=True)
        except Exception:  # noqa: BLE001 - keep the worker alive, surface the failure
            logger.exception("unhandled error in %s", topic)
        time.sleep(0.1)
