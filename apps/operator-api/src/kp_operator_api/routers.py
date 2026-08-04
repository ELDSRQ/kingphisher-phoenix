"""Operator API routers: campaign lifecycle, sources, recipients, approvals,
patterns, templates, audit.

Every mutating endpoint records a hash-chained audit event and enforces
RBAC. Deterministic checks (safety validation, approval requirements,
self-approval block, manifest hashing) happen here, in-process, so they cannot
be bypassed by the client.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from kp_authorization.rbac import Capability, Principal, Role
from kp_database.audit_store import AuditStore
from kp_database.campaign_service import prepare_campaign
from kp_database.models import (
    AlertSubscription,
    Campaign,
    CampaignApproval,
    CampaignPattern,
    PrivacyNotice,
    PrivacyRequest,
    Recipient,
    RecipientExclusion,
    TemplateVersion,
    TrackingEvent,
)
from kp_database.privacy import hash_mailbox
from kp_domain_models import models as dm
from kp_telemetry.errors import (
    ConflictError,
    NotFoundError,
    PermissionDeniedError,
    SafetyRejectionError,
    ValidationError_,
)
from kp_templating.render import MessageRenderer
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from kp_operator_api.auth import require_any_capability, require_capability
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.deps import get_audit_store, get_session, get_settings

router = APIRouter(prefix="/api/v1")
_renderer = MessageRenderer()


class CampaignCreate(BaseModel):
    pattern_id: str
    title: str = Field(min_length=1, max_length=255)
    sender_mailbox: str
    training_domain: str
    schedule_start: datetime
    schedule_end: datetime
    timezone: str = "UTC"
    max_recipients: int = Field(gt=0, le=100_000)
    template_version_id: str


class ApprovalSubmit(BaseModel):
    decision: dm.ApprovalDecision
    rationale: str | None = None


class ExclusionCreate(BaseModel):
    exclusion_type: dm.ExclusionType
    campaign_id: str | None = None
    reason: str | None = None
    expires_at: datetime | None = None


class SourceCreate(BaseModel):
    name: str
    source_type: dm.SourceType
    base_domain: str
    license_state_id: str | None = None


@router.post("/campaigns", status_code=status.HTTP_201_CREATED)
def create_campaign(
    body: CampaignCreate,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.CREATE_CAMPAIGN)),
) -> dict[str, Any]:
    pattern = session.get(CampaignPattern, uuid.UUID(body.pattern_id))
    if pattern is None or pattern.approval_state != dm.PatternApprovalState.APPROVED:
        raise HTTPException(status_code=422, detail="campaign requires an approved pattern")

    template = session.get(TemplateVersion, uuid.UUID(body.template_version_id))
    if template is None or template.approval_state != dm.TemplateApprovalState.APPROVED:
        raise HTTPException(status_code=422, detail="campaign requires an approved template")

    validator = session.info.get("safety_validator")
    if validator is not None:
        verdict = validator.validate(template.subject, template.plain_text or "", template.safe_html)
        if not verdict.allowed:
            raise SafetyRejectionError("template fails deterministic safety validation")

    if body.schedule_end <= body.schedule_start:
        raise HTTPException(status_code=422, detail="schedule_end must be after schedule_start")

    campaign = Campaign(
        campaign_id=uuid.uuid4(),
        pattern_id=uuid.UUID(body.pattern_id),
        current_template_id=uuid.UUID(body.template_version_id),
        title=body.title,
        state=dm.CampaignState.DRAFT,
        sender_mailbox=body.sender_mailbox,
        training_domain=body.training_domain,
        schedule_start=body.schedule_start,
        schedule_end=body.schedule_end,
        timezone=body.timezone,
        max_recipients=body.max_recipients,
        created_by=uuid.UUID(principal.principal_id) if principal.principal_id != "anonymous" else None,
        expires_at=body.schedule_end,
    )
    manifest = hashlib.sha256(
        f"{campaign.campaign_id}|{pattern.campaign_pattern_id}|{template.template_version_id}".encode()
    ).hexdigest()
    campaign.manifest_hash = manifest
    session.add(campaign)
    audit.record(
        actor=principal.principal_id,
        action="campaign.create",
        object_type="campaign",
        object_id=str(campaign.campaign_id),
        detail={"title": body.title, "manifest_hash": manifest},
    )
    session.commit()
    return {"campaign_id": str(campaign.campaign_id), "state": campaign.state.value}


@router.post("/campaigns/{campaign_id}/submit", status_code=status.HTTP_200_OK)
def submit_campaign(
    campaign_id: str,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.SCHEDULE_CAMPAIGN)),
) -> dict[str, Any]:
    campaign = _get_campaign(session, campaign_id)
    if campaign.state != dm.CampaignState.DRAFT:
        raise ConflictError("only drafts can be submitted for approval")
    campaign.state = dm.CampaignState.PENDING_APPROVAL
    audit.record(
        actor=principal.principal_id,
        action="campaign.submit",
        object_type="campaign",
        object_id=str(campaign.campaign_id),
    )
    session.commit()
    return {"campaign_id": str(campaign.campaign_id), "state": campaign.state.value}


@router.post("/campaigns/{campaign_id}/approvals/{approval_type}", status_code=status.HTTP_200_OK)
def approve_campaign(
    campaign_id: str,
    approval_type: dm.ApprovalType,
    body: ApprovalSubmit,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.APPROVE_CAMPAIGN)),
) -> dict[str, Any]:
    campaign = _get_campaign(session, campaign_id)
    if campaign.state != dm.CampaignState.PENDING_APPROVAL:
        raise ConflictError("campaign is not awaiting approval")

    required: dict[dm.ApprovalType, Role] = {
        dm.ApprovalType.SECURITY: Role.SECURITY_APPROVER,
        dm.ApprovalType.PRIVACY: Role.PRIVACY_APPROVER,
    }
    if approval_type not in required:
        raise HTTPException(status_code=422, detail=f"unsupported approval type {approval_type}")
    if required[approval_type] not in principal.roles:
        raise PermissionDeniedError(f"requires role {required[approval_type].value}")

    if str(campaign.created_by) == principal.principal_id:
        raise PermissionDeniedError("self-approval of your own campaign is prohibited")

    approval = CampaignApproval(
        campaign_approval_id=uuid.uuid4(),
        campaign_id=campaign.campaign_id,
        approval_type=approval_type,
        approver_id=uuid.UUID(principal.principal_id) if principal.principal_id != "anonymous" else uuid.uuid4(),
        decision=body.decision,
        rationale=body.rationale,
        decided_at=datetime.now(UTC),
        template_version_id=campaign.current_template_id,
    )
    session.add(approval)

    if body.decision == dm.ApprovalDecision.APPROVED:
        existing = (
            session.execute(
                select(CampaignApproval).where(
                    CampaignApproval.campaign_id == campaign.campaign_id,
                    CampaignApproval.decision == dm.ApprovalDecision.APPROVED,
                )
            )
            .scalars()
            .all()
        )
        types_approved = {a.approval_type for a in existing}
        types_approved.add(approval_type)
        if types_approved >= {dm.ApprovalType.SECURITY, dm.ApprovalType.PRIVACY}:
            campaign.state = dm.CampaignState.APPROVED
    else:
        campaign.state = dm.CampaignState.REJECTED
    audit.record(
        actor=principal.principal_id,
        action=f"campaign.approve.{approval_type.value}",
        object_type="campaign",
        object_id=str(campaign.campaign_id),
        detail={"decision": body.decision.value},
    )
    session.commit()
    return {"campaign_id": str(campaign.campaign_id), "state": campaign.state.value}


@router.post("/campaigns/{campaign_id}/schedule", status_code=status.HTTP_200_OK)
def schedule_campaign(
    campaign_id: str,
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.SCHEDULE_CAMPAIGN)),
) -> dict[str, Any]:
    campaign = _get_campaign(session, campaign_id)
    if campaign.state != dm.CampaignState.APPROVED:
        raise ConflictError("campaign must be APPROVED before scheduling")
    prepared = prepare_campaign(session, campaign, tracking_base_url=request.app.state.settings.tracking_base_url)
    assignment_ids = [p.assignment_id for p in prepared]
    request.app.state.queue.publish(
        "deliver",
        {
            "campaign_id": campaign_id,
            "recipient_assignment_ids": assignment_ids,
            "template_hash": campaign.manifest_hash,
        },
        idempotency_key=f"deliver:{campaign_id}",
    )
    campaign.state = dm.CampaignState.SCHEDULED
    audit.record(
        actor=principal.principal_id,
        action="campaign.schedule",
        object_type="campaign",
        object_id=str(campaign.campaign_id),
        detail={"prepared": len(assignment_ids)},
    )
    session.commit()
    return {"campaign_id": str(campaign.campaign_id), "state": campaign.state.value, "prepared": len(assignment_ids)}


@router.post("/campaigns/{campaign_id}/test-send", status_code=status.HTTP_200_OK)
def test_send_campaign(
    campaign_id: str,
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.SEND_CAMPAIGN)),
) -> dict[str, Any]:
    campaign = _get_campaign(session, campaign_id)
    prepared = prepare_campaign(
        session,
        campaign,
        tracking_base_url=request.app.state.settings.tracking_base_url,
        include_test_accounts=True,
        test_only=True,
    )
    assignment_ids = [p.assignment_id for p in prepared]
    request.app.state.queue.publish(
        "deliver",
        {
            "campaign_id": campaign_id,
            "recipient_assignment_ids": assignment_ids,
            "template_hash": campaign.manifest_hash,
        },
        idempotency_key=f"deliver:test:{campaign_id}",
    )
    audit.record(
        actor=principal.principal_id,
        action="campaign.test-send",
        object_type="campaign",
        object_id=str(campaign.campaign_id),
        detail={"prepared": len(assignment_ids)},
    )
    return {"campaign_id": str(campaign.campaign_id), "prepared": len(assignment_ids)}


@router.post("/campaigns/{campaign_id}/recall", status_code=status.HTTP_200_OK)
def recall_campaign(
    campaign_id: str,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.STOP_CAMPAIGN)),
) -> dict[str, Any]:
    campaign = _get_campaign(session, campaign_id)
    if campaign.state in (dm.CampaignState.RECALLED, dm.CampaignState.RECALL_IN_PROGRESS, dm.CampaignState.EXPIRED):
        raise ConflictError(f"campaign already {campaign.state.value}")
    campaign.state = dm.CampaignState.RECALL_IN_PROGRESS
    audit.record(
        actor=principal.principal_id,
        action="campaign.recall",
        object_type="campaign",
        object_id=str(campaign.campaign_id),
    )
    session.commit()
    return {"campaign_id": str(campaign.campaign_id), "state": campaign.state.value}


@router.get("/campaigns")
def list_campaigns(
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.VIEW_AGGREGATE)),
) -> list[dict[str, Any]]:
    rows = session.execute(select(Campaign)).scalars().all()
    return [
        {
            "campaign_id": str(c.campaign_id),
            "title": c.title,
            "state": c.state.value,
            "schedule_start": c.schedule_start,
            "schedule_end": c.schedule_end,
        }
        for c in rows
    ]


@router.post("/sources", status_code=status.HTTP_201_CREATED)
def create_source(
    body: SourceCreate,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_SOURCES)),
) -> dict[str, Any]:
    from kp_database.models import Source as SourceRow

    source = SourceRow(
        source_id=uuid.uuid4(),
        source_key=str(uuid.uuid4())[:8],
        name=body.name,
        source_type=body.source_type,
        base_domain=body.base_domain,
        enabled=False,
    )
    session.add(source)
    audit.record(
        actor=principal.principal_id,
        action="source.create",
        object_type="source",
        object_id=str(source.source_id),
        detail={"base_domain": body.base_domain},
    )
    session.commit()
    return {"source_id": str(source.source_id), "enabled": source.enabled}


@router.get("/recipients")
def list_recipients(
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.VIEW_NAMED_RESULTS)),
) -> list[dict[str, Any]]:
    rows = session.execute(select(Recipient)).scalars().all()
    return [{"recipient_id": str(r.recipient_id), "department": r.department, "status": r.status.value} for r in rows]


@router.post("/recipients/{recipient_id}/exclusions", status_code=status.HTTP_201_CREATED)
def add_exclusion(
    recipient_id: str,
    body: ExclusionCreate,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_EXCLUSIONS)),
) -> dict[str, Any]:
    recipient = session.get(Recipient, uuid.UUID(recipient_id))
    if recipient is None:
        raise NotFoundError("recipient not found")
    exclusion = RecipientExclusion(
        recipient_exclusion_id=uuid.uuid4(),
        recipient_id=recipient.recipient_id,
        exclusion_type=body.exclusion_type,
        campaign_id=uuid.UUID(body.campaign_id) if body.campaign_id else None,
        reason=body.reason,
        created_by=uuid.UUID(principal.principal_id) if principal.principal_id != "anonymous" else None,
        expires_at=body.expires_at,
    )
    session.add(exclusion)
    audit.record(
        actor=principal.principal_id,
        action="recipient.exclude",
        object_type="recipient",
        object_id=recipient_id,
        detail={"exclusion_type": body.exclusion_type.value},
    )
    session.commit()
    return {"recipient_exclusion_id": str(exclusion.recipient_exclusion_id)}


class RecipientsImport(BaseModel):
    csv_text: str = Field(min_length=1)
    department: str = ""


@router.post("/recipients/import", status_code=status.HTTP_201_CREATED)
def import_recipients_csv(
    body: RecipientsImport,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    settings: OperatorApiSettings = Depends(get_settings),
    principal: Principal = Depends(require_capability(Capability.MANAGE_RECIPIENTS)),
) -> dict[str, Any]:
    import csv
    import io

    salt = settings.require_recipient_hash_salt()
    created = 0
    skipped = 0
    errors: list[str] = []
    for idx, row in enumerate(csv.reader(io.StringIO(body.csv_text)), start=1):
        if not row or all(cell.strip() == "" for cell in row):
            continue
        if len(row) < 1:
            errors.append(f"row {idx}: expected at least one column")
            continue
        mailbox = row[0].strip()
        if "@" not in mailbox:
            errors.append(f"row {idx}: invalid mailbox {mailbox!r}")
            continue
        mailbox_key = hash_mailbox(mailbox, salt)
        existing = session.scalar(select(Recipient).where(Recipient.mailbox_sha256 == mailbox_key))
        if existing is not None:
            skipped += 1
            continue
        display_name = row[1].strip() if len(row) > 1 and row[1].strip() else mailbox
        department = row[2].strip() if len(row) > 2 and row[2].strip() else body.department
        recipient = Recipient(
            recipient_id=uuid.uuid4(),
            employee_key=mailbox.lower(),
            mailbox=mailbox,
            mailbox_sha256=mailbox_key,
            display_name=display_name,
            department=department,
            is_test_account=mailbox.lower().endswith("+test@example.com"),
            status=dm.RecipientStatus.ACTIVE,
        )
        session.add(recipient)
        created += 1
    audit.record(
        actor=principal.principal_id,
        action="recipient.import",
        object_type="recipients",
        object_id="csv",
        detail={"created": created, "skipped": skipped, "errors": len(errors)},
    )
    session.commit()
    return {"created": created, "skipped": skipped, "errors": errors[:20]}


class AlertSubscribe(BaseModel):
    campaign_id: str
    channel: str = "web"


@router.post("/alerts/subscriptions", status_code=status.HTTP_201_CREATED)
def subscribe_alerts(
    body: AlertSubscribe,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.SUBSCRIBE_ALERTS)),
) -> dict[str, Any]:
    campaign = _get_campaign(session, body.campaign_id)
    existing = session.scalar(
        select(AlertSubscription).where(
            AlertSubscription.user_id == uuid.UUID(principal.principal_id),
            AlertSubscription.campaign_id == campaign.campaign_id,
            AlertSubscription.channel == body.channel,
        )
    )
    if existing is not None:
        existing.active = True
        sub = existing
    else:
        sub = AlertSubscription(
            alert_subscription_id=uuid.uuid4(),
            user_id=uuid.UUID(principal.principal_id),
            campaign_id=campaign.campaign_id,
            channel=body.channel,
            active=True,
        )
        session.add(sub)
    audit.record(
        actor=principal.principal_id,
        action="alerts.subscribe",
        object_type="campaign",
        object_id=str(campaign.campaign_id),
        detail={"channel": body.channel},
    )
    session.commit()
    return {"alert_subscription_id": str(sub.alert_subscription_id), "active": sub.active}


@router.get("/alerts/subscriptions", status_code=status.HTTP_200_OK)
def list_alert_subscriptions(
    campaign_id: str | None = None,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.SUBSCRIBE_ALERTS)),
) -> list[dict[str, Any]]:
    stmt = select(AlertSubscription)
    if campaign_id:
        stmt = stmt.where(AlertSubscription.campaign_id == uuid.UUID(campaign_id))
    rows = session.execute(stmt).scalars().all()
    return [
        {
            "alert_subscription_id": str(s.alert_subscription_id),
            "campaign_id": str(s.campaign_id),
            "channel": s.channel,
            "active": s.active,
        }
        for s in rows
    ]


@router.delete("/alerts/subscriptions/{subscription_id}", status_code=status.HTTP_200_OK)
def unsubscribe_alerts(
    subscription_id: str,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.SUBSCRIBE_ALERTS)),
) -> dict[str, Any]:
    sub = session.get(AlertSubscription, uuid.UUID(subscription_id))
    if sub is None:
        raise NotFoundError("subscription not found")
    sub.active = False
    audit.record(
        actor=principal.principal_id,
        action="alerts.unsubscribe",
        object_type="campaign",
        object_id=str(sub.campaign_id),
        detail={"channel": sub.channel},
    )
    session.commit()
    return {"alert_subscription_id": subscription_id, "active": False}


class TemplatePreview(BaseModel):
    subject: str = ""
    plain_text: str = ""
    safe_html: str = ""


@router.post("/templates/preview", status_code=status.HTTP_200_OK)
def preview_template(
    body: TemplatePreview,
    request: Request,
    principal: Principal = Depends(require_capability(Capability.CREATE_CAMPAIGN)),
) -> dict[str, Any]:
    from kp_templating.render import CampaignContext, RecipientContext, TrackingContext

    tracking_base = request.app.state.settings.tracking_base_url.rstrip("/")
    sample_hash = "preview-" + hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:32]
    recipient = RecipientContext(
        first_name="Sample", last_name="Employee", department="Engineering", email="sample@example.com"
    )
    campaign_ctx = CampaignContext(
        title="Preview campaign", sender_display="IT Security", training_domain="training.local"
    )
    tracking = TrackingContext(
        open_url=f"{tracking_base}/v1/track/open/{sample_hash}",
        click_url=f"{tracking_base}/v1/track/click/{sample_hash}",
        training_url=request.app.state.settings.training_base_url,
    )
    try:
        subject = _renderer.render(
            body.subject or "",
            recipient=recipient,
            campaign=campaign_ctx,
            tracking=tracking,
            sender_email="sender@example.com",
        )
        plain_text = _renderer.render(
            body.plain_text or "",
            recipient=recipient,
            campaign=campaign_ctx,
            tracking=tracking,
            sender_email="sender@example.com",
        )
        html = _renderer.render(
            body.safe_html or "",
            recipient=recipient,
            campaign=campaign_ctx,
            tracking=tracking,
            sender_email="sender@example.com",
        )
    except Exception as exc:  # noqa: BLE001 - surface template errors to the author
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"subject": subject, "plain_text": plain_text, "safe_html": html}


@router.get("/templates")
def list_templates(
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.CREATE_CAMPAIGN)),
) -> list[dict[str, Any]]:
    rows = session.execute(select(TemplateVersion)).scalars().all()
    return [
        {
            "template_version_id": str(t.template_version_id),
            "version": t.version,
            "subject": t.subject,
            "approval_state": t.approval_state.value,
        }
        for t in rows
    ]


@router.get("/patterns")
def list_patterns(
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.APPROVE_PATTERN)),
) -> list[dict[str, Any]]:
    rows = session.execute(select(CampaignPattern)).scalars().all()
    return [
        {
            "campaign_pattern_id": str(p.campaign_pattern_id),
            "lure_category": p.lure_category.value,
            "approval_state": p.approval_state.value,
        }
        for p in rows
    ]


@router.post("/patterns/{pattern_id}/approve", status_code=status.HTTP_200_OK)
def approve_pattern(
    pattern_id: str,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.APPROVE_PATTERN)),
) -> dict[str, Any]:
    pattern = session.get(CampaignPattern, uuid.UUID(pattern_id))
    if pattern is None:
        raise NotFoundError("pattern not found")
    if str(pattern.approved_by) == principal.principal_id:
        raise PermissionDeniedError("self-approval of your own pattern is prohibited")
    pattern.approval_state = dm.PatternApprovalState.APPROVED
    pattern.approved_by = uuid.UUID(principal.principal_id) if principal.principal_id != "anonymous" else None
    pattern.approved_at = datetime.now(UTC)
    audit.record(
        actor=principal.principal_id, action="pattern.approve", object_type="campaign_pattern", object_id=pattern_id
    )
    session.commit()
    return {"campaign_pattern_id": pattern_id, "approval_state": pattern.approval_state.value}


@router.get("/audit", status_code=status.HTTP_200_OK)
def view_audit(
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.VIEW_AUDIT)),
) -> list[dict[str, Any]]:
    # CRIT-02: audit rows live on the dedicated audit engine and are not ORM
    # entities on the application session (previously selected pydantic
    # `dm.AuditEvent` and 500'd). Read them through the audit store.
    return audit.list_events(limit=500)


@router.post("/audit/verify", status_code=status.HTTP_200_OK)
def verify_audit(
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.VIEW_AUDIT)),
) -> dict[str, Any]:
    problems = audit.verify()
    return {"ok": not problems, "problems": problems}


def _get_campaign(session: Session, campaign_id: str) -> Campaign:
    campaign = session.get(Campaign, uuid.UUID(campaign_id))
    if campaign is None:
        raise NotFoundError("campaign not found")
    return campaign


class KillSwitchBody(BaseModel):
    campaign_id: uuid.UUID | None = None
    confirm: bool = False


@router.post("/kill-switch", status_code=status.HTTP_200_OK)
def kill_switch(
    body: KillSwitchBody,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.USE_KILL_SWITCH)),
) -> dict[str, Any]:
    """Revoke queued deliveries + tracking tokens.

    MED-13: scoped to a single campaign when `campaign_id` is given (global
    otherwise) and requires an explicit `confirm=true` so a misclick cannot
    cancel the whole delivery queue.
    """
    if not body.confirm:
        raise ValidationError_("kill switch requires explicit confirmation (confirm=true)")

    from kp_database.models import RecipientAssignment, TrackingToken

    now = datetime.now(UTC)
    assignment_filter = RecipientAssignment.send_state == dm.SendState.QUEUED
    token_filter = TrackingToken.status == dm.TokenStatus.ACTIVE
    if body.campaign_id is not None:
        assignment_filter = assignment_filter & (RecipientAssignment.campaign_id == body.campaign_id)
        token_filter = token_filter & (TrackingToken.campaign_id == body.campaign_id)

    rows = session.execute(select(RecipientAssignment).where(assignment_filter)).scalars().all()
    for row in rows:
        row.send_state = dm.SendState.EXPIRED
    tokens = session.execute(select(TrackingToken).where(token_filter)).scalars().all()
    for token in tokens:
        token.status = dm.TokenStatus.KILL_SWITCHED
        token.revoked_at = now
        token.revoked_reason = "kill switch engaged"
    audit.record(
        actor=principal.principal_id,
        action="kill-switch.engage",
        object_type="campaign" if body.campaign_id else "system",
        object_id=str(body.campaign_id) if body.campaign_id else "delivery",
        detail={"cancelled": len(rows), "tokens_revoked": len(tokens), "confirm": body.confirm},
    )
    session.commit()
    return {"cancelled": len(rows), "tokens_revoked": len(tokens)}


@router.get("/kill-switch", status_code=status.HTTP_200_OK)
def kill_switch_state(
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.USE_KILL_SWITCH)),
) -> dict[str, Any]:
    """Report whether the global kill switch has been engaged.

    The switch is one-shot by design; engagement is read back from the most
    recent global audit event so the console can arm/disable the button.
    """
    event = None
    for candidate in audit.list_events(limit=1000):
        if candidate["action"] == "kill-switch.engage" and candidate["object_type"] == "system":
            event = candidate
            break
    if event is None:
        return {"engaged": False}
    detail = event.get("detail") or {}
    return {
        "engaged": True,
        "engaged_at": event.get("occurred_at"),
        "actor": event.get("actor"),
        "last_cancelled": int(detail.get("cancelled", 0)),
        "last_tokens_revoked": int(detail.get("tokens_revoked", 0)),
    }


_PRIVACY_SLA_DAYS = 45


class PrivacyRequestCreate(BaseModel):
    request_type: dm.PrivacyRequestType
    requester_mailbox: str
    campaign_id: str | None = None


@router.get("/privacy/notice")
def get_privacy_notice(
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.HANDLE_PRIVACY)),
) -> dict[str, Any]:
    notice = session.scalar(select(PrivacyNotice).where(PrivacyNotice.is_current.is_(True)).limit(1))
    if notice is None:
        raise NotFoundError("no current privacy notice")
    return {
        "version": notice.version,
        "notice_text": notice.notice_text,
        "effective_at": notice.effective_at,
    }


@router.get("/privacy/requests")
def list_privacy_requests(
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.HANDLE_PRIVACY)),
) -> list[dict[str, Any]]:
    rows = session.execute(select(PrivacyRequest).order_by(PrivacyRequest.opened_at.desc())).scalars().all()
    return [
        {
            "privacy_request_id": str(r.privacy_request_id),
            "request_type": r.request_type.value,
            "requester_mailbox": r.requester_key,
            "status": r.status,
            "opened_at": r.opened_at,
            "sla_deadline": r.sla_deadline,
            "completed_at": r.completed_at,
            "completion_note": r.completion_note,
        }
        for r in rows
    ]


@router.post("/privacy/requests", status_code=status.HTTP_201_CREATED)
def submit_privacy_request(
    body: PrivacyRequestCreate,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    settings: OperatorApiSettings = Depends(get_settings),
    principal: Principal = Depends(require_capability(Capability.HANDLE_PRIVACY)),
) -> dict[str, Any]:
    opened_at = datetime.now(UTC)
    request = PrivacyRequest(
        privacy_request_id=uuid.uuid4(),
        request_type=body.request_type,
        requester_key=body.requester_mailbox,
        campaign_id=uuid.UUID(body.campaign_id) if body.campaign_id else None,
        status="opened",
        opened_at=opened_at,
        sla_deadline=opened_at + timedelta(days=_PRIVACY_SLA_DAYS),
    )
    session.add(request)
    audit.record(
        actor=principal.principal_id,
        action="privacy_request.submit",
        object_type="privacy_request",
        object_id=str(request.privacy_request_id),
        detail={
            "request_type": body.request_type.value,
            "campaign_id": body.campaign_id,
            "sla_deadline": request.sla_deadline.isoformat(),
        },
    )
    session.commit()
    return {
        "privacy_request_id": str(request.privacy_request_id),
        "status": request.status,
        "sla_deadline": request.sla_deadline,
    }


@router.post("/privacy/requests/{request_id}/verify")
def verify_privacy_request(
    request_id: str,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.HANDLE_PRIVACY)),
) -> dict[str, Any]:
    request = session.get(PrivacyRequest, uuid.UUID(request_id))
    if request is None:
        raise NotFoundError("privacy request not found")
    if request.status == "completed":
        raise ConflictError("privacy request already completed")
    request.status = "in_progress"
    audit.record(
        actor=principal.principal_id,
        action="privacy_request.verify",
        object_type="privacy_request",
        object_id=str(request.privacy_request_id),
    )
    session.commit()
    return {"privacy_request_id": str(request.privacy_request_id), "status": request.status}


def _recipients_for_request(
    session: Session, settings: OperatorApiSettings, request: PrivacyRequest
) -> list[Recipient]:
    salt = settings.require_recipient_hash_salt()
    mailbox = request.requester_key
    if not mailbox:
        return []
    digest = hash_mailbox(mailbox, salt)
    return list(session.execute(select(Recipient).where(Recipient.mailbox_sha256 == digest)).scalars().all())


@router.get("/privacy/requests/{request_id}/export")
def export_privacy_request(
    request_id: str,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    settings: OperatorApiSettings = Depends(get_settings),
    principal: Principal = Depends(require_capability(Capability.HANDLE_PRIVACY)),
) -> dict[str, Any]:
    request = session.get(PrivacyRequest, uuid.UUID(request_id))
    if request is None:
        raise NotFoundError("privacy request not found")
    recipients = _recipients_for_request(session, settings, request)
    audit.record(
        actor=principal.principal_id,
        action="privacy_request.export",
        object_type="privacy_request",
        object_id=str(request.privacy_request_id),
        detail={"records": len(recipients)},
    )
    session.commit()
    return {
        "privacy_request_id": str(request.privacy_request_id),
        "request_type": request.request_type.value,
        "records": [
            {
                "recipient_id": str(r.recipient_id),
                "mailbox": r.mailbox,
                "employee_key": r.employee_key,
                "display_name": r.display_name,
                "department": r.department,
                "is_test_account": r.is_test_account,
            }
            for r in recipients
        ],
    }


@router.post("/privacy/requests/{request_id}/fulfill")
def fulfill_privacy_request(
    request_id: str,
    body: dict[str, str],
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    settings: OperatorApiSettings = Depends(get_settings),
    principal: Principal = Depends(require_any_capability(Capability.HANDLE_PRIVACY, Capability.DELETE_DATA)),
) -> dict[str, Any]:
    request = session.get(PrivacyRequest, uuid.UUID(request_id))
    if request is None:
        raise NotFoundError("privacy request not found")
    if request.status == "completed":
        raise ConflictError("privacy request already completed")
    note = (body or {}).get("note", "")
    deleted = 0
    if request.request_type == dm.PrivacyRequestType.DELETION:
        from kp_database.models import RecipientAssignment, TrackingToken

        recipients = _recipients_for_request(session, settings, request)
        for recipient in recipients:
            if recipient.deleted_at is not None:
                continue
            recipient.deleted_at = datetime.now(UTC)
            assignment_ids = list(
                session.execute(
                    select(RecipientAssignment.recipient_assignment_id).where(
                        RecipientAssignment.recipient_id == recipient.recipient_id
                    )
                ).scalars()
            )
            if assignment_ids:
                session.execute(delete(TrackingToken).where(TrackingToken.recipient_assignment_id.in_(assignment_ids)))
                session.execute(
                    delete(RecipientAssignment).where(RecipientAssignment.recipient_assignment_id.in_(assignment_ids))
                )
            session.execute(delete(TrackingEvent).where(TrackingEvent.recipient_id == recipient.recipient_id))
            deleted += 1
    request.status = "completed"
    request.completed_at = datetime.now(UTC)
    request.completion_note = note
    audit.record(
        actor=principal.principal_id,
        action="privacy_request.fulfill",
        object_type="privacy_request",
        object_id=str(request.privacy_request_id),
        detail={"request_type": request.request_type.value, "deleted": deleted, "note": note},
    )
    session.commit()
    return {
        "privacy_request_id": str(request.privacy_request_id),
        "status": request.status,
        "deleted": deleted,
        "sla_deadline": request.sla_deadline,
    }


@router.delete("/recipients/{recipient_id}", status_code=status.HTTP_200_OK)
def delete_recipient(
    recipient_id: str,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.DELETE_DATA)),
) -> dict[str, Any]:
    recipient = session.get(Recipient, uuid.UUID(recipient_id))
    if recipient is None or recipient.deleted_at is not None:
        raise NotFoundError("recipient not found")
    recipient.deleted_at = datetime.now(UTC)
    audit.record(
        actor=principal.principal_id,
        action="recipient.delete",
        object_type="recipient",
        object_id=str(recipient.recipient_id),
    )
    session.commit()
    return {"recipient_id": str(recipient.recipient_id), "deleted_at": recipient.deleted_at}
