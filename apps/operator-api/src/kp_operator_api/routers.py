"""Operator API routers: campaign lifecycle, sources, recipients, approvals,
patterns, templates, audit.

Every mutating endpoint records a hash-chained audit event and enforces
RBAC. Deterministic checks (safety validation, approval requirements,
self-approval block, manifest hashing) happen here, in-process, so they cannot
be bypassed by the client.
"""

from __future__ import annotations

import csv
import hashlib
import io
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
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
from kp_database.privacy import (
    VERIFIED_PRIVACY_STATES,
    PrivacyRequestStatus,
    erase_recipient_data,
    hash_mailbox,
)
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
from sqlalchemy import select
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
    fetch_path: str = Field(default="/", max_length=1024)
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
    if campaign.state not in (dm.CampaignState.APPROVED, dm.CampaignState.SCHEDULED):
        raise ConflictError("campaign must be APPROVED before scheduling")
    if campaign.schedule_start is None:
        raise ValidationError_("campaign requires a schedule start")
    schedule_start = campaign.schedule_start
    if schedule_start.tzinfo is None:
        raise ValidationError_("schedule start must include a timezone offset")
    first_schedule = campaign.state == dm.CampaignState.APPROVED
    campaign.state = dm.CampaignState.SCHEDULED
    # prepare_campaign commits assignments and the SCHEDULED state together.
    # Publishing only after that commit closes the consumer/state race. A
    # repeated request is safe and can repair a transient Redis publish error.
    prepared = prepare_campaign(session, campaign, tracking_base_url=request.app.state.settings.tracking_base_url)
    assignment_ids = [p.assignment_id for p in prepared]
    request.app.state.queue.publish(
        "deliver",
        {
            "campaign_id": campaign_id,
            "recipient_assignment_ids": assignment_ids,
            "template_hash": campaign.manifest_hash,
            "test_send": True,
        },
        idempotency_key=f"deliver:{campaign_id}",
        available_at=max(schedule_start.timestamp(), datetime.now(UTC).timestamp()),
    )
    if first_schedule:
        audit.record(
            actor=principal.principal_id,
            action="campaign.schedule",
            object_type="campaign",
            object_id=str(campaign.campaign_id),
            detail={"prepared": len(assignment_ids), "scheduled_for": schedule_start.isoformat()},
        )
        _queue_campaign_alert(session, request, campaign, "campaign.scheduled")
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
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.STOP_CAMPAIGN)),
) -> dict[str, Any]:
    campaign = _get_campaign(session, campaign_id)
    if campaign.state in (dm.CampaignState.RECALLED, dm.CampaignState.RECALL_IN_PROGRESS, dm.CampaignState.EXPIRED):
        raise ConflictError(f"campaign already {campaign.state.value}")
    from kp_database.models import RecipientAssignment, TrackingToken

    assignments = list(
        session.scalars(
            select(RecipientAssignment).where(
                RecipientAssignment.campaign_id == campaign.campaign_id,
                RecipientAssignment.send_state == dm.SendState.QUEUED,
            )
        )
    )
    for assignment in assignments:
        assignment.send_state = dm.SendState.EXPIRED
    tokens = list(
        session.scalars(
            select(TrackingToken).where(
                TrackingToken.campaign_id == campaign.campaign_id,
                TrackingToken.status == dm.TokenStatus.ACTIVE,
            )
        )
    )
    now = datetime.now(UTC)
    for token in tokens:
        token.status = dm.TokenStatus.KILL_SWITCHED
        token.revoked_at = now
        token.revoked_reason = "campaign recalled"
    campaign.state = dm.CampaignState.RECALLED
    audit.record(
        actor=principal.principal_id,
        action="campaign.recall",
        object_type="campaign",
        object_id=str(campaign.campaign_id),
        detail={"cancelled": len(assignments), "tokens_revoked": len(tokens)},
    )
    session.commit()
    _queue_campaign_alert(session, request, campaign, "campaign.recalled")
    return {
        "campaign_id": str(campaign.campaign_id),
        "state": campaign.state.value,
        "cancelled": len(assignments),
        "tokens_revoked": len(tokens),
    }


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


def _campaign_report(session: Session, campaign: Campaign) -> dict[str, Any]:
    from kp_database.models import RecipientAssignment, TrainingAssignment

    assignments = list(
        session.scalars(select(RecipientAssignment).where(RecipientAssignment.campaign_id == campaign.campaign_id))
    )
    events = list(session.scalars(select(TrackingEvent).where(TrackingEvent.campaign_id == campaign.campaign_id)))
    training = list(
        session.scalars(select(TrainingAssignment).where(TrainingAssignment.campaign_id == campaign.campaign_id))
    )
    send_counts = {state.value: 0 for state in dm.SendState}
    for assignment in assignments:
        send_counts[assignment.send_state.value] += 1
    event_counts = {event_type.value: 0 for event_type in dm.EventType}
    confidence_counts = {confidence.value: 0 for confidence in dm.Confidence}
    for event in events:
        event_counts[event.event_type.value] += 1
        confidence_counts[event.confidence.value] += 1
    completed_training = sum(1 for item in training if item.completed_at is not None)
    delivered = send_counts.get(dm.SendState.DELIVERED.value, 0)
    return {
        "campaign_id": str(campaign.campaign_id),
        "title": campaign.title,
        "state": campaign.state.value,
        "schedule_start": campaign.schedule_start,
        "schedule_end": campaign.schedule_end,
        "recipients": len(assignments),
        "send_counts": send_counts,
        "event_counts": event_counts,
        "confidence_counts": confidence_counts,
        "training": {"assigned": len(training), "completed": completed_training},
        "rates": {
            "opened": event_counts.get(dm.EventType.OPENED.value, 0) / delivered if delivered else 0.0,
            "clicked": event_counts.get(dm.EventType.CLICKED.value, 0) / delivered if delivered else 0.0,
            "training_completed": completed_training / len(training) if training else 0.0,
        },
    }


@router.get("/campaigns/{campaign_id}/report")
def campaign_report(
    campaign_id: str,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.VIEW_AGGREGATE)),
) -> dict[str, Any]:
    return _campaign_report(session, _get_campaign(session, campaign_id))


@router.get("/campaigns/{campaign_id}/report.csv")
def campaign_report_csv(
    campaign_id: str,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.EXPORT_BULK)),
) -> Response:
    report = _campaign_report(session, _get_campaign(session, campaign_id))
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["metric", "value"])
    writer.writerow(["campaign_id", report["campaign_id"]])
    writer.writerow(["state", report["state"]])
    writer.writerow(["recipients", report["recipients"]])
    for group in ("send_counts", "event_counts", "confidence_counts"):
        for name, value in report[group].items():
            writer.writerow([f"{group}.{name}", value])
    for name, value in report["rates"].items():
        writer.writerow([f"rates.{name}", value])
    return Response(
        output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="campaign-{campaign_id}-report.csv"'},
    )


@router.post("/sources", status_code=status.HTTP_201_CREATED)
def create_source(
    body: SourceCreate,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_SOURCES)),
) -> dict[str, Any]:
    from kp_database.models import Source as SourceRow

    if body.source_type != dm.SourceType.RSS and body.source_type not in (
        dm.SourceType.STIX,
        dm.SourceType.BULK_DOWNLOAD,
    ):
        raise ValidationError_(f"source type {body.source_type.value} is not implemented")
    if not body.fetch_path.startswith("/") or body.fetch_path.startswith("//"):
        raise ValidationError_("fetch_path must be an absolute path, not a URL")
    source = SourceRow(
        source_id=uuid.uuid4(),
        source_key=str(uuid.uuid4())[:8],
        name=body.name,
        source_type=body.source_type,
        base_domain=body.base_domain,
        fetch_path=body.fetch_path,
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


@router.get("/sources")
def list_sources(
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.MANAGE_SOURCES)),
) -> list[dict[str, Any]]:
    from kp_database.models import Source as SourceRow

    rows = list(session.scalars(select(SourceRow).order_by(SourceRow.name)))
    return [
        {
            "source_id": str(row.source_id),
            "name": row.name,
            "source_type": row.source_type.value,
            "base_domain": row.base_domain,
            "fetch_path": row.fetch_path,
            "enabled": row.enabled,
            "last_success_at": row.last_success_at,
            "last_attempt_at": row.last_attempt_at,
            "consecutive_failures": row.consecutive_failures,
        }
        for row in rows
    ]


@router.post("/sources/{source_id}/enable")
def enable_source(
    source_id: str,
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_SOURCES)),
) -> dict[str, Any]:
    from kp_database.models import Source as SourceRow

    source = session.get(SourceRow, uuid.UUID(source_id))
    if source is None:
        raise NotFoundError("source not found")
    if source.source_type not in (dm.SourceType.RSS, dm.SourceType.STIX, dm.SourceType.BULK_DOWNLOAD):
        raise ValidationError_("source adapter is not implemented")
    source.enabled = True
    session.commit()
    request.app.state.queue.publish("ingest", {"source_id": source_id}, idempotency_key=f"ingest:{source_id}")
    audit.record(
        actor=principal.principal_id,
        action="source.enable",
        object_type="source",
        object_id=source_id,
    )
    return {"source_id": source_id, "enabled": True, "ingestion_queued": True}


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


@router.post("/recipients/sync-directory", status_code=status.HTTP_202_ACCEPTED)
def sync_recipients_from_directory(
    request: Request,
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_RECIPIENTS)),
) -> dict[str, Any]:
    """Queue a bounded, encrypted directory synchronization."""
    job_id = str(uuid.uuid4())
    request.app.state.queue.publish(
        "directory",
        {"requested_by": principal.principal_id, "job_id": job_id},
        idempotency_key=f"directory:{job_id}",
    )
    audit.record(
        actor=principal.principal_id,
        action="directory.sync.request",
        object_type="system",
        object_id=job_id,
        detail={},
    )
    return {"queued": True, "job_id": job_id}


class AlertSubscribe(BaseModel):
    campaign_id: str
    channel: str = Field(default="web", pattern="^(web|webhook|ntfy)$")
    destination_url: str | None = Field(default=None, max_length=2048)


@router.post("/alerts/subscriptions", status_code=status.HTTP_201_CREATED)
def subscribe_alerts(
    body: AlertSubscribe,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.SUBSCRIBE_ALERTS)),
) -> dict[str, Any]:
    campaign = _get_campaign(session, body.campaign_id)
    if body.channel != "web":
        parsed = urlparse(body.destination_url or "")
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValidationError_("outbound alert destinations require an HTTPS URL without embedded credentials")
        if body.channel == "ntfy" and (
            not parsed.path.strip("/") or "/" in parsed.path.strip("/") or parsed.query or parsed.fragment
        ):
            raise ValidationError_("ntfy destinations must be an HTTPS topic URL with one path segment")
    elif body.destination_url is not None:
        raise ValidationError_("web subscriptions do not accept a destination URL")
    new_secret: str | None = None
    existing = session.scalar(
        select(AlertSubscription).where(
            AlertSubscription.user_id == uuid.UUID(principal.principal_id),
            AlertSubscription.campaign_id == campaign.campaign_id,
            AlertSubscription.channel == body.channel,
        )
    )
    if existing is not None:
        existing.active = True
        if body.destination_url and body.destination_url != existing.destination_url:
            existing.destination_url = body.destination_url
            new_secret = secrets.token_hex(32)
            existing.signing_secret = new_secret
        sub = existing
    else:
        if body.channel != "web":
            new_secret = secrets.token_hex(32)
        sub = AlertSubscription(
            alert_subscription_id=uuid.uuid4(),
            user_id=uuid.UUID(principal.principal_id),
            campaign_id=campaign.campaign_id,
            channel=body.channel,
            destination_url=body.destination_url,
            signing_secret=new_secret,
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
    return {
        "alert_subscription_id": str(sub.alert_subscription_id),
        "active": sub.active,
        "signing_secret": new_secret,
    }


@router.get("/alerts/subscriptions", status_code=status.HTTP_200_OK)
def list_alert_subscriptions(
    campaign_id: str | None = None,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.SUBSCRIBE_ALERTS)),
) -> list[dict[str, Any]]:
    stmt = select(AlertSubscription).where(AlertSubscription.user_id == uuid.UUID(principal.principal_id))
    if campaign_id:
        stmt = stmt.where(AlertSubscription.campaign_id == uuid.UUID(campaign_id))
    rows = session.execute(stmt).scalars().all()
    return [
        {
            "alert_subscription_id": str(s.alert_subscription_id),
            "campaign_id": str(s.campaign_id),
            "channel": s.channel,
            "destination_configured": bool(s.destination_url),
            "last_delivery_at": s.last_delivery_at,
            "consecutive_failures": s.consecutive_failures,
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
    sub = session.scalar(
        select(AlertSubscription).where(
            AlertSubscription.alert_subscription_id == uuid.UUID(subscription_id),
            AlertSubscription.user_id == uuid.UUID(principal.principal_id),
        )
    )
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


def _queue_campaign_alert(session: Session, request: Request, campaign: Campaign, event_type: str) -> int:
    subscriptions = list(
        session.scalars(
            select(AlertSubscription).where(
                AlertSubscription.campaign_id == campaign.campaign_id,
                AlertSubscription.active.is_(True),
                AlertSubscription.channel != "web",
            )
        )
    )
    for subscription in subscriptions:
        request.app.state.queue.publish(
            "alert",
            {
                "subscription_id": str(subscription.alert_subscription_id),
                "campaign_id": str(campaign.campaign_id),
                "event_type": event_type,
                "occurred_at": datetime.now(UTC).isoformat(),
            },
            idempotency_key=f"alert:{subscription.alert_subscription_id}:{event_type}:{campaign.campaign_id}",
        )
    return len(subscriptions)


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
    request: Request,
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
    if body.campaign_id is not None:
        campaign = session.get(Campaign, body.campaign_id)
        if campaign is not None:
            _queue_campaign_alert(session, request, campaign, "campaign.kill_switch")
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


class PrivacyVerification(BaseModel):
    method: str = Field(min_length=1, max_length=64)
    evidence_ref: str = Field(min_length=1, max_length=255)


class PrivacyFulfillment(BaseModel):
    note: str = Field(default="", max_length=2000)
    corrections: dict[str, str | None] | None = None


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
    body: PrivacyVerification,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.HANDLE_PRIVACY)),
) -> dict[str, Any]:
    request = session.get(PrivacyRequest, uuid.UUID(request_id))
    if request is None:
        raise NotFoundError("privacy request not found")
    if request.status != PrivacyRequestStatus.OPENED.value:
        raise ConflictError("only an opened privacy request can be verified")
    request.status = PrivacyRequestStatus.VERIFIED.value
    request.verified_at = datetime.now(UTC)
    request.verification_method = body.method
    request.verification_evidence_ref = body.evidence_ref
    audit.record(
        actor=principal.principal_id,
        action="privacy_request.verify",
        object_type="privacy_request",
        object_id=str(request.privacy_request_id),
    )
    session.commit()
    return {
        "privacy_request_id": str(request.privacy_request_id),
        "status": request.status,
        "verified_at": request.verified_at,
    }


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
    if request.status not in VERIFIED_PRIVACY_STATES:
        raise ConflictError("privacy request must be verified before export")
    recipients = _recipients_for_request(session, settings, request)
    from kp_database.models import RecipientAssignment, RecipientExclusion, TrackingToken, TrainingAssignment

    recipient_ids = [recipient.recipient_id for recipient in recipients]
    assignments = (
        list(session.scalars(select(RecipientAssignment).where(RecipientAssignment.recipient_id.in_(recipient_ids))))
        if recipient_ids
        else []
    )
    assignment_ids = [assignment.recipient_assignment_id for assignment in assignments]
    tokens = (
        list(session.scalars(select(TrackingToken).where(TrackingToken.recipient_assignment_id.in_(assignment_ids))))
        if assignment_ids
        else []
    )
    token_ids = [token.token_id for token in tokens]
    events = (
        list(
            session.scalars(
                select(TrackingEvent).where(
                    (TrackingEvent.recipient_id.in_(recipient_ids)) | (TrackingEvent.token_id.in_(token_ids))
                )
            )
        )
        if recipient_ids or token_ids
        else []
    )
    training = (
        list(session.scalars(select(TrainingAssignment).where(TrainingAssignment.recipient_id.in_(recipient_ids))))
        if recipient_ids
        else []
    )
    exclusions = (
        list(session.scalars(select(RecipientExclusion).where(RecipientExclusion.recipient_id.in_(recipient_ids))))
        if recipient_ids
        else []
    )
    request.exported_at = datetime.now(UTC)
    audit.record(
        actor=principal.principal_id,
        action="privacy_request.export",
        object_type="privacy_request",
        object_id=str(request.privacy_request_id),
        detail={
            "recipients": len(recipients),
            "assignments": len(assignments),
            "events": len(events),
            "training_assignments": len(training),
            "exclusions": len(exclusions),
        },
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
        "assignments": [
            {
                "recipient_assignment_id": str(row.recipient_assignment_id),
                "recipient_id": str(row.recipient_id),
                "campaign_id": str(row.campaign_id),
                "send_state": row.send_state.value,
                "created_at": row.created_at,
            }
            for row in assignments
        ],
        "events": [
            {
                "event_id": str(row.event_id),
                "recipient_id": str(row.recipient_id) if row.recipient_id else None,
                "campaign_id": str(row.campaign_id) if row.campaign_id else None,
                "event_type": row.event_type.value,
                "confidence": row.confidence.value,
                "occurred_at": row.occurred_at,
                "payload": row.payload,
            }
            for row in events
        ],
        "training_assignments": [
            {
                "training_assignment_id": str(row.training_assignment_id),
                "recipient_id": str(row.recipient_id),
                "campaign_id": str(row.campaign_id) if row.campaign_id else None,
                "status": row.status.value,
                "assigned_at": row.assigned_at,
                "completed_at": row.completed_at,
            }
            for row in training
        ],
        "exclusions": [
            {
                "recipient_exclusion_id": str(row.recipient_exclusion_id),
                "recipient_id": str(row.recipient_id),
                "exclusion_type": row.exclusion_type.value,
                "campaign_id": str(row.campaign_id) if row.campaign_id else None,
                "reason": row.reason,
                "expires_at": row.expires_at,
            }
            for row in exclusions
        ],
    }


@router.post("/privacy/requests/{request_id}/fulfill")
def fulfill_privacy_request(
    request_id: str,
    body: PrivacyFulfillment,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    settings: OperatorApiSettings = Depends(get_settings),
    principal: Principal = Depends(require_any_capability(Capability.HANDLE_PRIVACY, Capability.DELETE_DATA)),
) -> dict[str, Any]:
    request = session.get(PrivacyRequest, uuid.UUID(request_id))
    if request is None:
        raise NotFoundError("privacy request not found")
    if request.status not in VERIFIED_PRIVACY_STATES:
        raise ConflictError("privacy request must be verified before fulfillment")
    if request.request_type == dm.PrivacyRequestType.EXCEPTION:
        raise HTTPException(status_code=422, detail="exception requests require documented legal review")
    if request.request_type == dm.PrivacyRequestType.ACCESS_EXPORT and request.exported_at is None:
        raise ConflictError("access export must be generated before fulfillment")
    note = body.note
    deleted = 0
    corrected = 0
    recipients = _recipients_for_request(session, settings, request)
    request.status = PrivacyRequestStatus.IN_PROGRESS.value
    if request.request_type == dm.PrivacyRequestType.DELETION:
        for recipient in recipients:
            deleted += int(erase_recipient_data(session, recipient.recipient_id, erased_at=datetime.now(UTC)))
        request.requester_key = f"erased-request-{request.privacy_request_id}"
    elif request.request_type == dm.PrivacyRequestType.CORRECTION:
        allowed = {"employee_key", "mailbox", "display_name", "department"}
        corrections = body.corrections or {}
        if not corrections or not set(corrections).issubset(allowed):
            raise HTTPException(status_code=422, detail="corrections must contain only supported recipient fields")
        for recipient in recipients:
            for field_name, value in corrections.items():
                if field_name == "mailbox":
                    if not value:
                        raise HTTPException(status_code=422, detail="mailbox cannot be empty")
                    recipient.mailbox = value
                    recipient.mailbox_sha256 = hash_mailbox(value, settings.require_recipient_hash_salt())
                else:
                    setattr(recipient, field_name, value)
            corrected += 1
    request.status = PrivacyRequestStatus.COMPLETED.value
    request.completed_at = datetime.now(UTC)
    request.completion_note = note
    audit.record(
        actor=principal.principal_id,
        action="privacy_request.fulfill",
        object_type="privacy_request",
        object_id=str(request.privacy_request_id),
        detail={
            "request_type": request.request_type.value,
            "deleted": deleted,
            "corrected": corrected,
            "completion_note_provided": bool(note),
        },
    )
    session.commit()
    return {
        "privacy_request_id": str(request.privacy_request_id),
        "status": request.status,
        "deleted": deleted,
        "corrected": corrected,
        "matched": len(recipients),
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
    erase_recipient_data(session, recipient.recipient_id, erased_at=datetime.now(UTC))
    audit.record(
        actor=principal.principal_id,
        action="recipient.delete",
        object_type="recipient",
        object_id=str(recipient.recipient_id),
    )
    session.commit()
    return {"recipient_id": str(recipient.recipient_id), "deleted_at": recipient.deleted_at}
