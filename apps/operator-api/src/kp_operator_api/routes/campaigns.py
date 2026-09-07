"""Campaign lifecycle routes: authoring, audience, approvals, launch, reporting.

Every mutating endpoint records a hash-chained audit event and enforces RBAC.
Deterministic checks (safety validation, approval requirements, manifest
hashing) happen here, in-process, so they cannot be bypassed by the client.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import threading
import uuid
import zipfile
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from kp_authorization.rbac import Capability, Principal
from kp_contracts.generation import TRAINING_URL_PLACEHOLDER
from kp_database.audit_store import AuditStore
from kp_database.awareness_ledger import AWARENESS_LEDGER_TERMINAL_CAMPAIGN_STATES
from kp_database.campaign_service import (
    MAX_AUDIENCE_RECIPIENTS,
    AudienceDefinition,
    AudiencePreview,
    _masked_mailbox,
    audience_definition,
    audience_matches_preview,
    bind_campaign_launch_review,
    bind_campaign_training_resource,
    campaign_launch_gate_error,
    configure_campaign_audience,
    empty_audience,
    freeze_campaign_audience,
    invalidate_campaign_audience,
    invalidate_campaign_launch_review,
    prepare_campaign,
    preview_campaign_audience,
    require_bound_training_resource,
    training_binding_error,
    training_resource_content_digest,
)
from kp_database.models import (
    Campaign,
    CampaignApproval,
    CampaignAudience,
    CampaignCanaryRecipient,
    CampaignLaunchGate,
    CampaignPattern,
    DeliveryReportCorrelation,
    Microsoft365IntegrationState,
    Recipient,
    RecipientAssignment,
    RulesOfEngagement,
    TemplateVersion,
    TrackingEvent,
    TrainingAssignment,
    TrainingResource,
)
from kp_database.outbox import dispatch_after_commit, enqueue_queue
from kp_database.program_service import require_program_active_for_schedule
from kp_domain_models import models as dm
from kp_domain_models.policy import ApprovalPolicy, is_recipient_allowed
from kp_domain_models.roe import (
    recipient_domain_roe_covered,
    roe_covers_schedule,
    verify_roe_signature,
)
from kp_domain_verification.verification import (
    normalize_domain,
)
from kp_telemetry.errors import (
    ConflictError,
    NotFoundError,
    PermissionDeniedError,
    SafetyRejectionError,
    ValidationError_,
)
from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from kp_operator_api.auth import require_any_capability, require_capability
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.deps import get_audit_store, get_session, get_settings
from kp_operator_api.ratelimit import RateLimiter
from kp_operator_api.routes.alerts import _queue_campaign_alert
from kp_operator_api.routes.shared import (
    _allowlisted_validation_message,
    _get_campaign,
    _normalize_mailbox,
    _principal_uuid,
    _system_safety_state,
)
from kp_operator_api.send_policy import resolve_recipient_policy
from kp_operator_api.sending_domains_roe import (
    _GUI_COLLECTION_MAX_LIMIT,
    _GUI_COLLECTION_MAX_OFFSET,
    _roe_signing_key,
)

router = APIRouter(prefix="/api/v1")

_MAX_COVERING_ROE_CANDIDATES = 100


_CANARY_EVIDENCE_TTL = timedelta(hours=24)


# UX-011 §2b — proof send ("show me how this lands in a real mail client").
# Only before a decision is recorded: a proof exists to inform the approval, so
# it is offered exactly while the campaign is still being authored or reviewed.
_PROOF_SEND_CAMPAIGN_STATES = frozenset(
    {
        dm.CampaignState.DRAFT,
        dm.CampaignState.PENDING_APPROVAL,
    }
)


# Throttle: a proof is a REAL outbound message, so the endpoint must not be
# loopable into a mail bomb against the designated test mailbox. Two windows,
# both fail-closed (RateLimiter.allow() returns False on any backend error):
# one per authenticated actor, one for the whole deployment.
_PROOF_SEND_ACTOR_LIMIT = 3


_PROOF_SEND_GLOBAL_LIMIT = 10


_PROOF_SEND_WINDOW_SECONDS = 300.0


_PROOF_SEND_GLOBAL_KEY = "__deployment__"


_proof_send_limiter_lock = threading.Lock()


_AUDIENCE_VALIDATION_MESSAGES = frozenset(
    {
        "audience selectors exceed the 10,000-recipient configuration limit",
        "sample_size must be between 1 and 10,000",
        "sample_seed is required when sample_size is set",
        "sample_seed must be at most 128 characters",
    }
)


class CampaignCreate(BaseModel):
    pattern_id: uuid.UUID
    title: str = Field(min_length=1, max_length=255)
    sender_mailbox: str = Field(min_length=3, max_length=255)
    #: The persona display name shown in the From header (e.g. "IT Service
    #: Desk"). Optional: absent renders as a bare address, exactly as before.
    sender_display_name: str | None = Field(default=None, max_length=255)
    training_domain: str = Field(min_length=1, max_length=253)
    schedule_start: datetime
    schedule_end: datetime
    timezone: str = Field(default="UTC", min_length=1, max_length=64)
    max_recipients: int = Field(gt=0, le=10_000)
    template_version_id: uuid.UUID
    training_resource_id: uuid.UUID

    @field_validator("title")
    @classmethod
    def normalize_title(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("campaign title cannot be blank")
        return normalized

    @field_validator("sender_mailbox")
    @classmethod
    def normalize_sender_mailbox(cls, value: str) -> str:
        return _normalize_mailbox(value, max_length=255)

    @field_validator("sender_display_name")
    @classmethod
    def normalize_sender_display_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @field_validator("training_domain")
    @classmethod
    def normalize_training_domain(cls, value: str) -> str:
        normalized = normalize_domain(value)
        if normalized is None:
            raise ValueError("training domain is malformed")
        return normalized

    @field_validator("schedule_start", "schedule_end")
    @classmethod
    def require_aware_schedule(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("campaign schedule timestamps must include a timezone offset")
        return value

    @field_validator("timezone")
    @classmethod
    def validate_timezone(cls, value: str) -> str:
        normalized = value.strip()
        try:
            return ZoneInfo(normalized).key
        except (ValueError, ZoneInfoNotFoundError):
            raise ValueError("timezone must be a recognized IANA timezone") from None


class CampaignAudienceUpdate(BaseModel):
    group_ids: list[uuid.UUID] = Field(default_factory=list, max_length=10_000)
    departments: list[str] = Field(default_factory=list, max_length=256)
    statuses: list[dm.RecipientStatus] = Field(default_factory=lambda: [dm.RecipientStatus.ACTIVE], max_length=3)
    include_recipient_ids: list[uuid.UUID] = Field(default_factory=list, max_length=10_000)
    exclude_recipient_ids: list[uuid.UUID] = Field(default_factory=list, max_length=10_000)
    sample_size: int | None = Field(default=None, ge=1, le=10_000)
    sample_seed: str | None = Field(default=None, max_length=128)


class CampaignTrainingBindingUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    training_resource_id: uuid.UUID


class CampaignAudienceFreeze(BaseModel):
    preview_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class ApprovalSubmit(BaseModel):
    decision: dm.ApprovalDecision
    rationale: str | None = Field(default=None, max_length=2000)

    @field_validator("rationale")
    @classmethod
    def normalize_rationale(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


def _audience_definition_body(body: CampaignAudienceUpdate) -> AudienceDefinition:
    return AudienceDefinition(
        group_ids=tuple(body.group_ids),
        departments=tuple(body.departments),
        statuses=tuple(body.statuses),
        include_recipient_ids=tuple(body.include_recipient_ids),
        exclude_recipient_ids=tuple(body.exclude_recipient_ids),
        sample_size=body.sample_size,
        sample_seed=body.sample_seed,
    )


def _audience_preview_for_request(
    request: Request,
    session: Session,
    campaign: Campaign,
) -> AudiencePreview:
    if campaign.schedule_start is None or campaign.schedule_end is None:
        raise ValidationError_("campaign requires a schedule window before audience preview")
    allowlist, unrestricted = resolve_recipient_policy(request.app.state.settings)
    covering = _covering_roes(
        session,
        schedule_start=campaign.schedule_start,
        schedule_end=campaign.schedule_end,
        signing_key=_roe_signing_key(request.app.state.settings),
    )
    return preview_campaign_audience(
        session,
        campaign,
        allowed_domains=None if unrestricted else allowlist,
        roe_options=[(roe.roe_id, frozenset(roe.target_domains or [])) for roe in covering],
    )


def _audience_preview_payload(preview: AudiencePreview) -> dict[str, Any]:
    return {
        "campaign_id": str(preview.campaign_id),
        "audience_version": preview.audience_version,
        "configuration_hash": preview.configuration_hash,
        "preview_hash": preview.preview_hash,
        "selected_count": preview.selected_count,
        "included_count": len(preview.included),
        "excluded_count": sum(preview.excluded_counts.values()),
        "excluded_counts": preview.excluded_counts,
        "sample_size": preview.sample_size,
        "sample_seed": preview.sample_seed,
        "roe_id": str(preview.roe_id) if preview.roe_id else None,
        "over_limit": preview.over_limit,
        "diff": {
            "added": preview.added_count,
            "removed": preview.removed_count,
            "unchanged": preview.unchanged_count,
        },
        "recipients": [
            {
                "recipient_id": str(item.recipient_id),
                "recipient_hash": item.recipient_hash,
                "mailbox": item.masked_mailbox,
                "department": item.department,
                "status": item.status.value,
            }
            for item in preview.included
        ],
    }


def _require_current_frozen_audience(
    request: Request,
    session: Session,
    campaign: Campaign,
    audit: AuditStore,
    principal: Principal,
) -> AudiencePreview:
    preview = _audience_preview_for_request(request, session, campaign)
    if audience_matches_preview(session, campaign, preview):
        return preview
    audience = session.get(CampaignAudience, campaign.campaign_id, with_for_update=True)
    if audience is not None:
        invalidate_campaign_audience(session, campaign, audience)
        audit.record(
            session=session,
            actor=principal.principal_id,
            action="campaign.audience.invalidated",
            object_type="campaign",
            object_id=str(campaign.campaign_id),
            detail={"reason": "recipient_or_policy_change", "preview_hash": preview.preview_hash},
        )
        session.commit()
    raise ConflictError("campaign audience changed and must be previewed, frozen, and reviewed again")


@router.post("/campaigns", status_code=status.HTTP_201_CREATED)
def create_campaign(
    body: CampaignCreate,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.CREATE_CAMPAIGN)),
) -> dict[str, Any]:
    pattern = session.get(CampaignPattern, body.pattern_id)
    if pattern is None or pattern.approval_state != dm.PatternApprovalState.APPROVED:
        raise HTTPException(status_code=422, detail="campaign requires an approved pattern")

    template = session.get(TemplateVersion, body.template_version_id)
    if template is None or template.approval_state != dm.TemplateApprovalState.APPROVED:
        raise HTTPException(status_code=422, detail="campaign requires an approved template")

    training_resource = session.get(TrainingResource, body.training_resource_id, with_for_update=True)
    if (
        training_resource is None
        or training_resource.approval_state is not dm.TemplateApprovalState.APPROVED
        or not training_resource.requires_completion
    ):
        raise HTTPException(
            status_code=422,
            detail="campaign requires an explicitly selected approved training lesson that requires completion",
        )

    validator = session.info.get("safety_validator")
    if validator is not None:
        # The training URL is a required, renderer-owned placeholder rather
        # than a network destination. Validate it using the same relative-path
        # substitution as the generation worker so the URL parser cannot
        # misclassify ``tracking.training_url`` as an external hostname. All
        # other URLs remain unchanged and subject to the configured allowlist.
        validation_plain_text = (template.plain_text or "").replace(
            TRAINING_URL_PLACEHOLDER, "/recipient-training-link"
        )
        validation_safe_html = (
            template.safe_html.replace(TRAINING_URL_PLACEHOLDER, "/recipient-training-link")
            if template.safe_html
            else template.safe_html
        )
        verdict = validator.validate(template.subject, validation_plain_text, validation_safe_html)
        if not verdict.allowed:
            raise SafetyRejectionError("template fails deterministic safety validation")

    if body.schedule_end <= body.schedule_start:
        raise HTTPException(status_code=422, detail="schedule_end must be after schedule_start")

    campaign = Campaign(
        campaign_id=uuid.uuid4(),
        pattern_id=body.pattern_id,
        current_template_id=body.template_version_id,
        title=body.title,
        state=dm.CampaignState.DRAFT,
        sender_mailbox=body.sender_mailbox,
        sender_display_name=body.sender_display_name,
        training_domain=body.training_domain,
        schedule_start=body.schedule_start,
        schedule_end=body.schedule_end,
        timezone=body.timezone,
        max_recipients=body.max_recipients,
        created_by=uuid.UUID(principal.principal_id) if principal.principal_id != "anonymous" else None,
        expires_at=body.schedule_end,
    )
    bind_campaign_training_resource(campaign, training_resource)
    manifest = cast(str, campaign.manifest_hash)
    session.add(campaign)
    session.add(empty_audience(campaign.campaign_id))
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="campaign.create",
        object_type="campaign",
        object_id=str(campaign.campaign_id),
        detail={
            "title": body.title,
            "manifest_hash": manifest,
            "training_resource_id": str(training_resource.training_resource_id),
            "training_resource_version": training_resource.version,
            "training_resource_digest": campaign.training_resource_digest,
        },
    )
    session.commit()
    return {"campaign_id": str(campaign.campaign_id), "state": campaign.state.value}


def _training_binding_view(
    campaign: Campaign,
    resource: TrainingResource | None,
    *,
    include_content: bool = False,
) -> dict[str, Any]:
    error = training_binding_error(campaign, resource)
    view: dict[str, Any] = {
        "ready": error is None,
        "error": error,
        "training_resource_id": (
            str(campaign.training_resource_id) if campaign.training_resource_id is not None else None
        ),
        "bound_version": campaign.training_resource_version,
        "bound_content_digest": campaign.training_resource_digest,
        "title": resource.title if resource is not None else None,
        "current_version": resource.version if resource is not None else None,
        "current_approval_state": resource.approval_state.value if resource is not None else None,
        "current_content_digest": training_resource_content_digest(resource) if resource is not None else None,
    }
    if include_content:
        view["content"] = resource.content if resource is not None else None
        view["content_type"] = "text/plain"
        view["html_execution"] = False
    if resource is not None and resource.knowledge_question is not None:
        # Operator-facing review view only. The public tracking page receives
        # the question and options without the answer index; the tracking
        # service compares the submitted option server-side.
        view["knowledge_check"] = {
            "question": resource.knowledge_question,
            "options": resource.knowledge_options or [],
            "answer_index": resource.knowledge_answer_index,
        }
    return view


@router.get("/campaigns/{campaign_id}/review")
def get_campaign_review(
    campaign_id: uuid.UUID,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.VIEW_AGGREGATE)),
) -> dict[str, Any]:
    del principal
    campaign = _get_campaign(session, campaign_id)
    resource = (
        session.get(TrainingResource, campaign.training_resource_id)
        if campaign.training_resource_id is not None
        else None
    )
    launch_gate = session.get(CampaignLaunchGate, campaign.campaign_id)
    audience = session.get(CampaignAudience, campaign.campaign_id)
    template = session.get(TemplateVersion, campaign.current_template_id) if campaign.current_template_id else None
    launch_error = campaign_launch_gate_error(campaign, audience, template, launch_gate)
    canary_count = session.scalar(
        select(func.count())
        .select_from(CampaignCanaryRecipient)
        .where(CampaignCanaryRecipient.campaign_id == campaign.campaign_id)
    )
    return {
        "campaign_id": str(campaign.campaign_id),
        "title": campaign.title,
        "state": campaign.state.value,
        "manifest_hash": campaign.manifest_hash,
        "launch_review": {
            "ready": launch_error is None,
            "error": launch_error,
            "review_manifest_hash": launch_gate.review_manifest_hash if launch_gate else None,
            "state": launch_gate.state if launch_gate else "unreviewed",
            "canary_recipient_count": canary_count or 0,
            "canary_expires_at": launch_gate.canary_expires_at if launch_gate else None,
            "provider": launch_gate.provider if launch_gate else None,
            "canary_evidence_hash": launch_gate.canary_evidence_hash if launch_gate else None,
        },
        "training_lesson": _training_binding_view(campaign, resource, include_content=True),
    }


@router.put("/campaigns/{campaign_id}/training-resource")
def update_campaign_training_resource(
    campaign_id: uuid.UUID,
    body: CampaignTrainingBindingUpdate,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.CREATE_CAMPAIGN)),
) -> dict[str, Any]:
    campaign = session.scalar(select(Campaign).where(Campaign.campaign_id == campaign_id).with_for_update())
    if campaign is None:
        raise NotFoundError("campaign not found")
    if campaign.state not in {
        dm.CampaignState.DRAFT,
        dm.CampaignState.PENDING_APPROVAL,
        dm.CampaignState.APPROVED,
    }:
        raise ConflictError(
            "only a draft or not-yet-scheduled reviewed campaign can change its training lesson; "
            "create a new campaign to replace a scheduled or completed legacy campaign"
        )
    resource = session.get(TrainingResource, body.training_resource_id, with_for_update=True)
    if (
        resource is None
        or resource.approval_state is not dm.TemplateApprovalState.APPROVED
        or not resource.requires_completion
    ):
        raise ConflictError("select an approved training lesson that requires completion")
    if (
        campaign.training_resource_id == resource.training_resource_id
        and training_binding_error(campaign, resource) is None
    ):
        return {
            "campaign_id": str(campaign.campaign_id),
            "state": campaign.state.value,
            "changed": False,
            "training_lesson": _training_binding_view(campaign, resource),
        }

    previous_resource_id = campaign.training_resource_id
    previous_state = campaign.state
    bind_campaign_training_resource(campaign, resource)
    campaign.state = dm.CampaignState.DRAFT
    invalidate_campaign_launch_review(session, campaign.campaign_id)
    session.execute(delete(CampaignApproval).where(CampaignApproval.campaign_id == campaign.campaign_id))
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="campaign.training_resource.bind",
        object_type="campaign",
        object_id=str(campaign.campaign_id),
        detail={
            "previous_training_resource_id": str(previous_resource_id) if previous_resource_id else None,
            "training_resource_id": str(resource.training_resource_id),
            "training_resource_version": resource.version,
            "training_resource_digest": campaign.training_resource_digest,
            "review_state_reset": previous_state is not dm.CampaignState.DRAFT,
        },
    )
    session.commit()
    return {
        "campaign_id": str(campaign.campaign_id),
        "state": campaign.state.value,
        "changed": True,
        "training_lesson": _training_binding_view(campaign, resource),
    }


@router.get("/campaigns/{campaign_id}/audience")
def get_campaign_audience(
    campaign_id: uuid.UUID,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.VIEW_AGGREGATE)),
) -> dict[str, Any]:
    del principal
    campaign = _get_campaign(session, campaign_id)
    audience = session.get(CampaignAudience, campaign.campaign_id)
    if audience is None:
        raise NotFoundError("campaign audience not found")
    definition = audience_definition(audience)
    return {
        "campaign_id": str(campaign_id),
        "version": audience.version,
        "group_ids": [str(item) for item in definition.group_ids],
        "departments": list(definition.departments),
        "statuses": [item.value for item in definition.statuses],
        "include_recipient_ids": [str(item) for item in definition.include_recipient_ids],
        "exclude_recipient_ids": [str(item) for item in definition.exclude_recipient_ids],
        "sample_size": definition.sample_size,
        "sample_seed": definition.sample_seed,
        "configuration_hash": audience.configuration_hash,
        "preview_hash": audience.preview_hash,
        "manifest_hash": audience.manifest_hash,
        "frozen_at": audience.frozen_at,
        "legacy_requires_configuration": audience.legacy_requires_configuration,
        "roe_id": str(campaign.roe_id) if campaign.roe_id else None,
    }


@router.put("/campaigns/{campaign_id}/audience")
def update_campaign_audience(
    campaign_id: uuid.UUID,
    body: CampaignAudienceUpdate,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.CREATE_CAMPAIGN)),
) -> dict[str, Any]:
    campaign = _get_campaign(session, campaign_id)
    try:
        audience, changed = configure_campaign_audience(session, campaign, _audience_definition_body(body))
    except ValueError as exc:
        raise ValidationError_(
            _allowlisted_validation_message(
                exc,
                allowed=_AUDIENCE_VALIDATION_MESSAGES,
                fallback="campaign audience configuration is invalid",
            )
        ) from None
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="campaign.audience.configure",
        object_type="campaign",
        object_id=str(campaign_id),
        detail={
            "changed": changed,
            "audience_version": audience.version,
            "configuration_hash": audience.configuration_hash,
        },
    )
    session.commit()
    return {
        "campaign_id": str(campaign_id),
        "state": campaign.state.value,
        "audience_version": audience.version,
        "configuration_hash": audience.configuration_hash,
        "changed": changed,
        "requires_preview": audience.frozen_at is None,
    }


@router.get("/campaigns/{campaign_id}/audience/preview")
def preview_campaign_audience_route(
    campaign_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.VIEW_AGGREGATE)),
) -> dict[str, Any]:
    del principal
    campaign = _get_campaign(session, campaign_id)
    return _audience_preview_payload(_audience_preview_for_request(request, session, campaign))


@router.post("/campaigns/{campaign_id}/audience/freeze")
def freeze_campaign_audience_route(
    campaign_id: uuid.UUID,
    body: CampaignAudienceFreeze,
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.CREATE_CAMPAIGN)),
) -> dict[str, Any]:
    campaign = _get_campaign(session, campaign_id)
    preview = _audience_preview_for_request(request, session, campaign)
    audience = freeze_campaign_audience(
        session,
        campaign,
        preview,
        expected_preview_hash=body.preview_hash,
    )
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="campaign.audience.freeze",
        object_type="campaign",
        object_id=str(campaign_id),
        detail={
            "audience_version": audience.version,
            "manifest_hash": audience.manifest_hash,
            "recipient_count": len(preview.included),
            "excluded_counts": preview.excluded_counts,
            "sample_seed": preview.sample_seed,
            "roe_id": str(preview.roe_id),
        },
    )
    session.commit()
    return {
        "campaign_id": str(campaign_id),
        "audience_version": audience.version,
        "manifest_hash": audience.manifest_hash,
        "frozen_at": audience.frozen_at,
        "recipient_count": len(preview.included),
        "excluded_counts": preview.excluded_counts,
        "sample_seed": preview.sample_seed,
        "roe_id": str(preview.roe_id),
    }


@router.post("/campaigns/{campaign_id}/submit", status_code=status.HTTP_200_OK)
def submit_campaign(
    campaign_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.CREATE_CAMPAIGN)),
) -> dict[str, Any]:
    campaign = _get_campaign(session, campaign_id)
    if campaign.state != dm.CampaignState.DRAFT:
        raise ConflictError("only drafts can be submitted for approval")
    training_resource = require_bound_training_resource(session, campaign)
    _require_current_frozen_audience(request, session, campaign, audit, principal)
    template = session.get(TemplateVersion, campaign.current_template_id, with_for_update=True)
    if template is None:
        raise ConflictError("campaign requires an approved template before review")
    launch_gate = bind_campaign_launch_review(session, campaign, template, submitted_by=_principal_uuid(principal))
    campaign.state = (
        dm.CampaignState.PENDING_APPROVAL
        if request.app.state.settings.approval_policy is ApprovalPolicy.ENFORCE
        else dm.CampaignState.APPROVED
    )
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="campaign.submit",
        object_type="campaign",
        object_id=str(campaign.campaign_id),
        detail={
            "manifest_hash": campaign.manifest_hash,
            "training_resource_id": str(training_resource.training_resource_id),
            "training_resource_version": campaign.training_resource_version,
            "training_resource_digest": campaign.training_resource_digest,
            "launch_manifest_hash": launch_gate.review_manifest_hash,
            "canary_manifest_hash": launch_gate.canary_manifest_hash,
        },
    )
    session.commit()
    return {
        "campaign_id": str(campaign.campaign_id),
        "state": campaign.state.value,
        "launch_manifest_hash": launch_gate.review_manifest_hash,
    }


REQUIRED_APPROVALS: frozenset[dm.ApprovalType] = frozenset({dm.ApprovalType.SECURITY, dm.ApprovalType.PRIVACY})


_APPROVAL_CAPABILITIES: dict[dm.ApprovalType, Capability] = {
    dm.ApprovalType.SECURITY: Capability.APPROVE_SECURITY,
    dm.ApprovalType.PRIVACY: Capability.APPROVE_PRIVACY,
}


def _require_campaign_approval_capability(
    approval_type: dm.ApprovalType,
    principal: Principal = Depends(require_any_capability(Capability.APPROVE_SECURITY, Capability.APPROVE_PRIVACY)),
) -> Principal:
    """Require the capability for the requested approval lane.

    A generic campaign-approval capability previously admitted campaign
    operators to this dependency and then relied on a role-name check inside
    the endpoint. That made the lane-specific capabilities ineffective and
    incorrectly rejected administrators that held those capabilities.
    """
    required = _APPROVAL_CAPABILITIES.get(approval_type)
    if required is None:
        raise HTTPException(status_code=422, detail="unsupported approval type")
    if not principal.can(required):
        raise PermissionDeniedError("the requested approval capability is not assigned")
    return principal


def _missing_campaign_approvals(session: Session, campaign: Campaign) -> set[dm.ApprovalType]:
    """Approval types still outstanding for `campaign`.

    Only APPROVED decisions count; a REJECTED row never satisfies a requirement.
    """
    gate = session.get(CampaignLaunchGate, campaign.campaign_id)
    if gate is None:
        return set(REQUIRED_APPROVALS)
    granted = {
        row.approval_type
        for row in session.execute(
            select(CampaignApproval).where(
                CampaignApproval.campaign_id == campaign.campaign_id,
                CampaignApproval.decision == dm.ApprovalDecision.APPROVED,
                CampaignApproval.launch_manifest_hash == gate.review_manifest_hash,
            )
        )
        .scalars()
        .all()
    }
    return set(REQUIRED_APPROVALS - granted)


def _campaign_action_flags(
    campaign: Campaign,
    audience: CampaignAudience | None,
    approvals: list[CampaignApproval],
    principal: Principal,
    approval_policy: ApprovalPolicy,
    *,
    training_ready: bool = True,
    launch_gate: CampaignLaunchGate | None = None,
    launch_ready: bool = True,
) -> dict[str, bool]:
    """Derive per-campaign authority and lifecycle actions for GUI clients.

    These flags intentionally cover the stable object/identity gates. Routes
    still revalidate mutable deployment controls such as the emergency stop,
    live RoE coverage, program state, and recipient policy at mutation time.
    """

    principal_id = _principal_uuid(principal)
    is_creator = campaign.created_by == principal_id
    audience_ready = bool(audience and audience.frozen_at and not audience.legacy_requires_configuration)
    launch_hash = launch_gate.review_manifest_hash if launch_gate is not None else None
    current_approvals = [
        approval for approval in approvals if launch_hash is not None and approval.launch_manifest_hash == launch_hash
    ]
    decided_types = {approval.approval_type for approval in current_approvals}
    approved_types = {
        approval.approval_type for approval in current_approvals if approval.decision == dm.ApprovalDecision.APPROVED
    }
    # AUT-002 (already enforced server-side in ``approve_campaign``): two-person
    # review means two DISTINCT people. A principal who already approved a facet
    # of this launch manifest, or who submitted it for review, cannot approve any
    # remaining lane. Reflect that here so the "needs my decision" queue and the
    # per-row buttons never surface a decision the server will reject. This only
    # narrows a UI flag to match the existing gate; it changes no authorization.
    approved_by_me = any(
        approval.decision == dm.ApprovalDecision.APPROVED and approval.approver_id == principal_id
        for approval in current_approvals
    )
    submitted_by_me = launch_gate is not None and launch_gate.submitted_by == principal_id

    def can_review(approval_type: dm.ApprovalType, capability: Capability) -> bool:
        return not (
            campaign.state != dm.CampaignState.PENDING_APPROVAL
            or not audience_ready
            or not training_ready
            or not launch_ready
            or is_creator
            or approved_by_me
            or submitted_by_me
            or not principal.can(capability)
            or approval_type in decided_types
        )

    terminal_states = {
        dm.CampaignState.RECALLED,
        dm.CampaignState.RECALL_IN_PROGRESS,
        dm.CampaignState.EXPIRED,
        dm.CampaignState.CANCELLED,
        dm.CampaignState.COMPLETED,
        dm.CampaignState.STOPPED,
        dm.CampaignState.REJECTED,
    }
    audience_locked_states = terminal_states | {
        dm.CampaignState.SCHEDULED,
        dm.CampaignState.SENDING,
        dm.CampaignState.ACTIVE,
    }
    approval_ready = approval_policy is not ApprovalPolicy.ENFORCE or approved_types >= REQUIRED_APPROVALS
    schedule_state = campaign.state == dm.CampaignState.APPROVED
    canary_current = bool(
        launch_gate
        and launch_gate.state == "canary_succeeded"
        and launch_gate.canary_evidence_hash
        and launch_gate.canary_succeeded_at
        and launch_gate.canary_expires_at
        and launch_gate.provider
        and launch_gate.provider_config_hash
        and launch_gate.canary_expires_at > datetime.now(UTC)
    )
    return {
        "can_configure_audience": bool(
            principal.can(Capability.CREATE_CAMPAIGN) and campaign.state not in audience_locked_states
        ),
        "can_configure_training": bool(
            principal.can(Capability.CREATE_CAMPAIGN)
            and campaign.state in {dm.CampaignState.DRAFT, dm.CampaignState.PENDING_APPROVAL, dm.CampaignState.APPROVED}
        ),
        "can_submit": bool(
            principal.can(Capability.CREATE_CAMPAIGN)
            and campaign.state == dm.CampaignState.DRAFT
            and audience_ready
            and training_ready
        ),
        "can_approve_security": can_review(dm.ApprovalType.SECURITY, Capability.APPROVE_SECURITY),
        "can_approve_privacy": can_review(dm.ApprovalType.PRIVACY, Capability.APPROVE_PRIVACY),
        "can_schedule": bool(
            principal.can(Capability.SCHEDULE_CAMPAIGN)
            and schedule_state
            and audience_ready
            and approval_ready
            and training_ready
            and launch_ready
            and launch_gate is not None
            and launch_gate.state == "reviewed"
        ),
        "can_publish": bool(
            principal.can(Capability.SCHEDULE_CAMPAIGN)
            and campaign.state == dm.CampaignState.SCHEDULED
            and canary_current
            and approval_ready
            and training_ready
            and launch_ready
        ),
        # Kept in the stable response schema for old consoles. The reviewed
        # canary action is now `can_schedule`; ad-hoc test sends are disabled.
        "can_test_send": False,
        # UX-011 §2b. Read-only authority hint for the proof send. It says only
        # "this principal may ask for a proof of THIS campaign"; it says nothing
        # about where a proof would go — the destination is derived from server
        # state alone (see ``_designated_proof_recipient``) and is re-derived by
        # the worker. The route revalidates the emergency stop, the recipient
        # policy and the designation at mutation time.
        "can_proof_send": bool(
            (
                principal.can(Capability.CREATE_CAMPAIGN)
                or principal.can(Capability.APPROVE_SECURITY)
                or principal.can(Capability.APPROVE_PRIVACY)
            )
            and campaign.state in _PROOF_SEND_CAMPAIGN_STATES
            and campaign.current_template_id is not None
        ),
        "can_recall": bool(
            principal.can(Capability.STOP_CAMPAIGN)
            and campaign.state
            in {
                dm.CampaignState.APPROVED,
                dm.CampaignState.SCHEDULED,
                dm.CampaignState.SENDING,
                dm.CampaignState.ACTIVE,
            }
        ),
    }


def _covering_roes(
    session: Session, *, schedule_start: datetime, schedule_end: datetime, signing_key: bytes
) -> list[RulesOfEngagement]:
    """Unrevoked RoEs whose engagement window contains the whole delivery window.

    This is the schedule half of the authorization boundary: without at least
    one covering RoE a campaign cannot be queued at all.
    """
    roes = list(
        session.scalars(
            select(RulesOfEngagement)
            .where(
                RulesOfEngagement.revoked_at.is_(None),
                RulesOfEngagement.window_start <= schedule_start,
                RulesOfEngagement.window_end >= schedule_end,
            )
            .order_by(RulesOfEngagement.signed_at.desc(), RulesOfEngagement.roe_id.desc())
            .limit(_MAX_COVERING_ROE_CANDIDATES + 1)
        ).all()
    )
    if len(roes) > _MAX_COVERING_ROE_CANDIDATES:
        raise ConflictError("active Rules-of-Engagement candidates exceed the supported scheduling boundary")
    return [
        roe
        for roe in roes
        if verify_roe_signature(
            roe.terms_hash,
            roe.signer,
            roe.signed_at,
            roe.signature,
            authorizing_party=roe.authorizing_party,
            target_domains=roe.target_domains or [],
            window_start=roe.window_start,
            window_end=roe.window_end,
            signature_version=roe.signature_version,
            signing_key=signing_key,
        )
        and roe_covers_schedule(
            revoked_at=roe.revoked_at,
            window_start=roe.window_start,
            window_end=roe.window_end,
            schedule_start=schedule_start,
            schedule_end=schedule_end,
        )
    ]


def _campaign_assignment_mailboxes(session: Session, campaign_id: uuid.UUID) -> list[tuple[str, str]]:
    """(assignment_id, mailbox) pairs for the assignments prepared for `campaign_id`."""
    rows = session.execute(
        select(RecipientAssignment.recipient_assignment_id, Recipient.mailbox)
        .join(RecipientAssignment, RecipientAssignment.recipient_id == Recipient.recipient_id)
        .where(RecipientAssignment.campaign_id == campaign_id)
    )
    return [(str(aid), mailbox) for aid, mailbox in rows if mailbox is not None]


def _roe_covers_mailbox(roe: RulesOfEngagement, mailbox: str) -> bool:
    return recipient_domain_roe_covered(mailbox, frozenset(roe.target_domains or []))


def _publish_delivery_batches(
    request: Request,
    session: Session,
    *,
    campaign: Campaign,
    campaign_id: str,
    assignment_ids: list[str],
    tracking_bearers: dict[str, dict[str, str]],
    idempotency_prefix: str,
    test_send: bool,
    delivery_phase: str,
    launch_gate: CampaignLaunchGate,
    available_at: float | None = None,
) -> int:
    """Publish delivery work in bounded batches.

    The queue enforces a 1MiB payload cap, so a single message carrying every
    assignment id fails for large campaigns. Chunking also gives the delivery
    worker a natural unit for reusing one SMTP/ACS connection. Batch index and
    the rotated verifier generation form the idempotency key: replaying one
    committed intent is suppressed, while a deliberate re-schedule can carry
    newly rotated bearers. Assignment claims remain the final send guard.
    """
    batch_size = max(1, request.app.state.settings.delivery_batch_size)
    batches = [assignment_ids[i : i + batch_size] for i in range(0, len(assignment_ids), batch_size)] or [[]]
    for index, batch in enumerate(batches):
        payload: dict[str, Any] = {
            "campaign_id": campaign_id,
            "recipient_assignment_ids": batch,
            # Raw bearers exist only in the transient queue payload and are
            # never logged. The worker binds verifier + checksum + assignment
            # before rendering a URL.
            "tracking_bearers": {assignment_id: tracking_bearers[assignment_id] for assignment_id in batch},
            "template_hash": campaign.manifest_hash,
            "delivery_phase": delivery_phase,
            "launch_manifest_hash": launch_gate.review_manifest_hash,
        }
        if test_send:
            payload["test_send"] = True
        if delivery_phase == "full":
            payload["canary_evidence_hash"] = launch_gate.canary_evidence_hash
            payload["provider"] = launch_gate.provider
            payload["provider_config_hash"] = launch_gate.provider_config_hash
        # A retry rotates queued tracking bearers by design. Include the
        # assignment-bound verifiers so the repaired payload is not mistaken
        # for the already-dispatched stale payload. Assignment DB claims still
        # prevent a previously sent recipient from being sent twice.
        payload_generation = hashlib.sha256(
            "|".join(
                f"{assignment_id}:{tracking_bearers[assignment_id]['verifier']}" for assignment_id in batch
            ).encode("utf-8")
        ).hexdigest()[:16]
        enqueue_queue(
            session,
            topic="deliver",
            payload=payload,
            idempotency_key=f"{idempotency_prefix}:{index}:{payload_generation}",
            available_at=datetime.fromtimestamp(available_at, tz=UTC) if available_at is not None else None,
        )
    dispatch_after_commit(
        session,
        lambda: request.app.state.audit_store.dispatch_pending_queue(request.app.state.queue),
    )
    return len(batches)


@router.post("/campaigns/{campaign_id}/approvals/{approval_type}", status_code=status.HTTP_200_OK)
def approve_campaign(
    campaign_id: uuid.UUID,
    approval_type: dm.ApprovalType,
    body: ApprovalSubmit,
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(_require_campaign_approval_capability),
) -> dict[str, Any]:
    campaign = session.scalar(select(Campaign).where(Campaign.campaign_id == campaign_id).with_for_update())
    if campaign is None:
        raise NotFoundError("campaign not found")
    if campaign.state != dm.CampaignState.PENDING_APPROVAL:
        raise ConflictError("campaign is not awaiting approval")
    training_resource = require_bound_training_resource(session, campaign)
    _require_current_frozen_audience(request, session, campaign, audit, principal)
    audience = session.get(CampaignAudience, campaign.campaign_id)
    template = session.get(TemplateVersion, campaign.current_template_id)
    launch_gate = session.get(CampaignLaunchGate, campaign.campaign_id, with_for_update=True)
    launch_error = campaign_launch_gate_error(campaign, audience, template, launch_gate)
    if launch_error is not None:
        raise ConflictError(launch_error)
    if launch_gate is None:
        raise ConflictError("campaign has no durable launch review; review it again")

    principal_id = _principal_uuid(principal)
    if campaign.created_by == principal_id:
        raise PermissionDeniedError("self-approval of your own campaign is prohibited")
    # Two-person review means two DISTINCT people, not two lanes held by one
    # operator. The operator who submitted this campaign for review advanced it
    # toward launch and is treated as an author for approval purposes even if a
    # later editor changed the content: the submitter's identity is durably
    # recorded on the launch gate so the block survives edits by others.
    if launch_gate.submitted_by is not None and launch_gate.submitted_by == principal_id:
        raise PermissionDeniedError("the operator who submitted this campaign for review cannot approve it")

    existing_lane = session.scalar(
        select(CampaignApproval).where(
            CampaignApproval.campaign_id == campaign.campaign_id,
            CampaignApproval.approval_type == approval_type,
            CampaignApproval.launch_manifest_hash == launch_gate.review_manifest_hash,
        )
    )
    if existing_lane is not None:
        raise ConflictError("the requested campaign review lane has already been decided")

    # Approvals already recorded against this exact review manifest. Fetched
    # once so both the self-double-approve guard and the completion check see
    # the same set, before this decision is added.
    approved_rows = (
        session.execute(
            select(CampaignApproval).where(
                CampaignApproval.campaign_id == campaign.campaign_id,
                CampaignApproval.decision == dm.ApprovalDecision.APPROVED,
                CampaignApproval.launch_manifest_hash == launch_gate.review_manifest_hash,
            )
        )
        .scalars()
        .all()
    )
    # One operator must not satisfy both facets: reject a second APPROVED
    # decision from anyone who has already approved a facet of this review, even
    # across a different lane. This closes the single-ADMINISTRATOR path where
    # one principal holds both APPROVE_SECURITY and APPROVE_PRIVACY.
    if body.decision == dm.ApprovalDecision.APPROVED and any(row.approver_id == principal_id for row in approved_rows):
        raise PermissionDeniedError(
            "you have already approved a facet of this review; an independent approver is required"
        )

    approval = CampaignApproval(
        campaign_approval_id=uuid.uuid4(),
        campaign_id=campaign.campaign_id,
        approval_type=approval_type,
        approver_id=principal_id,
        decision=body.decision,
        rationale=body.rationale,
        decided_at=datetime.now(UTC),
        template_version_id=campaign.current_template_id,
        launch_manifest_hash=launch_gate.review_manifest_hash,
    )
    session.add(approval)

    if body.decision == dm.ApprovalDecision.APPROVED:
        types_approved = {a.approval_type for a in approved_rows}
        types_approved.add(approval_type)
        approvers = {a.approver_id for a in approved_rows}
        approvers.add(principal_id)
        # Require both facets AND two distinct human approvers. The distinct
        # count is redundant given the guards above but keeps the completion
        # rule fail-closed on its own terms.
        if types_approved >= {dm.ApprovalType.SECURITY, dm.ApprovalType.PRIVACY} and len(approvers) >= 2:
            campaign.state = dm.CampaignState.APPROVED
    else:
        campaign.state = dm.CampaignState.REJECTED
    audit.record(
        session=session,
        actor=principal.principal_id,
        action=f"campaign.approve.{approval_type.value}",
        object_type="campaign",
        object_id=str(campaign.campaign_id),
        detail={
            "decision": body.decision.value,
            "manifest_hash": campaign.manifest_hash,
            "training_resource_id": str(training_resource.training_resource_id),
            "training_resource_version": campaign.training_resource_version,
            "training_resource_digest": campaign.training_resource_digest,
            "launch_manifest_hash": launch_gate.review_manifest_hash,
        },
    )
    session.commit()
    return {"campaign_id": str(campaign.campaign_id), "state": campaign.state.value}


@router.post("/campaigns/{campaign_id}/schedule", status_code=status.HTTP_200_OK)
def schedule_campaign(
    campaign_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.SCHEDULE_CAMPAIGN)),
) -> dict[str, Any]:
    """Queue only the reviewed canary cohort; never the full audience."""

    campaign = session.scalar(select(Campaign).where(Campaign.campaign_id == campaign_id).with_for_update())
    if campaign is None:
        raise NotFoundError("campaign not found")
    try:
        require_program_active_for_schedule(session, campaign_id)
    except ConflictError:
        audit.record(
            session=session,
            actor=principal.principal_id,
            action="campaign.schedule.blocked",
            object_type="campaign",
            object_id=str(campaign.campaign_id),
            detail={"reason": "campaign_program_paused"},
        )
        session.commit()
        raise
    safety_state = _system_safety_state(session, shared_lock=True)
    if safety_state.emergency_stop_engaged:
        audit.record(
            session=session,
            actor=principal.principal_id,
            action="campaign.schedule.blocked",
            object_type="campaign",
            object_id=str(campaign.campaign_id),
            detail={"reason": "global_emergency_stop", "generation": safety_state.generation},
        )
        session.commit()
        raise ConflictError("the global emergency stop is engaged; scheduling is disabled")
    if campaign.state != dm.CampaignState.APPROVED:
        raise ConflictError("campaign must complete review before its canary can be queued")
    _require_current_frozen_audience(request, session, campaign, audit, principal)
    if request.app.state.settings.approval_policy is ApprovalPolicy.ENFORCE:
        missing = _missing_campaign_approvals(session, campaign)
        if missing:
            outstanding = sorted(approval.value for approval in missing)
            audit.record(
                session=session,
                actor=principal.principal_id,
                action="campaign.schedule.blocked",
                object_type="campaign",
                object_id=str(campaign.campaign_id),
                detail={"reason": "missing_approvals", "missing": outstanding},
            )
            session.commit()
            raise ConflictError(
                "campaign requires "
                + " and ".join(outstanding)
                + " approval before scheduling (approval policy: enforce)"
            )
    if campaign.schedule_start is None:
        raise ValidationError_("campaign requires a schedule start")
    schedule_start = campaign.schedule_start
    if schedule_start.tzinfo is None:
        raise ValidationError_("schedule start must include a timezone offset")
    if campaign.schedule_end is None:
        raise ValidationError_("campaign requires a schedule end")
    schedule_end = campaign.schedule_end
    if schedule_end.tzinfo is None:
        raise ValidationError_("schedule end must include a timezone offset")
    if schedule_end <= datetime.now(UTC):
        raise ConflictError("campaign delivery window has ended; create and review a fresh campaign")
    covering = _covering_roes(
        session,
        schedule_start=schedule_start,
        schedule_end=schedule_end,
        signing_key=_roe_signing_key(request.app.state.settings),
    )
    if not covering:
        audit.record(
            session=session,
            actor=principal.principal_id,
            action="campaign.schedule.blocked",
            object_type="campaign",
            object_id=str(campaign.campaign_id),
            detail={"reason": "no_covering_roe"},
        )
        session.commit()
        raise ConflictError(
            "no active signed Rules-of-Engagement covers this campaign's delivery window; sign an RoE before scheduling"
        )
    audience = session.get(CampaignAudience, campaign.campaign_id)
    template = session.get(TemplateVersion, campaign.current_template_id)
    gate = session.get(CampaignLaunchGate, campaign.campaign_id, with_for_update=True)
    launch_error = campaign_launch_gate_error(campaign, audience, template, gate)
    if launch_error is not None:
        raise ConflictError(launch_error)
    if gate is None or gate.state != "reviewed":
        raise ConflictError("campaign canary is not in the reviewed state")
    chosen_roe = next((roe for roe in covering if roe.roe_id == gate.roe_id), None)
    if chosen_roe is None:
        raise ConflictError("the Rules-of-Engagement bound during review is no longer active")
    canary_ids = frozenset(
        session.scalars(
            select(CampaignCanaryRecipient.recipient_id)
            .where(CampaignCanaryRecipient.campaign_id == campaign.campaign_id)
            .order_by(CampaignCanaryRecipient.ordinal)
            .limit(MAX_AUDIENCE_RECIPIENTS + 1)
        )
    )
    if not canary_ids:
        raise ConflictError("campaign review has no locked canary recipients")
    if len(canary_ids) > MAX_AUDIENCE_RECIPIENTS:
        raise ConflictError("campaign canary cohort exceeds the supported boundary")
    canary_mailboxes = list(session.scalars(select(Recipient.mailbox).where(Recipient.recipient_id.in_(canary_ids))))
    if len(canary_mailboxes) != len(canary_ids) or any(
        not _roe_covers_mailbox(chosen_roe, mailbox) for mailbox in canary_mailboxes
    ):
        raise ConflictError("the reviewed Rules-of-Engagement no longer covers the locked canary cohort")

    campaign.state = dm.CampaignState.SCHEDULED
    prepared = prepare_campaign(
        session,
        campaign,
        tracking_base_url=request.app.state.settings.tracking_base_url,
        recipient_scope=canary_ids,
        token_hmac_key=request.app.state.settings.require_tracking_token_hmac_key(),
    )
    assignment_ids = [p.assignment_id for p in prepared]
    if len(assignment_ids) != len(canary_ids):
        raise ConflictError("locked canary assignments are incomplete; create a fresh reviewed campaign")
    tracking_bearers = {
        item.assignment_id: {
            "bearer": item.bearer_token,
            "verifier": item.token_verifier,
            "checksum": item.bearer_checksum,
        }
        for item in prepared
    }
    now = datetime.now(UTC)
    gate.state = "canary_queued"
    gate.canary_queued_at = now
    gate.canary_expires_at = min(now + _CANARY_EVIDENCE_TTL, schedule_end)
    gate.updated_at = now
    batches = _publish_delivery_batches(
        request,
        session,
        campaign=campaign,
        campaign_id=str(campaign_id),
        assignment_ids=assignment_ids,
        tracking_bearers=tracking_bearers,
        idempotency_prefix=f"deliver:canary:{campaign_id}:{gate.review_manifest_hash}",
        test_send=True,
        delivery_phase="canary",
        launch_gate=gate,
    )
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="campaign.canary.queue",
        object_type="campaign",
        object_id=str(campaign.campaign_id),
        detail={
            "prepared": len(assignment_ids),
            "queued": len(assignment_ids),
            "batches": batches,
            "expires_at": gate.canary_expires_at.isoformat(),
            "roe_id": str(chosen_roe.roe_id),
            "launch_manifest_hash": gate.review_manifest_hash,
            "canary_manifest_hash": gate.canary_manifest_hash,
            "training_resource_id": str(campaign.training_resource_id),
            "training_resource_version": campaign.training_resource_version,
            "training_resource_digest": campaign.training_resource_digest,
        },
    )
    session.commit()
    return {
        "campaign_id": str(campaign.campaign_id),
        "state": campaign.state.value,
        "phase": "canary",
        "prepared": len(assignment_ids),
        "queued": len(assignment_ids),
        "canary_expires_at": gate.canary_expires_at,
    }


@router.post("/campaigns/{campaign_id}/publish", status_code=status.HTTP_200_OK)
def publish_campaign(
    campaign_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.SCHEDULE_CAMPAIGN)),
) -> dict[str, Any]:
    """Publish the non-canary audience only after current durable evidence."""

    campaign = session.scalar(select(Campaign).where(Campaign.campaign_id == campaign_id).with_for_update())
    if campaign is None:
        raise NotFoundError("campaign not found")
    require_program_active_for_schedule(session, campaign_id)
    safety_state = _system_safety_state(session, shared_lock=True)
    if safety_state.emergency_stop_engaged:
        raise ConflictError("the global emergency stop is engaged; publication is disabled")
    if campaign.state != dm.CampaignState.SCHEDULED:
        raise ConflictError("campaign must have a completed canary before full publication")
    _require_current_frozen_audience(request, session, campaign, audit, principal)
    if request.app.state.settings.approval_policy is ApprovalPolicy.ENFORCE:
        missing = _missing_campaign_approvals(session, campaign)
        if missing:
            raise ConflictError("campaign approvals do not match the current launch review")
    audience = session.get(CampaignAudience, campaign.campaign_id)
    template = session.get(TemplateVersion, campaign.current_template_id)
    gate = session.get(CampaignLaunchGate, campaign.campaign_id, with_for_update=True)
    launch_error = campaign_launch_gate_error(campaign, audience, template, gate)
    if launch_error is not None:
        raise ConflictError(launch_error)
    now = datetime.now(UTC)
    if (
        gate is None
        or gate.state != "canary_succeeded"
        or gate.canary_succeeded_at is None
        or gate.canary_evidence_hash is None
        or gate.provider is None
        or gate.provider_config_hash is None
    ):
        raise ConflictError("full publication requires successful server-derived canary evidence")
    if gate.canary_expires_at is None or gate.canary_expires_at <= now:
        gate.state = "expired"
        gate.updated_at = now
        session.commit()
        raise ConflictError("canary evidence expired; create and review a fresh campaign")
    if campaign.schedule_start is None or campaign.schedule_end is None:
        raise ValidationError_("campaign requires a schedule window")
    covering = _covering_roes(
        session,
        schedule_start=campaign.schedule_start,
        schedule_end=campaign.schedule_end,
        signing_key=_roe_signing_key(request.app.state.settings),
    )
    if not any(roe.roe_id == gate.roe_id for roe in covering):
        raise ConflictError("the Rules-of-Engagement bound during review is no longer active")
    canary_ids = frozenset(
        session.scalars(
            select(CampaignCanaryRecipient.recipient_id).where(
                CampaignCanaryRecipient.campaign_id == campaign.campaign_id
            )
        )
    )
    if not canary_ids:
        raise ConflictError("reviewed canary cohort is missing")
    prepared = prepare_campaign(
        session,
        campaign,
        tracking_base_url=request.app.state.settings.tracking_base_url,
        omit_recipient_ids=canary_ids,
        token_hmac_key=request.app.state.settings.require_tracking_token_hmac_key(),
    )
    assignment_ids = [item.assignment_id for item in prepared]
    if not assignment_ids:
        raise ConflictError("campaign has no non-canary recipients to publish")
    tracking_bearers = {
        item.assignment_id: {
            "bearer": item.bearer_token,
            "verifier": item.token_verifier,
            "checksum": item.bearer_checksum,
        }
        for item in prepared
    }
    batches = _publish_delivery_batches(
        request,
        session,
        campaign=campaign,
        campaign_id=str(campaign_id),
        assignment_ids=assignment_ids,
        tracking_bearers=tracking_bearers,
        idempotency_prefix=f"deliver:full:{campaign_id}:{gate.canary_evidence_hash}",
        test_send=False,
        delivery_phase="full",
        launch_gate=gate,
        available_at=max(campaign.schedule_start.timestamp(), now.timestamp()),
    )
    gate.state = "full_published"
    gate.full_published_at = now
    gate.updated_at = now
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="campaign.publish.full",
        object_type="campaign",
        object_id=str(campaign.campaign_id),
        detail={
            "queued": len(assignment_ids),
            "batches": batches,
            "launch_manifest_hash": gate.review_manifest_hash,
            "canary_evidence_hash": gate.canary_evidence_hash,
            "provider": gate.provider,
            "provider_config_hash": gate.provider_config_hash,
        },
    )
    _queue_campaign_alert(session, request, campaign, "campaign.scheduled")
    session.commit()
    return {
        "campaign_id": str(campaign.campaign_id),
        "state": campaign.state.value,
        "phase": "full",
        "queued": len(assignment_ids),
    }


@router.post("/campaigns/{campaign_id}/test-send", status_code=status.HTTP_200_OK)
def test_send_campaign(
    campaign_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.SEND_CAMPAIGN)),
) -> dict[str, Any]:
    campaign = _get_campaign(session, campaign_id)
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="campaign.test-send.blocked",
        object_type="campaign",
        object_id=str(campaign.campaign_id),
        detail={"reason": "durable_canary_required"},
    )
    session.commit()
    del request
    raise ConflictError(
        "ad-hoc test sends are disabled; use Review & run canary so successful evidence can gate full publication"
    )


class ProofSendRequest(BaseModel):
    """Request body for a proof send.

    SECURITY — this model deliberately carries NO destination of any kind, and
    ``extra="forbid"`` makes an attempt to smuggle one (``mailbox``,
    ``recipient_id``, ``to``, …) a 422 rather than a silently ignored field.
    The destination comes only from :func:`_designated_proof_recipient`.
    """

    model_config = ConfigDict(extra="forbid")

    confirm: StrictBool = False
    reason: str = Field(min_length=1, max_length=500)


def _proof_send_limiters(request: Request) -> tuple[RateLimiter, RateLimiter]:
    """Return the (per-actor, per-deployment) proof-send limiters.

    Built lazily on ``app.state`` so the shared limiter wiring in ``main`` is
    untouched, and configured to match it: Redis-backed (shared across
    replicas) exactly when the process-wide user limiter is, otherwise the
    same bounded in-process window.
    """

    limiters = getattr(request.app.state, "proof_send_limiters", None)
    if limiters is not None:
        return cast(tuple[RateLimiter, RateLimiter], limiters)
    with _proof_send_limiter_lock:
        limiters = getattr(request.app.state, "proof_send_limiters", None)
        if limiters is None:
            shared = getattr(request.app.state, "user_limiter", None)
            redis_url = (
                (request.app.state.settings.redis_url.strip() or None)
                if shared is not None and getattr(shared, "distributed", False)
                else None
            )
            limiters = (
                RateLimiter(
                    limit=_PROOF_SEND_ACTOR_LIMIT,
                    window_seconds=_PROOF_SEND_WINDOW_SECONDS,
                    redis_url=redis_url,
                    namespace="operator-proof-send-actor",
                ),
                RateLimiter(
                    limit=_PROOF_SEND_GLOBAL_LIMIT,
                    window_seconds=_PROOF_SEND_WINDOW_SECONDS,
                    redis_url=redis_url,
                    namespace="operator-proof-send-global",
                ),
            )
            request.app.state.proof_send_limiters = limiters
    return cast(tuple[RateLimiter, RateLimiter], limiters)


def _designated_proof_recipient(session: Session) -> Recipient:
    """The proof mailbox — derived from server state, never from the caller.

    THE security property of the proof send: a caller must not be able to
    influence WHERE a real message goes. So the destination is not read from
    the request body, the query string, the path, or any header. It is the
    deterministic first row of the *server-designated test-account* set — the
    identical ``Recipient.is_test_account`` designation that already gates the
    canary cohort (``bind_campaign_launch_review``), that only a
    ``manage:recipients`` holder can change, that requires ``confirm`` + a
    reason, that is audited as ``recipient.test-account.update``, and that is
    locked while the recipient sits in a frozen or assigned live campaign
    (``designate_test_account``).

    Ordering by ``recipient_id`` makes the choice deterministic and
    caller-independent rather than "whichever row the planner returned first".
    The response tells the operator which designated account was used, so the
    selection is visible without ever being selectable.
    """

    recipient = session.scalars(
        select(Recipient)
        .where(
            Recipient.is_test_account.is_(True),
            Recipient.status == dm.RecipientStatus.ACTIVE,
            Recipient.deleted_at.is_(None),
        )
        .order_by(Recipient.recipient_id)
        .limit(1)
    ).first()
    if recipient is None:
        raise ConflictError(
            "no server-designated test account is available; designate one under Recipients before sending a proof"
        )
    return recipient


@router.post("/campaigns/{campaign_id}/proof-send", status_code=status.HTTP_202_ACCEPTED)
def proof_send_campaign(
    campaign_id: uuid.UUID,
    body: ProofSendRequest,
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(
        require_any_capability(
            Capability.CREATE_CAMPAIGN,
            Capability.APPROVE_SECURITY,
            Capability.APPROVE_PRIVACY,
        )
    ),
) -> dict[str, Any]:
    """UX-011 §2b — queue ONE rendered proof to the designated test mailbox.

    What this is: an author or approver asking to see the campaign's own
    rendered message land in a real mail client before a decision is recorded.

    What this is NOT, by construction:

    * It is not a delivery. It creates no ``RecipientAssignment``, no
      ``TrackingToken``, no ``DeliveryCorrelation`` and no canary evidence, and
      it never writes campaign, launch-gate, audience or approval state. The
      only rows this route writes are the queue outbox message and its audit
      events.
    * It is not caller-addressable. The queue payload carries a *recipient id*
      that this route derived from server state; it never carries a mailbox,
      and the worker re-derives and re-checks the designation before sending.

    Every refusal below is recorded as ``campaign.proof-send.blocked`` so an
    auditor sees attempts, not only successes.
    """

    if not body.confirm:
        raise ValidationError_("a proof send is a real outbound message and requires confirmation (confirm=true)")
    reason = body.reason.strip()
    if not reason:
        raise ValidationError_("a proof send requires a reason")

    campaign = _get_campaign(session, campaign_id)

    def refuse(detail_reason: str, error: Exception) -> None:
        audit.record(
            session=session,
            actor=principal.principal_id,
            action="campaign.proof-send.blocked",
            object_type="campaign",
            object_id=str(campaign.campaign_id),
            detail={"reason": detail_reason, "operator_reason": reason},
        )
        session.commit()
        raise error

    if campaign.state not in _PROOF_SEND_CAMPAIGN_STATES:
        refuse(
            "campaign_state_not_proofable",
            ConflictError("a proof send is only available while a campaign is a draft or pending approval"),
        )
    if campaign.current_template_id is None:
        refuse("no_template", ConflictError("campaign has no template to prove"))

    # Throttle before anything else that could turn into outbound mail. Both
    # windows must allow; `allow()` fails closed if its backend is unavailable.
    actor_limiter, global_limiter = _proof_send_limiters(request)
    if not actor_limiter.allow(principal.principal_id) or not global_limiter.allow(_PROOF_SEND_GLOBAL_KEY):
        refuse(
            "throttled",
            HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="proof sends are throttled; wait before requesting another",
            ),
        )

    safety_state = _system_safety_state(session, shared_lock=True)
    if safety_state.emergency_stop_engaged:
        refuse(
            "global_emergency_stop",
            ConflictError("the global emergency stop is engaged; proof sends are disabled"),
        )

    recipient = _designated_proof_recipient(session)

    # Recipient policy, identical to the delivery worker's: PLT-002 makes an
    # unset allowlist a hard 422 outside an explicitly-marked dev stack, and
    # this route deliberately does not special-case around that.
    settings: OperatorApiSettings = request.app.state.settings
    allowlist, unrestricted = resolve_recipient_policy(settings)
    if not unrestricted and not is_recipient_allowed(recipient.mailbox or "", allowlist):
        refuse(
            "domain_not_allowed",
            ConflictError("the designated test mailbox is outside the recipient-domain allowlist"),
        )

    # If a signed RoE is already bound, its verified target domains bind the
    # proof too. Before review there is usually no RoE yet; this check can only
    # ever refuse more, never allow something the allowlist refused.
    if campaign.roe_id is not None:
        roe = session.get(RulesOfEngagement, campaign.roe_id)
        covered = roe is not None and recipient_domain_roe_covered(
            recipient.mailbox or "", frozenset(roe.target_domains or [])
        )
        if not covered:
            refuse(
                "target_domain_not_roe_covered",
                ConflictError("the designated test mailbox is outside this campaign's Rules-of-Engagement"),
            )

    # A proof must never touch a mailbox this campaign is actually contacting:
    # that is the one way a proof could be confused with, or double up on, a
    # real send.
    assigned = session.scalar(
        select(RecipientAssignment.recipient_assignment_id)
        .where(
            RecipientAssignment.campaign_id == campaign.campaign_id,
            RecipientAssignment.recipient_id == recipient.recipient_id,
        )
        .limit(1)
    )
    if assigned is not None:
        refuse(
            "recipient_already_assigned",
            ConflictError("the designated test mailbox is already a recipient of this campaign; no proof was sent"),
        )

    # No mailbox in the payload — the worker re-derives it from the recipient
    # row and re-checks the designation before it contacts any provider.
    enqueue_queue(
        session,
        topic="deliver",
        payload={
            "job_type": "proof_send",
            "campaign_id": str(campaign.campaign_id),
            "proof_recipient_id": str(recipient.recipient_id),
            "template_hash": campaign.manifest_hash,
            "requested_by": principal.principal_id,
        },
        idempotency_key=f"proof-send:{campaign.campaign_id}:{uuid.uuid4()}",
    )
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="campaign.proof-send.queued",
        object_type="campaign",
        object_id=str(campaign.campaign_id),
        detail={
            "proof_recipient_id": str(recipient.recipient_id),
            "destination": "server_designated_test_account",
            "template_hash": campaign.manifest_hash,
            "campaign_state": campaign.state.value,
            "operator_reason": reason,
        },
    )
    dispatch_after_commit(
        session,
        lambda: request.app.state.audit_store.dispatch_pending_queue(request.app.state.queue),
    )
    session.commit()
    payload: dict[str, Any] = {
        "campaign_id": str(campaign.campaign_id),
        "state": campaign.state.value,
        "queued": True,
        "proof_recipient_id": str(recipient.recipient_id),
        "destination": "server_designated_test_account",
    }
    # Same privacy boundary as every other recipient projection: the masked
    # mailbox appears only for the capability literally named view_named:results.
    if principal.can(Capability.VIEW_NAMED_RESULTS):
        payload["masked_mailbox"] = _masked_mailbox(recipient.mailbox)
    return payload


@router.post("/campaigns/{campaign_id}/recall", status_code=status.HTTP_200_OK)
def recall_campaign(
    campaign_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.STOP_CAMPAIGN)),
) -> dict[str, Any]:
    campaign = _get_campaign(session, campaign_id)
    if campaign.state not in {
        dm.CampaignState.APPROVED,
        dm.CampaignState.SCHEDULED,
        dm.CampaignState.SENDING,
        dm.CampaignState.ACTIVE,
    }:
        raise ConflictError("campaign is not in a recallable state")
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
        session=session,
        actor=principal.principal_id,
        action="campaign.recall",
        object_type="campaign",
        object_id=str(campaign.campaign_id),
        detail={"cancelled": len(assignments), "tokens_revoked": len(tokens)},
    )
    _queue_campaign_alert(session, request, campaign, "campaign.recalled")
    session.commit()
    return {
        "campaign_id": str(campaign.campaign_id),
        "state": campaign.state.value,
        "cancelled": len(assignments),
        "tokens_revoked": len(tokens),
    }


@router.get("/campaigns")
def list_campaigns(
    limit: int = Query(default=100, ge=1, le=_GUI_COLLECTION_MAX_LIMIT),
    offset: int = Query(default=0, ge=0, le=_GUI_COLLECTION_MAX_OFFSET),
    session: Session = Depends(get_session),
    settings: OperatorApiSettings = Depends(get_settings),
    principal: Principal = Depends(require_capability(Capability.VIEW_AGGREGATE)),
) -> list[dict[str, Any]]:
    rows = (
        session.execute(select(Campaign).order_by(Campaign.campaign_id.desc()).offset(offset).limit(limit))
        .scalars()
        .all()
    )
    audiences = {
        item.campaign_id: item
        for item in session.scalars(
            select(CampaignAudience).where(
                CampaignAudience.campaign_id.in_([campaign.campaign_id for campaign in rows])
            )
        )
    }
    launch_gates = {
        item.campaign_id: item
        for item in session.scalars(
            select(CampaignLaunchGate).where(
                CampaignLaunchGate.campaign_id.in_([campaign.campaign_id for campaign in rows])
            )
        )
    }
    approvals: dict[uuid.UUID, list[CampaignApproval]] = {}
    resource_ids = {campaign.training_resource_id for campaign in rows if campaign.training_resource_id is not None}
    training_resources = {
        resource.training_resource_id: resource
        for resource in (
            session.scalars(select(TrainingResource).where(TrainingResource.training_resource_id.in_(resource_ids)))
            if resource_ids
            else []
        )
    }
    template_ids = {campaign.current_template_id for campaign in rows if campaign.current_template_id is not None}
    templates = {
        template.template_version_id: template
        for template in (
            session.scalars(select(TemplateVersion).where(TemplateVersion.template_version_id.in_(template_ids)))
            if template_ids
            else []
        )
    }
    if rows:
        for approval in session.scalars(
            select(CampaignApproval).where(
                CampaignApproval.campaign_id.in_([campaign.campaign_id for campaign in rows])
            )
        ):
            approvals.setdefault(approval.campaign_id, []).append(approval)
    return [
        {
            "campaign_id": str(c.campaign_id),
            "title": c.title,
            "state": c.state.value,
            "schedule_start": c.schedule_start,
            "schedule_end": c.schedule_end,
            "sender_mailbox": c.sender_mailbox,
            "sender_display_name": c.sender_display_name,
            # A campaign scheduled before the RoE gate landed (or whose RoE
            # was revoked) cannot deliver until it is re-scheduled onto an
            # active RoE; the console surfaces this rather than letting the
            # operator discover it as silent no_roe blocks at delivery time.
            "roe_bound": c.roe_id is not None,
            "audience_frozen": bool(audiences.get(c.campaign_id) and audiences[c.campaign_id].frozen_at),
            "audience_version": audiences[c.campaign_id].version if c.campaign_id in audiences else None,
            "audience_legacy": bool(
                audiences.get(c.campaign_id) and audiences[c.campaign_id].legacy_requires_configuration
            ),
            "training_lesson": _training_binding_view(c, training_resources.get(c.training_resource_id)),
            "launch_gate": {
                "state": launch_gates[c.campaign_id].state,
                "review_manifest_hash": launch_gates[c.campaign_id].review_manifest_hash,
                "canary_expires_at": launch_gates[c.campaign_id].canary_expires_at,
                "provider": launch_gates[c.campaign_id].provider,
                "canary_evidence_hash": launch_gates[c.campaign_id].canary_evidence_hash,
            }
            if c.campaign_id in launch_gates
            else {
                "state": "unreviewed",
                "review_manifest_hash": None,
                "canary_expires_at": None,
                "provider": None,
                "canary_evidence_hash": None,
            },
            **_campaign_action_flags(
                c,
                audiences.get(c.campaign_id),
                approvals.get(c.campaign_id, []),
                principal,
                settings.approval_policy,
                training_ready=training_binding_error(c, training_resources.get(c.training_resource_id)) is None,
                launch_gate=launch_gates.get(c.campaign_id),
                launch_ready=campaign_launch_gate_error(
                    c,
                    audiences.get(c.campaign_id),
                    templates.get(c.current_template_id),
                    launch_gates.get(c.campaign_id),
                )
                is None,
            ),
        }
        for c in rows
    ]


@router.get("/campaigns/needs-my-decision")
def campaigns_needing_my_decision(
    limit: int = Query(default=100, ge=1, le=_GUI_COLLECTION_MAX_LIMIT),
    offset: int = Query(default=0, ge=0, le=_GUI_COLLECTION_MAX_OFFSET),
    session: Session = Depends(get_session),
    settings: OperatorApiSettings = Depends(get_settings),
    principal: Principal = Depends(require_any_capability(Capability.APPROVE_SECURITY, Capability.APPROVE_PRIVACY)),
) -> list[dict[str, Any]]:
    """Campaigns awaiting THIS principal's approval decision.

    A read-only projection of the same ``_campaign_action_flags`` the campaigns
    table already computes: a campaign appears only when a security or privacy
    lane is open *for this principal*. It therefore honours the AUT-002
    two-distinct-approver rule by construction — the flags exclude the campaign
    creator, the submitter for review, any lane already decided, and any lane
    this principal would be barred from because they already approved another
    facet. No campaign this principal already approved or submitted is shown.

    Enforces no gate of its own: ``approve_campaign`` re-checks state, frozen
    audience, the launch gate, self-approval and distinct approvers at decision
    time exactly as before.
    """
    rows = (
        session.execute(
            select(Campaign)
            .where(Campaign.state == dm.CampaignState.PENDING_APPROVAL)
            .order_by(Campaign.campaign_id.desc())
            .offset(offset)
            .limit(limit)
        )
        .scalars()
        .all()
    )
    if not rows:
        return []
    campaign_ids = [campaign.campaign_id for campaign in rows]
    audiences = {
        item.campaign_id: item
        for item in session.scalars(select(CampaignAudience).where(CampaignAudience.campaign_id.in_(campaign_ids)))
    }
    launch_gates = {
        item.campaign_id: item
        for item in session.scalars(select(CampaignLaunchGate).where(CampaignLaunchGate.campaign_id.in_(campaign_ids)))
    }
    resource_ids = {campaign.training_resource_id for campaign in rows if campaign.training_resource_id is not None}
    training_resources = {
        resource.training_resource_id: resource
        for resource in (
            session.scalars(select(TrainingResource).where(TrainingResource.training_resource_id.in_(resource_ids)))
            if resource_ids
            else []
        )
    }
    template_ids = {campaign.current_template_id for campaign in rows if campaign.current_template_id is not None}
    templates = {
        template.template_version_id: template
        for template in (
            session.scalars(select(TemplateVersion).where(TemplateVersion.template_version_id.in_(template_ids)))
            if template_ids
            else []
        )
    }
    approvals: dict[uuid.UUID, list[CampaignApproval]] = {}
    for approval in session.scalars(select(CampaignApproval).where(CampaignApproval.campaign_id.in_(campaign_ids))):
        approvals.setdefault(approval.campaign_id, []).append(approval)

    queue: list[dict[str, Any]] = []
    for c in rows:
        flags = _campaign_action_flags(
            c,
            audiences.get(c.campaign_id),
            approvals.get(c.campaign_id, []),
            principal,
            settings.approval_policy,
            training_ready=training_binding_error(c, training_resources.get(c.training_resource_id)) is None,
            launch_gate=launch_gates.get(c.campaign_id),
            launch_ready=campaign_launch_gate_error(
                c,
                audiences.get(c.campaign_id),
                templates.get(c.current_template_id),
                launch_gates.get(c.campaign_id),
            )
            is None,
        )
        if not (flags["can_approve_security"] or flags["can_approve_privacy"]):
            continue
        gate = launch_gates.get(c.campaign_id)
        audience = audiences.get(c.campaign_id)
        queue.append(
            {
                "campaign_id": str(c.campaign_id),
                "title": c.title,
                "state": c.state.value,
                "schedule_start": c.schedule_start,
                "schedule_end": c.schedule_end,
                "submitted_by": str(gate.submitted_by) if gate is not None and gate.submitted_by is not None else None,
                "audience_version": audience.version if audience is not None else None,
                "can_approve_security": flags["can_approve_security"],
                "can_approve_privacy": flags["can_approve_privacy"],
            }
        )
    return queue


def _campaign_report(session: Session, campaign: Campaign) -> dict[str, Any]:
    assignments = list(
        session.scalars(select(RecipientAssignment).where(RecipientAssignment.campaign_id == campaign.campaign_id))
    )
    events = list(session.scalars(select(TrackingEvent).where(TrackingEvent.campaign_id == campaign.campaign_id)))
    training = list(
        session.scalars(select(TrainingAssignment).where(TrainingAssignment.campaign_id == campaign.campaign_id))
    )
    send_counts = {state.value: 0 for state in dm.SendState}
    # Why sends failed, not just how many. A policy refusal
    # ("domain_not_allowed") needs a different response from an operator than a
    # transport error, and without this the console cannot tell them apart.
    failure_reasons: dict[str, int] = {}
    for assignment in assignments:
        send_counts[assignment.send_state.value] += 1
        if assignment.send_state is dm.SendState.FAILED:
            reason = assignment.failure_reason or "unspecified"
            failure_reasons[reason] = failure_reasons.get(reason, 0) + 1
    event_counts = {event_type.value: 0 for event_type in dm.EventType}
    confidence_counts = {confidence.value: 0 for confidence in dm.Confidence}
    for event in events:
        event_counts[event.event_type.value] += 1
        confidence_counts[event.confidence.value] += 1
    report_time = datetime.now(UTC)
    training_states = {state.value: 0 for state in dm.TrainingState}
    for item in training:
        state = dm.training_state(
            assigned_at=item.assigned_at,
            due_at=item.due_at,
            opened_at=item.opened_at,
            completed_at=item.completed_at,
            as_of=report_time,
        )
        training_states[state.value] += 1
    completed_training = training_states[dm.TrainingState.COMPLETED.value]
    correlation_count = len(
        list(
            session.scalars(
                select(DeliveryReportCorrelation.delivery_attempt_id)
                .join(
                    RecipientAssignment,
                    RecipientAssignment.recipient_assignment_id == DeliveryReportCorrelation.recipient_assignment_id,
                )
                .where(RecipientAssignment.campaign_id == campaign.campaign_id)
            )
        )
    )
    mailbox_state = session.scalar(
        select(Microsoft365IntegrationState)
        .where(Microsoft365IntegrationState.kind == "mailbox")
        .order_by(
            Microsoft365IntegrationState.last_attempt_at.desc().nullslast(),
            Microsoft365IntegrationState.updated_at.desc(),
        )
        .limit(1)
    )
    # SMTP/ACS currently prove provider handoff, not mailbox delivery. Keep
    # DELIVERED reserved for a future receipt connector while using every
    # confirmed handoff as the honest denominator for recipient interaction.
    accepted = send_counts.get(dm.SendState.ACCEPTED.value, 0)
    delivered = send_counts.get(dm.SendState.DELIVERED.value, 0)
    interaction_denominator = accepted + delivered
    return {
        "campaign_id": str(campaign.campaign_id),
        "title": campaign.title,
        "state": campaign.state.value,
        "schedule_start": campaign.schedule_start,
        "schedule_end": campaign.schedule_end,
        "sender_mailbox": campaign.sender_mailbox,
        "sender_display_name": campaign.sender_display_name,
        "recipients": len(assignments),
        "send_counts": send_counts,
        "failure_reasons": dict(sorted(failure_reasons.items())),
        "event_counts": event_counts,
        "confidence_counts": confidence_counts,
        "training": {"total": len(training), **training_states},
        "reported_mail_pipeline": {
            "correlated_deliveries": correlation_count,
            "reports_validated": event_counts.get(dm.EventType.MESSAGE_REPORTED.value, 0),
            "mailbox_status": mailbox_state.status if mailbox_state is not None else "never",
            "last_poll_success_at": mailbox_state.last_success_at if mailbox_state is not None else None,
            "canary_ready": bool(correlation_count and mailbox_state and mailbox_state.status == "healthy"),
        },
        "rates": {
            "denominator": interaction_denominator,
            "denominator_state": "provider_handoff",
            "opened": event_counts.get(dm.EventType.OPENED.value, 0) / interaction_denominator
            if interaction_denominator
            else 0.0,
            "clicked": event_counts.get(dm.EventType.CLICKED.value, 0) / interaction_denominator
            if interaction_denominator
            else 0.0,
            "training_completed": completed_training / len(training) if training else 0.0,
        },
    }


@router.get("/campaigns/{campaign_id}/report")
def campaign_report(
    campaign_id: uuid.UUID,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.VIEW_AGGREGATE)),
) -> dict[str, Any]:
    return _campaign_report(session, _get_campaign(session, campaign_id))


@router.post("/campaigns/{campaign_id}/training/reminders", status_code=status.HTTP_202_ACCEPTED)
def queue_training_reminders(
    campaign_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.SCHEDULE_CAMPAIGN)),
) -> dict[str, Any]:
    """Queue one idempotent scan; the worker selects only due eligible rows."""
    campaign = _get_campaign(session, campaign_id)
    if campaign.state in {
        dm.CampaignState.STOPPED,
        dm.CampaignState.CANCELLED,
        dm.CampaignState.RECALL_IN_PROGRESS,
        dm.CampaignState.RECALLED,
    }:
        raise ConflictError("training reminders are disabled for stopped or recalled campaigns")
    now = datetime.now(UTC)
    due = len(
        list(
            session.scalars(
                select(TrainingAssignment.training_assignment_id).where(
                    TrainingAssignment.campaign_id == campaign.campaign_id,
                    TrainingAssignment.completed_at.is_(None),
                    TrainingAssignment.followup_sent_at.is_(None),
                    TrainingAssignment.due_at <= now,
                    TrainingAssignment.access_expires_at > now,
                )
            )
        )
    )
    if due == 0:
        return {"queued": False, "due": 0}
    job_id = str(uuid.uuid4())
    enqueue_queue(
        session,
        topic="remind",
        payload={"campaign_id": str(campaign.campaign_id), "requested_by": principal.principal_id},
        idempotency_key=f"training-reminder:{campaign.campaign_id}:{job_id}",
    )
    dispatch_after_commit(session, lambda: audit.dispatch_pending_queue(request.app.state.queue))
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="training.reminders.queue",
        object_type="campaign",
        object_id=str(campaign.campaign_id),
        detail={"due": due, "job_id": job_id},
    )
    session.commit()
    return {"queued": True, "due": due, "job_id": job_id}


@router.get("/campaigns/{campaign_id}/recipients")
def campaign_recipient_results(
    campaign_id: uuid.UUID,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(get_session),
    _principal: Principal = Depends(require_capability(Capability.VIEW_NAMED_RESULTS)),
) -> dict[str, Any]:
    """Per-recipient outcomes for one campaign.

    Returns a masked display label (display name + masked mailbox) alongside the
    outcome for callers holding ``VIEW_NAMED_RESULTS`` — the capability whose
    literal purpose is identifying a specific person's behaviour. Raw mailboxes
    are never returned: the mailbox is masked with the same ``_masked_mailbox``
    primitive the audience preview already uses (``j***@corp.example``), so a
    reader learns no more than the audience preview already reveals to the same
    capability. This does not widen any authorization boundary.
    """
    campaign = _get_campaign(session, campaign_id)
    total = int(
        session.scalar(
            select(func.count())
            .select_from(RecipientAssignment)
            .where(RecipientAssignment.campaign_id == campaign.campaign_id)
        )
        or 0
    )
    rows = session.execute(
        select(RecipientAssignment, Recipient)
        .join(Recipient, Recipient.recipient_id == RecipientAssignment.recipient_id)
        .where(RecipientAssignment.campaign_id == campaign.campaign_id)
        .order_by(RecipientAssignment.recipient_assignment_id)
        .offset(offset)
        .limit(limit)
    ).all()

    token_ids = [assignment.token_id for assignment, _recipient in rows if assignment.token_id is not None]
    events = (
        session.scalars(
            select(TrackingEvent).where(
                TrackingEvent.campaign_id == campaign.campaign_id,
                TrackingEvent.token_id.in_(token_ids),
            )
        ).all()
        if token_ids
        else []
    )
    by_token: dict[Any, set[str]] = {}
    for event in events:
        if event.token_id is None:
            continue
        by_token.setdefault(event.token_id, set()).add(event.event_type.value)
    assignment_ids = [assignment.recipient_assignment_id for assignment, _recipient in rows]
    training_rows = (
        session.scalars(
            select(TrainingAssignment).where(
                TrainingAssignment.campaign_id == campaign.campaign_id,
                TrainingAssignment.recipient_assignment_id.in_(assignment_ids),
            )
        ).all()
        if assignment_ids
        else []
    )
    training_by_assignment = {
        item.recipient_assignment_id: item for item in training_rows if item.recipient_assignment_id is not None
    }
    report_time = datetime.now(UTC)

    results: list[dict[str, Any]] = []
    for assignment, recipient in rows:
        seen = by_token.get(assignment.token_id, set())
        training = training_by_assignment.get(assignment.recipient_assignment_id)
        confirmed_interaction = dm.EventType.HUMAN_INTERACTION_CONFIRMED.value in seen
        training_started = training is not None and training.opened_at is not None
        training_completed = training is not None and training.completed_at is not None
        # Close disposition mirrors the awareness-ledger rule: a terminal
        # campaign with no retained human activity is an explicit
        # no-activity-at-close outcome, never a silently omitted row.
        if campaign.state in AWARENESS_LEDGER_TERMINAL_CAMPAIGN_STATES:
            has_activity = any(
                (
                    dm.EventType.OPENED.value in seen,
                    dm.EventType.CLICKED.value in seen,
                    dm.EventType.MESSAGE_REPORTED.value in seen,
                    confirmed_interaction,
                    training_started,
                    training_completed,
                )
            )
            close_disposition = "no_activity_at_close" if not has_activity else "activity_at_close"
        else:
            close_disposition = None
        results.append(
            {
                "recipient_id": str(recipient.recipient_id),
                "display_name": recipient.display_name,
                "masked_mailbox": _masked_mailbox(recipient.mailbox),
                "department": recipient.department,
                "send_state": assignment.send_state.value,
                "failure_reason": assignment.failure_reason,
                "opened": dm.EventType.OPENED.value in seen,
                "clicked": dm.EventType.CLICKED.value in seen,
                "reported": dm.EventType.MESSAGE_REPORTED.value in seen,
                "confirmed_interaction": confirmed_interaction,
                "close_disposition": close_disposition,
                "training_state": (
                    dm.training_state(
                        assigned_at=training.assigned_at,
                        due_at=training.due_at,
                        opened_at=training.opened_at,
                        completed_at=training.completed_at,
                        as_of=report_time,
                    ).value
                    if training is not None
                    else None
                ),
                "training_due_at": training.due_at if training is not None else None,
            }
        )
    return {
        "items": results,
        "total": total,
        "limit": limit,
        "offset": offset,
        "truncated": offset + len(results) < total,
    }


@router.get("/campaigns/{campaign_id}/report.csv")
def campaign_report_csv(
    campaign_id: uuid.UUID,
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
    for group in ("send_counts", "failure_reasons", "event_counts", "confidence_counts"):
        for name, value in report[group].items():
            writer.writerow([f"{group}.{name}", value])
    for name, value in report["training"].items():
        writer.writerow([f"training.{name}", value])
    for name, value in report["rates"].items():
        writer.writerow([f"rates.{name}", value])
    return Response(
        output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="campaign-{campaign_id}-report.csv"'},
    )


def _evidence_json(payload: Any) -> bytes:
    """Stable, human-diffable JSON for an evidence-bundle member."""
    return json.dumps(payload, indent=2, sort_keys=True, default=str).encode("utf-8")


@router.get("/campaigns/{campaign_id}/evidence.zip")
def campaign_evidence_bundle(
    campaign_id: uuid.UUID,
    session: Session = Depends(get_session),
    _principal: Principal = Depends(require_capability(Capability.EXPORT_BULK)),
) -> Response:
    """Read-only approval/authorization evidence for one campaign, as a zip.

    A single artefact answering "who approved this, under which RoE, against
    which launch manifest and canary evidence". Every member is a projection of
    rows that already exist behind the capabilities that already guard them;
    nothing is computed or mutated. It never contains mailboxes or display
    names — recipients appear in the audience manifest only as their hash, which
    is what the frozen manifest already stores.
    """
    campaign = _get_campaign(session, campaign_id)
    gate = session.get(CampaignLaunchGate, campaign.campaign_id)
    approvals = list(
        session.scalars(
            select(CampaignApproval)
            .where(CampaignApproval.campaign_id == campaign.campaign_id)
            .order_by(CampaignApproval.decided_at)
        )
    )
    roe = session.get(RulesOfEngagement, campaign.roe_id) if campaign.roe_id is not None else None

    campaign_doc = {
        "campaign_id": str(campaign.campaign_id),
        "title": campaign.title,
        "state": campaign.state.value,
        "schedule_start": campaign.schedule_start,
        "schedule_end": campaign.schedule_end,
        "sender_mailbox": campaign.sender_mailbox,
        "sender_display_name": campaign.sender_display_name,
        "content_manifest_hash": campaign.manifest_hash,
        "training_resource_id": str(campaign.training_resource_id) if campaign.training_resource_id else None,
        "training_resource_version": campaign.training_resource_version,
        "training_resource_digest": campaign.training_resource_digest,
        "roe_id": str(campaign.roe_id) if campaign.roe_id else None,
        "launch_gate": None
        if gate is None
        else {
            "state": gate.state,
            "review_manifest_hash": gate.review_manifest_hash,
            "content_manifest_hash": gate.content_manifest_hash,
            "template_approval_hash": gate.template_approval_hash,
            "audience_manifest_hash": gate.audience_manifest_hash,
            "canary_manifest_hash": gate.canary_manifest_hash,
            "canary_evidence_hash": gate.canary_evidence_hash,
            "provider": gate.provider,
            "provider_config_hash": gate.provider_config_hash,
            "submitted_by": str(gate.submitted_by) if gate.submitted_by else None,
        },
    }
    approvals_doc = [
        {
            "approval_type": approval.approval_type.value,
            "approver_id": str(approval.approver_id),
            "decision": approval.decision.value,
            "rationale": approval.rationale,
            "decided_at": approval.decided_at,
            "launch_manifest_hash": approval.launch_manifest_hash,
        }
        for approval in approvals
    ]
    roe_doc = None
    if roe is not None:
        roe_doc = {
            "roe_id": str(roe.roe_id),
            "signer": roe.signer,
            "authorizing_party": roe.authorizing_party,
            "terms_hash": roe.terms_hash,
            "signature_version": roe.signature_version,
            "signed_at": roe.signed_at,
            "window_start": roe.window_start,
            "window_end": roe.window_end,
            "target_domains": list(roe.target_domains or []),
            "revoked_at": roe.revoked_at,
        }

    members = {
        "campaign.json": _evidence_json(campaign_doc),
        "approvals.json": _evidence_json(approvals_doc),
        "roe.json": _evidence_json(roe_doc),
    }
    manifest_lines = "".join(f"{hashlib.sha256(body).hexdigest()}  {name}\n" for name, body in sorted(members.items()))
    members["manifest.sha256"] = manifest_lines.encode("utf-8")

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, body in sorted(members.items()):
            archive.writestr(name, body)
    return Response(
        buffer.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="campaign-{campaign_id}-evidence.zip"'},
    )
