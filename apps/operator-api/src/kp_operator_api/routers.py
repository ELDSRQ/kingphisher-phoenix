"""Operator API routers: campaign lifecycle, sources, recipients, approvals,
patterns, templates, audit.

Every mutating endpoint records a hash-chained audit event and enforces
RBAC. Deterministic checks (safety validation, approval requirements,
self-approval checks on legacy review routes, manifest hashing) happen here, in-process, so they cannot
be bypassed by the client.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import io
import re
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from urllib.parse import urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from kp_authorization.rbac import Capability, Principal
from kp_contracts.generation import TRAINING_URL_PLACEHOLDER
from kp_contracts.queue import DEFAULT_QUEUE_TOPICS
from kp_database.audit_store import AuditStore
from kp_database.awareness_ledger import AWARENESS_LEDGER_TERMINAL_CAMPAIGN_STATES
from kp_database.campaign_service import (
    MAX_AUDIENCE_RECIPIENTS,
    AudienceDefinition,
    AudiencePreview,
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
    template_content_approval_hash,
    training_binding_error,
    training_resource_content_digest,
)
from kp_database.models import (
    AlertSubscription,
    AudienceGroup,
    AudienceGroupMember,
    Campaign,
    CampaignApproval,
    CampaignAudience,
    CampaignAudienceManifest,
    CampaignCanaryRecipient,
    CampaignLaunchGate,
    CampaignPattern,
    DeliveryReportCorrelation,
    Microsoft365IntegrationState,
    PrivacyNotice,
    PrivacyRequest,
    Recipient,
    RecipientAssignment,
    RecipientExclusion,
    RulesOfEngagement,
    Source,
    SourceItem,
    SourceTerms,
    SystemSafetyState,
    TemplateVersion,
    TrackingEvent,
    TrackingToken,
    TrainingAssignment,
    TrainingResource,
    VerifiedDomain,
)
from kp_database.outbox import dispatch_after_commit, enqueue_queue
from kp_database.privacy import (
    VERIFIED_PRIVACY_STATES,
    PrivacyRequestStatus,
    erase_recipient_data,
    hash_mailbox,
)
from kp_database.program_service import require_program_active_for_schedule
from kp_domain_models import models as dm
from kp_domain_models.policy import ApprovalPolicy
from kp_domain_models.roe import (
    ROE_SIGNATURE_VERSION,
    normalize_roe_domains,
    recipient_domain_roe_covered,
    roe_covers_schedule,
    roe_signature_hex,
    verify_roe_signature,
)
from kp_domain_models.source_governance import source_governance_is_current
from kp_domain_verification.lookalike import candidate_sending_domains
from kp_domain_verification.verification import (
    RelayKind,
    normalize_domain,
    required_dns_records,
    verify_domain,
)
from kp_telemetry.errors import (
    ConflictError,
    NotFoundError,
    PermissionDeniedError,
    SafetyRejectionError,
    ValidationError_,
)
from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator
from sqlalchemy import and_, delete, func, or_, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from kp_operator_api.auth import require_any_capability, require_capability
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.content_library import register_routes as register_content_library_routes
from kp_operator_api.deps import get_audit_store, get_session, get_settings
from kp_operator_api.recipient_import_planning import (
    RecipientImportApplyRequest,
    RecipientImportPreviewRequest,
    RecipientsImport,
    _apply_recipient_import_plan,
    _recipient_import_audit_detail,
    _recipient_import_issues,
    _recipient_import_options,
    _recipient_import_plan,
    _recipient_import_preview_payload,
    _recipient_import_retryable_db_conflict,
    _rollback_recipient_import_conflict,
    _serialize_recipient_import_write,
)
from kp_operator_api.send_policy import resolve_recipient_policy

router = APIRouter(prefix="/api/v1")

_GUI_COLLECTION_MAX_LIMIT = 200
_GUI_COLLECTION_MAX_OFFSET = 10_000
_MAX_COVERING_ROE_CANDIDATES = 100
_CANARY_EVIDENCE_TTL = timedelta(hours=24)
_RECIPIENT_IMPORT_REPREVIEW_CONFLICT = "recipient state changed concurrently; preview the import again"

_AUDIENCE_VALIDATION_MESSAGES = frozenset(
    {
        "audience selectors exceed the 10,000-recipient configuration limit",
        "sample_size must be between 1 and 10,000",
        "sample_seed is required when sample_size is set",
        "sample_seed must be at most 128 characters",
    }
)


def _allowlisted_validation_message(exc: ValueError, *, allowed: frozenset[str], fallback: str) -> str:
    candidate = exc.args[0] if len(exc.args) == 1 and isinstance(exc.args[0], str) else None
    return candidate if candidate in allowed else fallback


def _domain_verification_failure(error: str | None) -> str:
    if error == "challenge TXT record not found":
        return "domain not verified: challenge TXT record not found"
    if error is not None and error.startswith("not a usable domain:"):
        return "not a usable domain"
    if error is not None and error.startswith("dns error:"):
        return "domain verification unavailable because the DNS lookup failed"
    return "domain verification failed"


_MAILBOX_LOCAL_PART = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}\Z")


def _normalize_mailbox(value: str, *, max_length: int) -> str:
    """Return a conservative, storage-safe mailbox or reject it.

    The browser's ``type=email`` control is only a convenience; callers may
    use the API directly.  Keep the server boundary deliberately simple:
    quoted local parts and Unicode domains are not accepted, while explicit
    punycode remains available where required.
    """

    candidate = value.strip().lower()
    if not candidate or len(candidate) > max_length or candidate.count("@") != 1:
        raise ValueError("mailbox is malformed")
    local, domain = candidate.split("@", 1)
    normalized_domain = normalize_domain(domain)
    if (
        _MAILBOX_LOCAL_PART.fullmatch(local) is None
        or local.startswith(".")
        or local.endswith(".")
        or ".." in local
        or normalized_domain is None
        or "." not in normalized_domain
    ):
        raise ValueError("mailbox is malformed")
    normalized = f"{local}@{normalized_domain}"
    if len(normalized) > max_length:
        raise ValueError("mailbox is malformed")
    return normalized


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


class AudienceGroupUpsert(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    recipient_ids: list[uuid.UUID] = Field(default_factory=list, max_length=10_000)
    directory_group_ref: str | None = Field(default=None, max_length=256)


class DirectoryApply(BaseModel):
    preview_id: uuid.UUID


class DeadLetterReplay(BaseModel):
    confirm: bool = False


def _queue_topic(topic: str) -> str:
    if topic not in DEFAULT_QUEUE_TOPICS:
        raise ValidationError_("unknown queue topic")
    return topic


_SAFE_QUEUE_PAYLOAD_FIELDS = frozenset(
    {
        "action",
        "campaign_id",
        "pattern_id",
        "preview_id",
        "source_id",
        "retention_policy_id",
    }
)


def _safe_queue_payload(value: Any, *, field: str | None = None) -> Any:
    """Expose enough envelope structure to diagnose a job, never its PII."""
    if isinstance(value, dict):
        safe: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items(), start=1):
            key_text = str(key)
            safe_key = key_text if re.fullmatch(r"[a-z_][a-z0-9_]{0,63}", key_text) else f"redacted_field_{index}"
            safe[safe_key] = _safe_queue_payload(item, field=key_text)
        return safe
    if isinstance(value, list):
        return {"type": "list", "count": len(value)}
    if field in _SAFE_QUEUE_PAYLOAD_FIELDS and isinstance(value, str | int | float | bool | type(None)):
        return value
    return "[redacted]"


def _dead_letter_summary(item: dict[str, Any]) -> dict[str, Any]:
    message = item.get("message")
    if not isinstance(message, dict):
        return {
            "topic": item["topic"],
            "reference": item["reference"],
            "malformed": True,
            "replayable": False,
            "retry": None,
            "dead_lettered_at": None,
            "payload_field_count": 0,
        }
    payload = message.get("payload")
    return {
        "topic": item["topic"],
        "reference": item["reference"],
        "malformed": False,
        "replayable": True,
        "retry": message.get("retry"),
        "dead_lettered_at": message.get("dead_lettered_at"),
        "replay_count": message.get("replay_count", 0),
        "payload_field_count": len(payload) if isinstance(payload, dict) else 0,
    }


def _queue_reference(reference: str) -> str:
    if len(reference) > 128 or re.fullmatch(r"[A-Za-z0-9-]+", reference) is None:
        raise ValidationError_("invalid dead-letter reference")
    return reference


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


class ExclusionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    exclusion_type: dm.ExclusionType
    campaign_id: uuid.UUID | None = None
    reason: str = Field(min_length=1, max_length=500)
    expires_at: datetime | None = None

    @field_validator("reason")
    @classmethod
    def normalize_reason(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("exclusion reason cannot be blank")
        return normalized

    @field_validator("expires_at")
    @classmethod
    def require_future_aware_expiry(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("exclusion expiry must include a timezone offset")
        normalized = value.astimezone(UTC)
        if normalized <= datetime.now(UTC):
            raise ValueError("exclusion expiry must be in the future")
        return normalized


class ExclusionRevoke(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirm: StrictBool
    rationale: str = Field(min_length=1, max_length=500)

    @field_validator("rationale")
    @classmethod
    def normalize_rationale(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("exclusion revocation rationale cannot be blank")
        return normalized


class SourceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    source_type: dm.SourceType
    base_domain: str = Field(min_length=1, max_length=253)
    fetch_path: str = Field(default="/", max_length=1024)

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("source name cannot be blank")
        return normalized

    @field_validator("base_domain")
    @classmethod
    def normalize_base_domain(cls, value: str) -> str:
        normalized = normalize_domain(value)
        if normalized is None or "." not in normalized:
            raise ValueError("source base domain is malformed")
        return normalized


class SourceTermsAcknowledgement(BaseModel):
    """Explicit operator attestation for one bounded terms reference."""

    model_config = ConfigDict(extra="forbid")

    terms_reference: str = Field(min_length=1, max_length=2048)
    terms_hash: str = Field(min_length=64, max_length=64)
    commercial_use_ok: StrictBool
    automation_ok: StrictBool
    redistribution_ok: StrictBool
    retention_ok: StrictBool
    next_review_at: datetime

    @field_validator("terms_reference")
    @classmethod
    def normalize_terms_reference(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or any(ord(character) < 32 for character in normalized):
            raise ValueError("terms_reference must be a non-empty single-line reference")
        return normalized

    @field_validator("terms_hash")
    @classmethod
    def normalize_terms_hash(cls, value: str) -> str:
        normalized = value.strip().lower()
        if re.fullmatch(r"[0-9a-f]{64}", normalized) is None:
            raise ValueError("terms_hash must be a SHA-256 hexadecimal digest")
        return normalized

    @field_validator("commercial_use_ok", "automation_ok", "redistribution_ok", "retention_ok")
    @classmethod
    def require_permission_confirmation(cls, value: bool) -> bool:
        if not value:
            raise ValueError("every source-use permission must be explicitly confirmed")
        return value

    @field_validator("next_review_at")
    @classmethod
    def require_aware_next_review(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("next_review_at must include a timezone offset")
        return value


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


@router.get("/audience-groups")
def list_audience_groups(
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.VIEW_AGGREGATE)),
) -> dict[str, Any]:
    del principal
    groups = list(session.scalars(select(AudienceGroup).order_by(AudienceGroup.name).limit(10_001)))
    if len(groups) > 10_000:
        raise ConflictError("static audience groups exceed the supported 10,000-group boundary")
    # Count in Python from a bounded two-column query; this avoids a separate
    # query per group while keeping the response simple.
    member_counts: dict[uuid.UUID, int] = {}
    member_ids: dict[uuid.UUID, list[str]] = {}
    if groups:
        member_rows = list(
            session.execute(
                select(AudienceGroupMember.audience_group_id, AudienceGroupMember.recipient_id)
                .where(AudienceGroupMember.audience_group_id.in_([item.audience_group_id for item in groups]))
                .limit(10_001)
            )
        )
        if len(member_rows) > 10_000:
            raise ConflictError("static group memberships exceed the supported 10,000-recipient boundary")
        for group_id, _ in member_rows:
            member_counts[group_id] = member_counts.get(group_id, 0) + 1
        for group_id, recipient_id in member_rows:
            member_ids.setdefault(group_id, []).append(str(recipient_id))
    directory_healthy = (
        session.scalar(
            select(Microsoft365IntegrationState.integration_state_id).where(
                Microsoft365IntegrationState.kind == "directory",
                Microsoft365IntegrationState.status == "healthy",
            )
        )
        is not None
    )
    return {
        "groups": [
            {
                "audience_group_id": str(item.audience_group_id),
                "name": item.name,
                "member_count": member_counts.get(item.audience_group_id, 0),
                "recipient_ids": sorted(member_ids.get(item.audience_group_id, [])),
                "directory_group_ref": item.directory_group_ref,
                "directory_group_resolved": bool(item.directory_group_ref and directory_healthy),
            }
            for item in groups
        ]
    }


def _replace_group_members(session: Session, group: AudienceGroup, recipient_ids: list[uuid.UUID]) -> None:
    unique_ids = sorted(set(recipient_ids), key=str)
    if unique_ids:
        known = set(
            session.scalars(select(Recipient.recipient_id).where(Recipient.recipient_id.in_(unique_ids)).limit(10_001))
        )
        if known != set(unique_ids):
            raise ValidationError_("static audience group contains an unknown recipient")
    session.execute(delete(AudienceGroupMember).where(AudienceGroupMember.audience_group_id == group.audience_group_id))
    session.add_all(
        [
            AudienceGroupMember(
                audience_group_member_id=uuid.uuid4(),
                audience_group_id=group.audience_group_id,
                recipient_id=recipient_id,
            )
            for recipient_id in unique_ids
        ]
    )


def _directory_group_reference(value: str | None, settings: OperatorApiSettings) -> tuple[str | None, str | None]:
    if not value:
        return None, None
    normalized = value.strip().lower()
    digest = hmac.new(
        settings.require_recipient_hash_salt(),
        b"kp-directory-group-v1\0microsoft365\0" + normalized.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return normalized, digest


@router.post("/audience-groups", status_code=status.HTTP_201_CREATED)
def create_audience_group(
    body: AudienceGroupUpsert,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    settings: OperatorApiSettings = Depends(get_settings),
    principal: Principal = Depends(require_capability(Capability.CREATE_CAMPAIGN)),
) -> dict[str, Any]:
    name = body.name.strip()
    if session.scalar(select(AudienceGroup).where(AudienceGroup.name == name)) is not None:
        raise ConflictError("an audience group with that name already exists")
    directory_ref, directory_ref_hash = _directory_group_reference(body.directory_group_ref, settings)
    if directory_ref_hash and session.scalar(
        select(AudienceGroup).where(AudienceGroup.directory_group_ref_hash == directory_ref_hash)
    ):
        raise ConflictError("that Entra directory group is already connected")
    group = AudienceGroup(
        audience_group_id=uuid.uuid4(),
        name=name,
        directory_group_ref=directory_ref,
        directory_group_ref_hash=directory_ref_hash,
        created_by=uuid.UUID(principal.principal_id) if principal.principal_id != "anonymous" else None,
    )
    session.add(group)
    session.flush()
    _replace_group_members(session, group, body.recipient_ids)
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="audience-group.create",
        object_type="audience_group",
        object_id=str(group.audience_group_id),
        detail={"name": name, "member_count": len(set(body.recipient_ids))},
    )
    session.commit()
    return {"audience_group_id": str(group.audience_group_id), "member_count": len(set(body.recipient_ids))}


@router.put("/audience-groups/{group_id}")
def update_audience_group(
    group_id: uuid.UUID,
    body: AudienceGroupUpsert,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    settings: OperatorApiSettings = Depends(get_settings),
    principal: Principal = Depends(require_capability(Capability.CREATE_CAMPAIGN)),
) -> dict[str, Any]:
    group = session.get(AudienceGroup, group_id, with_for_update=True)
    if group is None:
        raise NotFoundError("audience group not found")
    duplicate = session.scalar(
        select(AudienceGroup).where(
            AudienceGroup.name == body.name.strip(),
            AudienceGroup.audience_group_id != group.audience_group_id,
        )
    )
    if duplicate is not None:
        raise ConflictError("an audience group with that name already exists")
    directory_ref, directory_ref_hash = _directory_group_reference(body.directory_group_ref, settings)
    duplicate_ref = (
        session.scalar(
            select(AudienceGroup).where(
                AudienceGroup.directory_group_ref_hash == directory_ref_hash,
                AudienceGroup.audience_group_id != group.audience_group_id,
            )
        )
        if directory_ref_hash
        else None
    )
    if duplicate_ref is not None:
        raise ConflictError("that Entra directory group is already connected")
    group.name = body.name.strip()
    group.directory_group_ref = directory_ref
    group.directory_group_ref_hash = directory_ref_hash
    group.updated_at = datetime.now(UTC)
    _replace_group_members(session, group, body.recipient_ids)
    impacted = list(
        session.scalars(
            select(CampaignAudience).where(CampaignAudience.group_ids.contains([str(group.audience_group_id)]))
        )
    )
    invalidated = 0
    for audience in impacted:
        campaign = session.get(Campaign, audience.campaign_id, with_for_update=True)
        if campaign is not None and audience.frozen_at is not None:
            invalidate_campaign_audience(session, campaign, audience)
            invalidated += 1
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="audience-group.update",
        object_type="audience_group",
        object_id=str(group.audience_group_id),
        detail={"member_count": len(set(body.recipient_ids)), "campaigns_invalidated": invalidated},
    )
    session.commit()
    return {
        "audience_group_id": str(group_id),
        "member_count": len(set(body.recipient_ids)),
        "invalidated": invalidated,
    }


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
    launch_gate = bind_campaign_launch_review(session, campaign, template)
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


def _principal_uuid(principal: Principal) -> uuid.UUID:
    """Return the canonical caller UUID for persisted identity comparisons."""

    try:
        return uuid.UUID(principal.principal_id)
    except ValueError as exc:
        # The authentication adapter rejects this before route dispatch. Keep
        # direct/internal calls fail-closed without reflecting the identifier.
        raise PermissionDeniedError("authenticated principal identifier is invalid") from exc


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

    def can_review(approval_type: dm.ApprovalType, capability: Capability) -> bool:
        return not (
            campaign.state != dm.CampaignState.PENDING_APPROVAL
            or not audience_ready
            or not training_ready
            or not launch_ready
            or is_creator
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

    existing_lane = session.scalar(
        select(CampaignApproval).where(
            CampaignApproval.campaign_id == campaign.campaign_id,
            CampaignApproval.approval_type == approval_type,
            CampaignApproval.launch_manifest_hash == launch_gate.review_manifest_hash,
        )
    )
    if existing_lane is not None:
        raise ConflictError("the requested campaign review lane has already been decided")

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
        existing = (
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
        types_approved = {a.approval_type for a in existing}
        types_approved.add(approval_type)
        if types_approved >= {dm.ApprovalType.SECURITY, dm.ApprovalType.PRIVACY}:
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

    Deliberately does not return mailboxes, matching `list_recipients`: an
    operator needs to know *which assignments* failed and why, not who clicked
    what. Identifying a specific person's behaviour is a different decision with
    different consequences, and the aggregate report covers the normal case.
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


def _source_terms_at(
    session: Session,
    source: Any,
) -> SourceTerms | None:
    """Return only the acknowledgement selected by and belonging to ``source``."""
    if source.license_state_id is None:
        return None
    terms = session.get(SourceTerms, source.license_state_id)
    if terms is None or terms.source_id != source.source_id:
        return None
    return terms


def _as_utc(value: datetime) -> datetime:
    # PostgreSQL returns aware values for these timestamp-with-time-zone
    # columns. Treat SQLite's naive test representation as UTC so the predicate
    # remains identical in focused lifecycle tests.
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _source_terms_are_current(terms: SourceTerms | None, *, as_of: datetime) -> bool:
    """Fail-closed source-use predicate mirrored at the worker boundary."""
    if terms is None or not terms.enabled:
        return False
    if not all(
        (
            terms.commercial_use_ok,
            terms.automation_ok,
            terms.redistribution_ok,
            terms.retention_ok,
        )
    ):
        return False
    reviewed_at = _as_utc(terms.terms_reviewed_at)
    next_review_at = _as_utc(terms.next_review_at)
    now = _as_utc(as_of)
    return reviewed_at <= now < next_review_at and reviewed_at < next_review_at


def _source_terms_payload(source: Any, terms: SourceTerms | None, *, as_of: datetime) -> dict[str, Any]:
    acknowledgement = None
    if terms is not None:
        acknowledgement = {
            "source_terms_id": str(terms.source_terms_id),
            "terms_reference": terms.terms_reference,
            "terms_hash": terms.terms_hash,
            "commercial_use_ok": terms.commercial_use_ok,
            "automation_ok": terms.automation_ok,
            "redistribution_ok": terms.redistribution_ok,
            "retention_ok": terms.retention_ok,
            "reviewed_at": terms.terms_reviewed_at,
            "next_review_at": terms.next_review_at,
            "enabled": terms.enabled,
        }
    return {
        "source_id": str(source.source_id),
        "license_state_id": str(source.license_state_id) if source.license_state_id else None,
        "governance_ready": _source_terms_are_current(terms, as_of=as_of),
        "acknowledgement": acknowledgement,
    }


def _block_source_without_current_terms(
    *,
    session: Session,
    audit: AuditStore,
    principal: Principal,
    source: Any,
) -> None:
    was_enabled = bool(source.enabled)
    source.enabled = False
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="source.governance.blocked",
        object_type="source",
        object_id=str(source.source_id),
        detail={"reason": "source_terms_not_current", "source_disabled": was_enabled},
    )
    session.commit()
    raise ConflictError("current source terms acknowledgement is required")


@router.post("/sources", status_code=status.HTTP_201_CREATED)
def create_source(
    body: SourceCreate,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.SUBMIT_SOURCE)),
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
        session=session,
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
    limit: int = Query(default=100, ge=1, le=_GUI_COLLECTION_MAX_LIMIT),
    offset: int = Query(default=0, ge=0, le=_GUI_COLLECTION_MAX_OFFSET),
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.MANAGE_SOURCES)),
) -> list[dict[str, Any]]:
    from kp_database.models import Source as SourceRow

    rows = list(
        session.scalars(select(SourceRow).order_by(SourceRow.name, SourceRow.source_id).offset(offset).limit(limit))
    )
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


@router.post("/sources/{source_id}/terms", status_code=status.HTTP_201_CREATED)
def acknowledge_source_terms(
    source_id: uuid.UUID,
    body: SourceTermsAcknowledgement,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_SOURCES)),
) -> dict[str, Any]:
    from kp_database.models import Source as SourceRow

    source = session.get(SourceRow, source_id, with_for_update=True)
    if source is None:
        raise NotFoundError("source not found")
    reviewed_at = datetime.now(UTC)
    if body.next_review_at.astimezone(UTC) <= reviewed_at:
        raise ValidationError_("next_review_at must be in the future")

    # Locking the source serializes acknowledgements for one source. Keeping
    # prior rows disabled preserves provenance while ensuring only the selected
    # current row can authorize future ingestion.
    prior_terms = session.scalars(select(SourceTerms).where(SourceTerms.source_id == source_id)).all()
    for prior in prior_terms:
        prior.enabled = False
    terms = SourceTerms(
        source_terms_id=uuid.uuid4(),
        source_id=source_id,
        terms_reference=body.terms_reference,
        terms_hash=body.terms_hash,
        commercial_use_ok=body.commercial_use_ok,
        automation_ok=body.automation_ok,
        redistribution_ok=body.redistribution_ok,
        retention_ok=body.retention_ok,
        terms_reviewed_at=reviewed_at,
        next_review_at=body.next_review_at.astimezone(UTC),
        enabled=True,
    )
    session.add(terms)
    source.license_state_id = terms.source_terms_id
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="source.terms.acknowledge",
        object_type="source",
        object_id=str(source_id),
        detail={"source_terms_id": str(terms.source_terms_id), "permissions_confirmed": True},
    )
    session.commit()
    return _source_terms_payload(source, terms, as_of=reviewed_at)


@router.get("/sources/{source_id}/terms/current")
def current_source_terms(
    source_id: uuid.UUID,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.MANAGE_SOURCES)),
) -> dict[str, Any]:
    from kp_database.models import Source as SourceRow

    source = session.get(SourceRow, source_id)
    if source is None:
        raise NotFoundError("source not found")
    terms = _source_terms_at(session, source)
    return _source_terms_payload(source, terms, as_of=datetime.now(UTC))


@router.post("/sources/{source_id}/terms/revoke")
def revoke_source_terms(
    source_id: uuid.UUID,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_SOURCES)),
) -> dict[str, Any]:
    from kp_database.models import Source as SourceRow

    source = session.get(SourceRow, source_id, with_for_update=True)
    if source is None:
        raise NotFoundError("source not found")
    terms = _source_terms_at(session, source)
    terms_changed = bool(terms is not None and terms.enabled)
    source_changed = bool(source.enabled)
    if terms is not None:
        terms.enabled = False
    source.enabled = False
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="source.terms.revoke" if terms_changed or source_changed else "source.terms.revoke.noop",
        object_type="source",
        object_id=str(source_id),
        detail={"terms_changed": terms_changed, "source_disabled": source_changed},
    )
    session.commit()
    return _source_terms_payload(source, terms, as_of=datetime.now(UTC))


@router.post("/sources/{source_id}/enable")
def enable_source(
    source_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_SOURCES)),
) -> dict[str, Any]:
    from kp_database.models import Source as SourceRow

    source = session.get(SourceRow, source_id, with_for_update=True)
    if source is None:
        raise NotFoundError("source not found")
    if source.source_type not in (dm.SourceType.RSS, dm.SourceType.STIX, dm.SourceType.BULK_DOWNLOAD):
        raise ValidationError_("source adapter is not implemented")
    terms = _source_terms_at(session, source)
    if not _source_terms_are_current(terms, as_of=datetime.now(UTC)):
        _block_source_without_current_terms(session=session, audit=audit, principal=principal, source=source)
    if source.enabled:
        audit.record(
            session=session,
            actor=principal.principal_id,
            action="source.enable.noop",
            object_type="source",
            object_id=str(source_id),
            detail={"changed": False, "ingestion_queued": False},
        )
        session.commit()
        return {
            "source_id": str(source_id),
            "enabled": True,
            "changed": False,
            "ingestion_queued": False,
            "job_id": None,
        }

    source.enabled = True
    job_id = _queue_source_ingestion(session, source_id)
    dispatch_after_commit(session, lambda: audit.dispatch_pending_queue(request.app.state.queue))
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="source.enable",
        object_type="source",
        object_id=str(source_id),
        detail={"changed": True, "ingestion_queued": True, "job_id": str(job_id)},
    )
    session.commit()
    return {
        "source_id": str(source_id),
        "enabled": True,
        "changed": True,
        "ingestion_queued": True,
        "job_id": str(job_id),
    }


def _queue_source_ingestion(session: Session, source_id: uuid.UUID) -> uuid.UUID:
    job_id = uuid.uuid4()
    enqueue_queue(
        session,
        topic="ingest",
        payload={"source_id": str(source_id), "job_id": str(job_id)},
        idempotency_key=f"ingest:{source_id}:{job_id}",
    )
    return job_id


@router.post("/sources/{source_id}/disable")
def disable_source(
    source_id: uuid.UUID,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_SOURCES)),
) -> dict[str, Any]:
    from kp_database.models import Source as SourceRow

    source = session.get(SourceRow, source_id, with_for_update=True)
    if source is None:
        raise NotFoundError("source not found")
    changed = bool(source.enabled)
    if changed:
        source.enabled = False
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="source.disable" if changed else "source.disable.noop",
        object_type="source",
        object_id=str(source_id),
        detail={"changed": changed},
    )
    session.commit()
    return {"source_id": str(source_id), "enabled": False, "changed": changed}


@router.post("/sources/{source_id}/ingest", status_code=status.HTTP_202_ACCEPTED)
def ingest_source_now(
    source_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_SOURCES)),
) -> dict[str, Any]:
    from kp_database.models import Source as SourceRow

    source = session.get(SourceRow, source_id, with_for_update=True)
    if source is None:
        raise NotFoundError("source not found")
    terms = _source_terms_at(session, source)
    if not _source_terms_are_current(terms, as_of=datetime.now(UTC)):
        _block_source_without_current_terms(session=session, audit=audit, principal=principal, source=source)
    if not source.enabled:
        raise ConflictError("source must be enabled before ingestion can be queued")
    if source.source_type not in (dm.SourceType.RSS, dm.SourceType.STIX, dm.SourceType.BULK_DOWNLOAD):
        raise ValidationError_("source adapter is not implemented")
    job_id = _queue_source_ingestion(session, source_id)
    dispatch_after_commit(session, lambda: audit.dispatch_pending_queue(request.app.state.queue))
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="source.ingest.queue",
        object_type="source",
        object_id=str(source_id),
        detail={"job_id": str(job_id)},
    )
    session.commit()
    return {
        "source_id": str(source_id),
        "enabled": True,
        "ingestion_queued": True,
        "job_id": str(job_id),
    }


@router.get("/recipients")
def list_recipients(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(get_session),
    _principal: Principal = Depends(
        require_any_capability(Capability.VIEW_NAMED_RESULTS, Capability.MANAGE_RECIPIENTS)
    ),
) -> dict[str, Any]:
    total = int(session.scalar(select(func.count()).select_from(Recipient)) or 0)
    rows = list(session.scalars(select(Recipient).order_by(Recipient.recipient_id).offset(offset).limit(limit)))
    items = [
        {
            "recipient_id": str(r.recipient_id),
            "department": r.department,
            "status": r.status.value,
            "is_test_account": r.is_test_account,
        }
        for r in rows
    ]
    return {
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
        "truncated": offset + len(items) < total,
    }


class TestAccountDesignation(BaseModel):
    is_test_account: StrictBool
    confirm: StrictBool = False
    reason: str = Field(min_length=1, max_length=500)


_CANARY_ELIGIBILITY_TERMINAL_STATES = frozenset(
    {
        dm.CampaignState.RECALLED,
        dm.CampaignState.RECALL_IN_PROGRESS,
        dm.CampaignState.EXPIRED,
        dm.CampaignState.CANCELLED,
        dm.CampaignState.COMPLETED,
        dm.CampaignState.STOPPED,
        dm.CampaignState.REJECTED,
    }
)


@router.put("/recipients/{recipient_id}/test-account", status_code=status.HTTP_200_OK)
def designate_test_account(
    recipient_id: uuid.UUID,
    body: TestAccountDesignation,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_RECIPIENTS)),
) -> dict[str, Any]:
    """Explicitly opt a recipient into or out of canary/test-send eligibility."""
    if not body.confirm:
        raise ValidationError_("test-account designation requires explicit confirmation (confirm=true)")
    reason = body.reason.strip()
    if not reason:
        raise ValidationError_("test-account designation requires a reason")

    recipient = session.get(Recipient, recipient_id, with_for_update=True)
    if recipient is None or recipient.deleted_at is not None:
        raise NotFoundError("recipient not found")
    previous = bool(recipient.is_test_account)
    requested = body.is_test_account
    changed = previous != requested
    if changed:
        protected_campaign_id = session.scalar(
            select(Campaign.campaign_id)
            .outerjoin(CampaignAudience, CampaignAudience.campaign_id == Campaign.campaign_id)
            .outerjoin(
                CampaignAudienceManifest,
                and_(
                    CampaignAudienceManifest.campaign_id == Campaign.campaign_id,
                    CampaignAudienceManifest.recipient_id == recipient.recipient_id,
                ),
            )
            .outerjoin(
                RecipientAssignment,
                and_(
                    RecipientAssignment.campaign_id == Campaign.campaign_id,
                    RecipientAssignment.recipient_id == recipient.recipient_id,
                ),
            )
            .where(
                Campaign.state.not_in(_CANARY_ELIGIBILITY_TERMINAL_STATES),
                or_(
                    and_(
                        CampaignAudience.frozen_at.is_not(None),
                        CampaignAudienceManifest.recipient_id.is_not(None),
                    ),
                    RecipientAssignment.recipient_assignment_id.is_not(None),
                ),
            )
            .limit(1)
            .with_for_update(of=Campaign)
        )
        if protected_campaign_id is not None:
            audit.record(
                session=session,
                actor=principal.principal_id,
                action="recipient.test-account.blocked",
                object_type="recipient",
                object_id=str(recipient.recipient_id),
                detail={
                    "old_is_test_account": previous,
                    "new_is_test_account": requested,
                    "changed": False,
                    "reason": reason,
                    "protected_campaign": True,
                },
            )
            session.commit()
            raise ConflictError(
                "test-account designation is locked while the recipient belongs to a frozen or assigned "
                "nonterminal campaign"
            )
        recipient.is_test_account = requested

    audit.record(
        session=session,
        actor=principal.principal_id,
        action="recipient.test-account.update",
        object_type="recipient",
        object_id=str(recipient.recipient_id),
        detail={
            "old_is_test_account": previous,
            "new_is_test_account": requested,
            "changed": changed,
            "reason": reason,
        },
    )
    session.commit()
    return {
        "recipient_id": str(recipient.recipient_id),
        "is_test_account": recipient.is_test_account,
        "changed": changed,
    }


@router.post("/recipients/{recipient_id}/exclusions", status_code=status.HTTP_201_CREATED)
def add_exclusion(
    recipient_id: uuid.UUID,
    body: ExclusionCreate,
    response: Response,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_EXCLUSIONS)),
) -> dict[str, Any]:
    recipient = session.get(Recipient, recipient_id, with_for_update=True)
    if recipient is None or recipient.deleted_at is not None or recipient.status is not dm.RecipientStatus.ACTIVE:
        raise NotFoundError("recipient not found")
    campaign_specific = body.exclusion_type is dm.ExclusionType.CAMPAIGN_SPECIFIC
    if campaign_specific != (body.campaign_id is not None):
        raise ValidationError_("campaign-specific exclusions require exactly one campaign")
    if body.campaign_id is not None and session.get(Campaign, body.campaign_id) is None:
        raise NotFoundError("campaign not found")
    now = datetime.now(UTC)
    if body.expires_at is not None and body.expires_at <= now:
        raise ValidationError_("exclusion expiry must be in the future")
    scope = (
        RecipientExclusion.campaign_id == body.campaign_id
        if body.campaign_id is not None
        else RecipientExclusion.campaign_id.is_(None)
    )
    existing = session.scalar(
        select(RecipientExclusion)
        .where(
            RecipientExclusion.recipient_id == recipient.recipient_id,
            RecipientExclusion.exclusion_type == body.exclusion_type,
            scope,
            RecipientExclusion.revoked_at.is_(None),
            RecipientExclusion.expires_at.is_(None) | (RecipientExclusion.expires_at > now),
        )
        .order_by(RecipientExclusion.created_at.desc())
        .limit(1)
        .with_for_update()
    )
    created = existing is None
    if existing is not None:
        exclusion = existing
        response.status_code = status.HTTP_200_OK
    else:
        exclusion = RecipientExclusion(
            recipient_exclusion_id=uuid.uuid4(),
            recipient_id=recipient.recipient_id,
            exclusion_type=body.exclusion_type,
            campaign_id=body.campaign_id,
            reason=body.reason,
            created_by=uuid.UUID(principal.principal_id) if principal.principal_id != "anonymous" else None,
            expires_at=body.expires_at,
        )
        session.add(exclusion)
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="recipient.exclude",
        object_type="recipient",
        object_id=str(recipient_id),
        detail={
            "exclusion_type": body.exclusion_type.value,
            "campaign_id": str(body.campaign_id) if body.campaign_id else None,
            "created": created,
        },
    )
    session.commit()
    return {"recipient_exclusion_id": str(exclusion.recipient_exclusion_id), "created": created}


def _recipient_exclusion_payload(exclusion: RecipientExclusion, *, now: datetime) -> dict[str, Any]:
    active = exclusion.revoked_at is None and (exclusion.expires_at is None or exclusion.expires_at > now)
    return {
        "recipient_exclusion_id": str(exclusion.recipient_exclusion_id),
        "recipient_id": str(exclusion.recipient_id),
        "exclusion_type": exclusion.exclusion_type.value,
        "campaign_id": str(exclusion.campaign_id) if exclusion.campaign_id else None,
        "reason": exclusion.reason[:500] if exclusion.reason else None,
        "created_by": str(exclusion.created_by) if exclusion.created_by else None,
        "created_at": exclusion.created_at,
        "expires_at": exclusion.expires_at,
        "active": active,
        "revoked_at": exclusion.revoked_at,
        "revoked_by": str(exclusion.revoked_by) if exclusion.revoked_by else None,
        "revoke_reason": exclusion.revoke_reason[:500] if exclusion.revoke_reason else None,
    }


@router.get("/recipients/{recipient_id}/exclusions", status_code=status.HTTP_200_OK)
def list_recipient_exclusions(
    recipient_id: uuid.UUID,
    include_inactive: bool = False,
    limit: int = Query(default=50, ge=1, le=100),
    session: Session = Depends(get_session),
    _principal: Principal = Depends(require_capability(Capability.MANAGE_EXCLUSIONS)),
) -> list[dict[str, Any]]:
    recipient = session.get(Recipient, recipient_id)
    if recipient is None or recipient.deleted_at is not None:
        raise NotFoundError("recipient not found")
    now = datetime.now(UTC)
    active_predicate = and_(
        RecipientExclusion.revoked_at.is_(None),
        RecipientExclusion.expires_at.is_(None) | (RecipientExclusion.expires_at > now),
    )
    active = list(
        session.scalars(
            select(RecipientExclusion)
            .where(RecipientExclusion.recipient_id == recipient_id, active_predicate)
            .order_by(RecipientExclusion.created_at.desc())
            .limit(limit)
        )
    )
    rows = active
    if include_inactive and len(rows) < limit:
        inactive = list(
            session.scalars(
                select(RecipientExclusion)
                .where(RecipientExclusion.recipient_id == recipient_id, ~active_predicate)
                .order_by(RecipientExclusion.created_at.desc())
                .limit(limit - len(rows))
            )
        )
        rows = [*active, *inactive]
    return [_recipient_exclusion_payload(row, now=now) for row in rows]


@router.post(
    "/recipients/{recipient_id}/exclusions/{exclusion_id}/revoke",
    status_code=status.HTTP_200_OK,
)
def revoke_recipient_exclusion(
    recipient_id: uuid.UUID,
    exclusion_id: uuid.UUID,
    body: ExclusionRevoke,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_EXCLUSIONS)),
) -> dict[str, Any]:
    if not body.confirm:
        raise ValidationError_("exclusion revocation requires explicit confirmation (confirm=true)")
    exclusion = session.scalar(
        select(RecipientExclusion)
        .where(
            RecipientExclusion.recipient_exclusion_id == exclusion_id,
            RecipientExclusion.recipient_id == recipient_id,
        )
        .with_for_update()
    )
    if exclusion is None:
        raise NotFoundError("recipient exclusion not found")
    changed = exclusion.revoked_at is None
    if changed:
        exclusion.revoked_at = datetime.now(UTC)
        exclusion.revoked_by = uuid.UUID(principal.principal_id) if principal.principal_id != "anonymous" else None
        exclusion.revoke_reason = body.rationale
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="recipient.exclusion.revoke",
        object_type="recipient",
        object_id=str(recipient_id),
        detail={
            "recipient_exclusion_id": str(exclusion_id),
            "exclusion_type": exclusion.exclusion_type.value,
            "campaign_id": str(exclusion.campaign_id) if exclusion.campaign_id else None,
            "changed": changed,
        },
    )
    session.commit()
    return {
        "recipient_exclusion_id": str(exclusion.recipient_exclusion_id),
        "active": False,
        "changed": changed,
        "revoked_at": exclusion.revoked_at,
    }


@router.post("/recipients/import/preview", status_code=status.HTTP_200_OK)
def preview_recipients_csv(
    body: RecipientImportPreviewRequest,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    settings: OperatorApiSettings = Depends(get_settings),
    principal: Principal = Depends(require_capability(Capability.MANAGE_RECIPIENTS)),
) -> dict[str, Any]:
    plan = _recipient_import_plan(body, session, settings, lock_rows=False)
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="recipient.import.preview",
        object_type="recipients",
        object_id="csv",
        detail=_recipient_import_audit_detail(body, plan),
    )
    session.commit()
    return _recipient_import_preview_payload(body, plan)


@router.post("/recipients/import/apply", status_code=status.HTTP_200_OK)
def apply_recipients_csv(
    body: RecipientImportApplyRequest,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    settings: OperatorApiSettings = Depends(get_settings),
    principal: Principal = Depends(require_capability(Capability.MANAGE_RECIPIENTS)),
) -> dict[str, Any]:
    if body.deactivate_missing and not body.deactivate_missing_confirm:
        raise ValidationError_("deactivate-missing requires a second explicit confirmation")
    try:
        with _serialize_recipient_import_write(session):
            plan = _recipient_import_plan(body, session, settings, lock_rows=True)
            if not hmac.compare_digest(body.preview_digest, plan.digest):
                raise ConflictError(
                    "CSV, import options, recipient state, or domain policy changed; preview the import again"
                )
            if not plan.can_apply:
                raise ConflictError(
                    "deactivate-missing requires a clean preview with no blocked, invalid, or duplicate rows"
                )
            _apply_recipient_import_plan(plan, session)
            audit.record(
                session=session,
                actor=principal.principal_id,
                action="recipient.import.apply",
                object_type="recipients",
                object_id="csv",
                detail=_recipient_import_audit_detail(body, plan),
            )
            session.commit()
    except DBAPIError as exc:
        if not _recipient_import_retryable_db_conflict(exc):
            raise
        _rollback_recipient_import_conflict(session)
        raise ConflictError(_RECIPIENT_IMPORT_REPREVIEW_CONFLICT) from None
    return {
        "preview_digest": plan.digest,
        "counts": plan.counts,
        "errors": _recipient_import_issues(plan),
        "applied": True,
    }


@router.post("/recipients/import", status_code=status.HTTP_201_CREATED)
def import_recipients_csv(
    body: RecipientsImport,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    settings: OperatorApiSettings = Depends(get_settings),
    principal: Principal = Depends(require_capability(Capability.MANAGE_RECIPIENTS)),
) -> dict[str, Any]:
    preview_body = RecipientImportPreviewRequest(csv_text=body.csv_text, department=body.department)
    try:
        with _serialize_recipient_import_write(session):
            plan = _recipient_import_plan(preview_body, session, settings, lock_rows=True)
            _apply_recipient_import_plan(plan, session)
            audit.record(
                session=session,
                actor=principal.principal_id,
                action="recipient.import",
                object_type="recipients",
                object_id="csv",
                detail={
                    **_recipient_import_audit_detail(preview_body, plan),
                    "options": {**_recipient_import_options(preview_body, plan), "legacy_skip_only": True},
                },
            )
            session.commit()
    except DBAPIError as exc:
        if not _recipient_import_retryable_db_conflict(exc):
            raise
        _rollback_recipient_import_conflict(session)
        raise ConflictError(_RECIPIENT_IMPORT_REPREVIEW_CONFLICT) from None
    return {
        "created": plan.counts["created"],
        "skipped": plan.counts["existing"] + plan.counts["duplicate"],
        "blocked": plan.counts["blocked"],
        "errors": [f"row {issue.row}: {issue.code}" for issue in plan.parsed.errors],
    }


@router.post("/recipients/sync-directory", status_code=status.HTTP_202_ACCEPTED)
def sync_recipients_from_directory(
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_RECIPIENTS)),
) -> dict[str, Any]:
    """Compatibility alias: queue a preview, never an implicit apply."""
    _require_integration_action(session, kind="directory")
    job_id = str(uuid.uuid4())
    enqueue_queue(
        session,
        topic="directory",
        payload={"action": "preview", "requested_by": principal.principal_id, "job_id": job_id},
        idempotency_key=f"directory:preview:{job_id}",
    )
    dispatch_after_commit(session, lambda: audit.dispatch_pending_queue(request.app.state.queue))
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="directory.preview.request",
        object_type="system",
        object_id=job_id,
        detail={},
    )
    session.commit()
    return {"queued": True, "job_id": job_id, "action": "preview"}


_INTEGRATION_PROVIDERS = {
    "directory": frozenset({"microsoft365"}),
    "mailbox": frozenset({"microsoft365", "mailpit"}),
}
_UNCONFIGURED_INTEGRATION_STATES = frozenset({"unconfigured", "configuration_error"})
_UNAVAILABLE_INTEGRATION_STATES = frozenset({"disabled", "unavailable"})


def _is_durable_fingerprint(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _integration_configuration_reason(state: Microsoft365IntegrationState | None, *, kind: str) -> str | None:
    label = "directory" if kind == "directory" else "reported mailbox"
    if state is None:
        return f"The {label} worker has not registered a durable configuration."
    if state.kind != kind or state.provider not in _INTEGRATION_PROVIDERS[kind]:
        return f"The selected {label} provider is not supported."
    if not _is_durable_fingerprint(state.scope_hash) or not _is_durable_fingerprint(state.config_fingerprint):
        return f"The {label} integration has not completed durable configuration."
    if state.status in _UNCONFIGURED_INTEGRATION_STATES:
        return f"The {label} integration reports an invalid or incomplete configuration."
    return None


def _integration_action_reason(state: Microsoft365IntegrationState | None, *, kind: str) -> str | None:
    reason = _integration_configuration_reason(state, kind=kind)
    if reason is not None:
        return reason
    if state is not None and state.status in _UNAVAILABLE_INTEGRATION_STATES:
        label = "directory" if kind == "directory" else "reported mailbox"
        return f"The {label} worker or provider is currently unavailable."
    return None


def _latest_integration_state(session: Session, *, kind: str) -> Microsoft365IntegrationState | None:
    return session.scalar(
        select(Microsoft365IntegrationState)
        .where(Microsoft365IntegrationState.kind == kind)
        .order_by(
            Microsoft365IntegrationState.updated_at.desc(),
            Microsoft365IntegrationState.last_attempt_at.desc().nullslast(),
        )
        .limit(1)
    )


def _require_integration_action(session: Session, *, kind: str) -> Microsoft365IntegrationState:
    state = _latest_integration_state(session, kind=kind)
    reason = _integration_action_reason(state, kind=kind)
    if reason is not None:
        raise ConflictError(reason)
    if state is None:
        # Keep this invariant fail-closed even under optimized Python, and
        # defend against future drift in the readiness-reason helper.
        raise ConflictError("Microsoft 365 integration state is unavailable")
    return state


def _integration_state_payload(
    state: Microsoft365IntegrationState | None,
    *,
    kind: str,
) -> dict[str, Any]:
    configuration_reason = _integration_configuration_reason(state, kind=kind)
    action_reason = _integration_action_reason(state, kind=kind)
    if state is None:
        return {
            "configured": False,
            "configuration_reason": configuration_reason,
            "provider": None,
            "status": "never",
            "last_attempt_at": None,
            "last_success_at": None,
            "last_applied_at": None,
            "cursor_present": False,
            "cursor_age_seconds": None,
            "counts": {},
            "last_error": None,
            "preview_id": None,
            "preview_expires_at": None,
            "apply_available": False,
            "discard_available": False,
            "action_available": False,
            "action_unavailable_reason": action_reason,
        }
    age = None
    if state.last_success_at is not None:
        last_success = state.last_success_at
        if last_success.tzinfo is None:
            last_success = last_success.replace(tzinfo=UTC)
        age = max(0, int((datetime.now(UTC) - last_success).total_seconds()))
    preview_current = False
    if state.pending_preview_id is not None and state.pending_expires_at is not None:
        expires_at = state.pending_expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        preview_current = expires_at > datetime.now(UTC)
    return {
        "configured": configuration_reason is None,
        "configuration_reason": configuration_reason,
        "provider": state.provider,
        "status": state.status,
        "last_attempt_at": state.last_attempt_at,
        "last_success_at": state.last_success_at,
        "last_applied_at": state.last_applied_at,
        "cursor_present": state.cursor is not None,
        "cursor_age_seconds": age,
        "counts": state.last_counts or {},
        "last_error": state.last_error,
        "preview_id": str(state.pending_preview_id) if state.pending_preview_id else None,
        "preview_hash": state.pending_preview_hash,
        "preview_expires_at": state.pending_expires_at,
        "apply_available": bool(action_reason is None and state.status == "preview_ready" and preview_current),
        "discard_available": bool(action_reason is None and state.pending_preview_id),
        "action_available": action_reason is None,
        "action_unavailable_reason": action_reason,
    }


@router.get("/integrations/microsoft365/status")
def microsoft365_integration_status(
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.VIEW_AGGREGATE)),
) -> dict[str, Any]:
    del principal
    states: dict[str, Microsoft365IntegrationState] = {}
    for state in session.scalars(
        select(Microsoft365IntegrationState).order_by(
            Microsoft365IntegrationState.updated_at.desc(),
            Microsoft365IntegrationState.last_attempt_at.desc().nullslast(),
        )
    ):
        states.setdefault(state.kind, state)
    directory = _integration_state_payload(states.get("directory"), kind="directory")
    mailbox = _integration_state_payload(states.get("mailbox"), kind="mailbox")
    return {
        "directory": directory,
        "reported_mailbox": mailbox,
        "directory_preview_available": directory["action_available"],
        "directory_preview_unavailable_reason": directory["action_unavailable_reason"],
        "mailbox_poll_available": mailbox["action_available"],
        "mailbox_poll_unavailable_reason": mailbox["action_unavailable_reason"],
    }


@router.post("/recipients/directory/preview", status_code=status.HTTP_202_ACCEPTED)
def preview_recipients_from_directory(
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_RECIPIENTS)),
) -> dict[str, Any]:
    return sync_recipients_from_directory(request, session, audit, principal)


@router.post("/recipients/directory/apply", status_code=status.HTTP_202_ACCEPTED)
def apply_recipients_from_directory(
    body: DirectoryApply,
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_RECIPIENTS)),
) -> dict[str, Any]:
    state = _require_integration_action(session, kind="directory")
    expires_at = state.pending_expires_at
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if (
        state.pending_preview_id != body.preview_id
        or state.status != "preview_ready"
        or expires_at is None
        or expires_at <= datetime.now(UTC)
    ):
        raise ConflictError("directory preview is missing, stale or already applied")
    job_id = str(uuid.uuid4())
    enqueue_queue(
        session,
        topic="directory",
        payload={
            "action": "apply",
            "preview_id": str(body.preview_id),
            "requested_by": principal.principal_id,
            "job_id": job_id,
        },
        idempotency_key=f"directory:apply:{body.preview_id}",
    )
    dispatch_after_commit(session, lambda: audit.dispatch_pending_queue(request.app.state.queue))
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="directory.apply.request",
        object_type="system",
        object_id=job_id,
        detail={"preview_id": str(body.preview_id)},
    )
    session.commit()
    return {"queued": True, "job_id": job_id, "preview_id": str(body.preview_id)}


@router.post("/recipients/directory/discard", status_code=status.HTTP_202_ACCEPTED)
def discard_directory_preview(
    body: DirectoryApply,
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_RECIPIENTS)),
) -> dict[str, Any]:
    state = _require_integration_action(session, kind="directory")
    if state.pending_preview_id != body.preview_id:
        raise ConflictError("directory preview is missing, stale or already discarded")
    job_id = str(uuid.uuid4())
    enqueue_queue(
        session,
        topic="directory",
        payload={
            "action": "discard",
            "preview_id": str(body.preview_id),
            "requested_by": principal.principal_id,
            "job_id": job_id,
        },
        idempotency_key=f"directory:discard:{body.preview_id}",
    )
    dispatch_after_commit(session, lambda: audit.dispatch_pending_queue(request.app.state.queue))
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="directory.discard.request",
        object_type="system",
        object_id=job_id,
        detail={"preview_id": str(body.preview_id)},
    )
    session.commit()
    return {"queued": True, "job_id": job_id, "preview_id": str(body.preview_id)}


@router.post("/integrations/reported-mail/poll", status_code=status.HTTP_202_ACCEPTED)
def poll_reported_mailbox(
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_RECIPIENTS)),
) -> dict[str, Any]:
    _require_integration_action(session, kind="mailbox")
    job_id = str(uuid.uuid4())
    enqueue_queue(
        session,
        topic="mailbox",
        payload={"requested_by": principal.principal_id, "job_id": job_id},
        idempotency_key=f"mailbox:poll:{job_id}",
    )
    dispatch_after_commit(session, lambda: audit.dispatch_pending_queue(request.app.state.queue))
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="mailbox.poll.request",
        object_type="system",
        object_id=job_id,
        detail={},
    )
    session.commit()
    return {"queued": True, "job_id": job_id}


class AlertSubscribe(BaseModel):
    campaign_id: uuid.UUID
    channel: str = Field(default="web", pattern="^(web|webhook|ntfy)$")
    destination_url: str | None = Field(default=None, max_length=2048)


def _alert_destination_is_allowlisted(host: str, allowlist: frozenset[str]) -> bool:
    """Mirror the worker's exact host-or-www policy before persistence."""

    normalized_host = host.lower().removeprefix("www.")
    return any(normalized_host == domain.lower().removeprefix("www.") for domain in allowlist)


@router.post("/alerts/subscriptions", status_code=status.HTTP_201_CREATED)
def subscribe_alerts(
    body: AlertSubscribe,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    settings: OperatorApiSettings = Depends(get_settings),
    principal: Principal = Depends(require_capability(Capability.SUBSCRIBE_ALERTS)),
) -> dict[str, Any]:
    campaign = _get_campaign(session, body.campaign_id)
    if body.channel != "web":
        parsed = urlparse(body.destination_url or "")
        try:
            port = parsed.port
        except ValueError:
            port = -1
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or port not in (None, 443)
            or parsed.fragment
        ):
            raise ValidationError_("outbound alert destinations require an HTTPS URL without embedded credentials")
        if not _alert_destination_is_allowlisted(
            parsed.hostname,
            settings.alert_webhook_domain_allowlist(),
        ):
            raise ValidationError_("outbound alert destination is not in the configured domain allowlist")
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
        session=session,
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
    campaign_id: uuid.UUID | None = None,
    limit: int = Query(default=100, ge=1, le=_GUI_COLLECTION_MAX_LIMIT),
    offset: int = Query(default=0, ge=0, le=_GUI_COLLECTION_MAX_OFFSET),
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.SUBSCRIBE_ALERTS)),
) -> list[dict[str, Any]]:
    stmt = select(AlertSubscription).where(AlertSubscription.user_id == uuid.UUID(principal.principal_id))
    if campaign_id:
        stmt = stmt.where(AlertSubscription.campaign_id == campaign_id)
    rows = (
        session.execute(
            stmt.order_by(AlertSubscription.campaign_id, AlertSubscription.alert_subscription_id)
            .offset(offset)
            .limit(limit)
        )
        .scalars()
        .all()
    )
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
    subscription_id: uuid.UUID,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.SUBSCRIBE_ALERTS)),
) -> dict[str, Any]:
    sub = session.scalar(
        select(AlertSubscription).where(
            AlertSubscription.alert_subscription_id == subscription_id,
            AlertSubscription.user_id == uuid.UUID(principal.principal_id),
        )
    )
    if sub is None:
        raise NotFoundError("subscription not found")
    sub.active = False
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="alerts.unsubscribe",
        object_type="campaign",
        object_id=str(sub.campaign_id),
        detail={"channel": sub.channel},
    )
    session.commit()
    return {"alert_subscription_id": str(subscription_id), "active": False}


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
        enqueue_queue(
            session,
            topic="alert",
            payload={
                "subscription_id": str(subscription.alert_subscription_id),
                "campaign_id": str(campaign.campaign_id),
                "event_type": event_type,
                "occurred_at": datetime.now(UTC).isoformat(),
            },
            idempotency_key=f"alert:{subscription.alert_subscription_id}:{event_type}:{campaign.campaign_id}",
        )
    dispatch_after_commit(
        session,
        lambda: request.app.state.audit_store.dispatch_pending_queue(request.app.state.queue),
    )
    return len(subscriptions)


register_content_library_routes(router)


def _pattern_source_item_id(pattern: CampaignPattern) -> uuid.UUID | None:
    """Return validated source provenance without acquiring database locks."""

    attack_mapping = pattern.attack_mapping
    if not isinstance(attack_mapping, dict) or "source_item_id" not in attack_mapping:
        return None
    raw_source_item_id = attack_mapping.get("source_item_id")
    if not isinstance(raw_source_item_id, str):
        raise SafetyRejectionError("pattern source evidence is unavailable or not active")
    try:
        return uuid.UUID(raw_source_item_id)
    except ValueError as exc:
        raise SafetyRejectionError("pattern source evidence is unavailable or not active") from exc


def _require_active_pattern_source(session: Session, pattern: CampaignPattern) -> uuid.UUID | None:
    """Fail closed when a source-backed pattern no longer has curated evidence.

    Manually authored patterns have no ``source_item_id`` provenance and retain
    their existing review path. Ingested and cloned source-backed patterns keep
    that identifier in ``attack_mapping``; approval rechecks the authoritative
    source row so a later quarantine, rejection, or duplicate decision cannot
    be bypassed through an older draft.
    """

    source_item_id = _pattern_source_item_id(pattern)
    if source_item_id is None:
        return None
    source_item = session.get(SourceItem, source_item_id, with_for_update=True)
    if (
        source_item is None
        or source_item.quarantine_state != dm.QuarantineState.ACTIVE
        or source_item.duplicate_of is not None
    ):
        raise SafetyRejectionError("pattern source evidence is unavailable or not active")
    source = session.get(Source, source_item.source_id, with_for_update=True, populate_existing=True)
    terms = (
        session.get(
            SourceTerms,
            source.license_state_id,
            with_for_update=True,
            populate_existing=True,
        )
        if source is not None and source.license_state_id is not None
        else None
    )
    if source is None or not source_governance_is_current(
        source,
        terms,
        evidence_license_state_id=source_item.license_state_id,
        as_of=datetime.now(UTC),
    ):
        raise SafetyRejectionError("pattern source governance is not current")
    return source_item_id


@router.post("/patterns/{pattern_id}/approve", status_code=status.HTTP_200_OK)
def approve_pattern(
    pattern_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.APPROVE_PATTERN)),
) -> dict[str, Any]:
    # Source-backed review and threat curation use the same source-then-pattern
    # lock order. The initial read discovers provenance only; the locked reload
    # below is authoritative and must still match it.
    pattern_snapshot = session.get(CampaignPattern, pattern_id)
    if pattern_snapshot is None:
        raise NotFoundError("pattern not found")
    source_item_id = _require_active_pattern_source(session, pattern_snapshot)
    pattern = session.get(
        CampaignPattern,
        pattern_id,
        with_for_update=True,
        populate_existing=True,
    )
    if pattern is None:
        raise NotFoundError("pattern not found")
    if _pattern_source_item_id(pattern) != source_item_id:
        raise ConflictError("pattern source evidence changed; review again")
    principal_id = _principal_uuid(principal)
    if pattern.created_by == principal_id:
        raise PermissionDeniedError("self-approval of your own pattern is prohibited")
    if pattern.approval_state not in {dm.PatternApprovalState.DRAFT, dm.PatternApprovalState.PENDING}:
        raise ConflictError("pattern is not awaiting approval")
    if pattern.prohibited_content_indicators:
        raise SafetyRejectionError("pattern contains prohibited-content indicators and cannot be approved")
    pattern.approval_state = dm.PatternApprovalState.APPROVED
    pattern.approved_by = principal_id
    pattern.approved_at = datetime.now(UTC)
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="pattern.approve",
        object_type="campaign_pattern",
        object_id=str(pattern_id),
    )
    # Nothing published to the generate topic, so the generation worker idled
    # forever and approved patterns never became draft templates (P-1). Approval
    # is the trigger: a pattern a human has vouched for is what we are willing
    # to build training content from. `requested_by` lets the template record who
    # set generation in motion, so that person cannot also approve the result.
    enqueue_queue(
        session,
        topic="generate",
        payload={"pattern_id": str(pattern_id), "requested_by": principal.principal_id},
        idempotency_key=f"generate:{pattern_id}:{pattern.pattern_version}",
    )
    dispatch_after_commit(session, lambda: audit.dispatch_pending_queue(request.app.state.queue))
    session.commit()
    return {
        "campaign_pattern_id": str(pattern_id),
        "approval_state": pattern.approval_state.value,
        # This response describes the durable fact established by this
        # transaction. Queue dispatch and provider execution are asynchronous;
        # claiming either completed here hid missing managed generation roles.
        "generation_request_recorded": True,
    }


class TemplateDecision(BaseModel):
    decision: dm.ApprovalDecision
    rationale: str = Field(min_length=1, max_length=2000)


_INCOMPLETE_TEMPLATE_CONTENT = "template content is incomplete or not recipient-bound"


def _require_approvable_template_content(template: TemplateVersion) -> None:
    """Reject canonical content that cannot bind a recipient training route."""

    subject = template.subject
    plain_text = template.plain_text
    safe_html = template.safe_html
    if not isinstance(subject, str) or not subject.strip():
        raise ValidationError_(_INCOMPLETE_TEMPLATE_CONTENT)
    if not isinstance(plain_text, str) or not plain_text.strip() or TRAINING_URL_PLACEHOLDER not in plain_text:
        raise ValidationError_(_INCOMPLETE_TEMPLATE_CONTENT)
    if safe_html is not None and not isinstance(safe_html, str):
        raise ValidationError_(_INCOMPLETE_TEMPLATE_CONTENT)
    if isinstance(safe_html, str) and safe_html.strip() and TRAINING_URL_PLACEHOLDER not in safe_html:
        raise ValidationError_(_INCOMPLETE_TEMPLATE_CONTENT)


@router.post("/templates/{template_version_id}/decision", status_code=status.HTTP_200_OK)
def decide_template(
    template_version_id: uuid.UUID,
    body: TemplateDecision,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.APPROVE_TEMPLATE)),
) -> dict[str, Any]:
    """Approve or reject AI-generated content before it can be used.

    This is the human gate on the generation pipeline. Until a template leaves
    DRAFT nothing can schedule it, so an unreviewed model output cannot reach a
    recipient.
    """
    template = session.get(TemplateVersion, template_version_id)
    if template is None:
        raise NotFoundError("template not found")
    if template.approval_state != dm.TemplateApprovalState.DRAFT:
        raise ConflictError(f"template is already {template.approval_state.value}")

    # Whoever asked for the content must not be the one who signs it off. The
    # requester is recorded at generation time; when it is unknown (older rows,
    # or a self-published job) we cannot check, and say so in the audit trail.
    requested_by = (template.raw_proposal or {}).get("requested_by")
    if requested_by and str(requested_by) == principal.principal_id:
        raise PermissionDeniedError(
            "you requested this generation; approval of AI-generated content must come from someone else"
        )

    approved = body.decision == dm.ApprovalDecision.APPROVED
    if approved:
        # Only canonical reviewed columns are deliverable. Legacy rows that
        # carry usable-looking raw proposals but no canonical content remain
        # rejectable, but cannot be promoted into the delivery path.
        _require_approvable_template_content(template)
        template.approval_hash = template_content_approval_hash(template)
    template.approval_state = dm.TemplateApprovalState.APPROVED if approved else dm.TemplateApprovalState.REJECTED
    audit.record(
        session=session,
        actor=principal.principal_id,
        action=f"template.{'approve' if approved else 'reject'}",
        object_type="template",
        object_id=str(template_version_id),
        detail={
            "rationale": body.rationale,
            "requester_known": bool(requested_by),
        },
    )
    session.commit()
    return {
        "template_version_id": str(template_version_id),
        "approval_state": template.approval_state.value,
    }


@router.get("/templates/pending", status_code=status.HTTP_200_OK)
def list_pending_templates(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=_GUI_COLLECTION_MAX_OFFSET),
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.APPROVE_TEMPLATE)),
) -> list[dict[str, Any]]:
    """Drafts awaiting human review, newest first."""
    rows = session.scalars(
        select(TemplateVersion)
        .where(TemplateVersion.approval_state == dm.TemplateApprovalState.DRAFT)
        .order_by(TemplateVersion.template_version_id.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return [
        {
            "template_version_id": str(row.template_version_id),
            "model_id": row.model_id,
            "subject": (row.raw_proposal or {}).get("subject", ""),
            "plain_text": (row.raw_proposal or {}).get("plain_text", ""),
            "requested_by": (row.raw_proposal or {}).get("requested_by"),
            "context_untrusted": bool((row.raw_proposal or {}).get("context_untrusted")),
            "neutralization_reasons": (row.raw_proposal or {}).get("neutralization_reasons", []),
        }
        for row in rows
    ]


@router.get("/queues/dead-letters", status_code=status.HTTP_200_OK)
def list_dead_letters(
    request: Request,
    topic: str | None = Query(default=None),
    offset: int = Query(default=0, ge=0, le=100_000),
    limit: int = Query(default=100, ge=1, le=500),
    principal: Principal = Depends(require_capability(Capability.MANAGE_QUEUE)),
) -> dict[str, Any]:
    """List bounded, non-sensitive DLQ summaries for the operator console."""
    del principal
    topics = (_queue_topic(topic),) if topic is not None else DEFAULT_QUEUE_TOPICS
    counts = {candidate: request.app.state.queue.dead_letter_count(candidate) for candidate in topics}
    remaining_offset = offset
    remaining_limit = limit
    items: list[dict[str, Any]] = []
    for candidate in topics:
        topic_count = counts[candidate]
        if remaining_offset >= topic_count:
            remaining_offset -= topic_count
            continue
        page = request.app.state.queue.list_dead_letters(
            candidate,
            offset=remaining_offset,
            limit=remaining_limit,
        )
        items.extend(_dead_letter_summary(item) for item in page)
        remaining_limit -= len(page)
        remaining_offset = 0
        if remaining_limit <= 0:
            break
    return {
        "items": items,
        "total": sum(counts.values()),
        "offset": offset,
        "limit": limit,
        "topic_counts": counts,
    }


@router.get("/queues/dead-letters/{topic}/{reference}", status_code=status.HTTP_200_OK)
def inspect_dead_letter(
    topic: str,
    reference: str,
    request: Request,
    principal: Principal = Depends(require_capability(Capability.MANAGE_QUEUE)),
) -> dict[str, Any]:
    """Inspect a DLQ envelope through a PII/secret-redacting projection."""
    del principal
    candidate = request.app.state.queue.get_dead_letter(_queue_topic(topic), _queue_reference(reference))
    if candidate is None:
        raise NotFoundError("dead-letter message not found")
    summary = _dead_letter_summary(candidate)
    message = candidate.get("message")
    if not isinstance(message, dict):
        return {**summary, "payload": None}
    return {
        **summary,
        "published_at": message.get("published_at"),
        "replayed_at": message.get("replayed_at"),
        "payload": _safe_queue_payload(message.get("payload", {})),
    }


@router.post("/queues/dead-letters/{topic}/{reference}/replay", status_code=status.HTTP_202_ACCEPTED)
def replay_dead_letter(
    topic: str,
    reference: str,
    body: DeadLetterReplay,
    request: Request,
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_QUEUE)),
) -> dict[str, Any]:
    """Audit, then atomically replay exactly one valid dead-letter envelope."""
    if not body.confirm:
        raise ValidationError_("dead-letter replay requires explicit confirmation")
    safe_topic = _queue_topic(topic)
    safe_reference = _queue_reference(reference)
    # The audit intent is durable before Redis is mutated. This can leave an
    # auditable attempted replay when another operator wins the race, but can
    # never leave an unaudited successful replay.
    audit.record(
        actor=principal.principal_id,
        action="queue.dead-letter.replay.request",
        object_type="queue_message",
        object_id=f"{safe_topic}:{safe_reference}",
        detail={"topic": safe_topic, "confirmed": True},
        idempotency_key=f"dlq-replay-request:{safe_topic}:{safe_reference}:{uuid.uuid4()}",
    )
    try:
        replayed = request.app.state.queue.replay_dead_letter(safe_topic, safe_reference)
    except ValueError as exc:
        raise ValidationError_(
            _allowlisted_validation_message(
                exc,
                allowed=frozenset({"malformed dead-letter messages cannot be replayed"}),
                fallback="dead-letter message cannot be replayed",
            )
        ) from exc
    if replayed is None:
        raise NotFoundError("dead-letter message was already replayed or is no longer available")
    return {
        "queued": True,
        "topic": safe_topic,
        "reference": safe_reference,
        "replay_count": replayed.get("replay_count", 1),
    }


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


def _get_campaign(session: Session, campaign_id: uuid.UUID) -> Campaign:
    campaign = session.get(Campaign, campaign_id)
    if campaign is None:
        raise NotFoundError("campaign not found")
    return campaign


def _system_safety_state(
    session: Session,
    *,
    shared_lock: bool = False,
    exclusive_lock: bool = False,
) -> SystemSafetyState:
    """Load the singleton interlock, optionally participating in its lock.

    A missing row means the safety migration was not applied.  Treat that as
    an unavailable safety control, never as an implicitly disengaged stop.
    PostgreSQL shared/exclusive row locks linearize scheduling and provider
    sends against an operator engaging the stop.
    """

    if shared_lock and exclusive_lock:
        raise ValueError("only one safety-state lock mode may be requested")
    if shared_lock:
        state = session.get(
            SystemSafetyState,
            1,
            with_for_update={"read": True},
            populate_existing=True,
        )
    elif exclusive_lock:
        state = session.get(SystemSafetyState, 1, with_for_update=True, populate_existing=True)
    else:
        state = session.get(SystemSafetyState, 1, populate_existing=True)
    if state is None:
        raise HTTPException(status_code=503, detail="persistent emergency-stop state is unavailable")
    return state


class KillSwitchBody(BaseModel):
    campaign_id: uuid.UUID | None = None
    confirm: bool = False
    reason: str | None = Field(default=None, max_length=500)


class KillSwitchResetBody(BaseModel):
    confirm: bool = False
    reason: str = Field(min_length=1, max_length=500)


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

    now = datetime.now(UTC)
    reason = (body.reason or "").strip()
    safety_state = None
    changed = True
    campaign = None
    if body.campaign_id is None:
        if not reason:
            raise ValidationError_("global kill switch requires a reason")
        safety_state = _system_safety_state(session, exclusive_lock=True)
        changed = not safety_state.emergency_stop_engaged
        if changed:
            safety_state.emergency_stop_engaged = True
            safety_state.generation += 1
            safety_state.engaged_at = now
            safety_state.engaged_by = principal.principal_id
            safety_state.engage_reason = reason
            safety_state.updated_at = now
    else:
        # A scoped emergency action must name a real campaign and persist a
        # terminal campaign fence. Expiring only the rows visible right now
        # allowed a queued test-send or a later publisher to recreate work for
        # the same campaign after this endpoint returned success.
        campaign = session.get(Campaign, body.campaign_id, with_for_update=True)
        if campaign is None:
            raise NotFoundError("campaign not found")
        changed = campaign.state != dm.CampaignState.STOPPED
        campaign.state = dm.CampaignState.STOPPED

    assignment_filter = RecipientAssignment.send_state == dm.SendState.QUEUED
    token_filter = TrackingToken.status == dm.TokenStatus.ACTIVE
    if body.campaign_id is not None:
        assignment_filter = assignment_filter & (RecipientAssignment.campaign_id == body.campaign_id)
        token_filter = token_filter & (TrackingToken.campaign_id == body.campaign_id)

    assignments_result = cast(
        CursorResult[Any],
        session.execute(
            update(RecipientAssignment)
            .where(assignment_filter)
            .values(
                send_state=dm.SendState.EXPIRED,
                failure_reason="global_emergency_stop" if body.campaign_id is None else "campaign_kill_switch",
            )
            .execution_options(synchronize_session=False)
        ),
    )
    cancelled = assignments_result.rowcount or 0
    tokens_result = cast(
        CursorResult[Any],
        session.execute(
            update(TrackingToken)
            .where(token_filter)
            .values(
                status=dm.TokenStatus.KILL_SWITCHED,
                revoked_at=now,
                revoked_reason=(
                    "global emergency stop engaged" if body.campaign_id is None else "campaign kill switch"
                ),
            )
            .execution_options(synchronize_session=False)
        ),
    )
    tokens_revoked = tokens_result.rowcount or 0
    if safety_state is not None:
        safety_state.last_cancelled = cancelled
        safety_state.last_tokens_revoked = tokens_revoked
        safety_state.updated_at = now
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="kill-switch.engage",
        object_type="campaign" if body.campaign_id else "system",
        object_id=str(body.campaign_id) if body.campaign_id else "delivery",
        detail={
            "cancelled": cancelled,
            "tokens_revoked": tokens_revoked,
            "confirm": body.confirm,
            "changed": changed,
            "reason": reason or None,
            "generation": safety_state.generation if safety_state is not None else None,
        },
    )
    if campaign is not None:
        _queue_campaign_alert(session, request, campaign, "campaign.kill_switch")
    session.commit()
    return {
        "cancelled": cancelled,
        "tokens_revoked": tokens_revoked,
        "engaged": safety_state.emergency_stop_engaged if safety_state is not None else None,
        "changed": changed,
        "generation": safety_state.generation if safety_state is not None else None,
    }


@router.post("/kill-switch/reset", status_code=status.HTTP_200_OK)
def reset_kill_switch(
    body: KillSwitchResetBody,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.USE_KILL_SWITCH)),
) -> dict[str, Any]:
    """Deliberately disengage the persistent global emergency stop.

    Resetting only reopens future scheduling/delivery.  Assignments cancelled
    and tracking credentials revoked by engagement stay terminal.
    """

    if not body.confirm:
        raise ValidationError_("kill switch reset requires explicit confirmation (confirm=true)")
    reason = body.reason.strip()
    if not reason:
        raise ValidationError_("kill switch reset requires a reason")

    state = _system_safety_state(session, exclusive_lock=True)
    changed = state.emergency_stop_engaged
    now = datetime.now(UTC)
    if changed:
        state.emergency_stop_engaged = False
        state.generation += 1
        state.disengaged_at = now
        state.disengaged_by = principal.principal_id
        state.disengage_reason = reason
        state.updated_at = now
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="kill-switch.disengage",
        object_type="system",
        object_id="delivery",
        detail={"confirm": body.confirm, "changed": changed, "reason": reason, "generation": state.generation},
    )
    session.commit()
    return {"engaged": state.emergency_stop_engaged, "changed": changed, "generation": state.generation}


@router.get("/kill-switch", status_code=status.HTTP_200_OK)
def kill_switch_state(
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.USE_KILL_SWITCH)),
) -> dict[str, Any]:
    """Report the persistent global interlock rather than audit history."""

    state = _system_safety_state(session)
    return {
        "engaged": state.emergency_stop_engaged,
        "generation": state.generation,
        "engaged_at": state.engaged_at,
        "engaged_by": state.engaged_by,
        "engage_reason": state.engage_reason,
        "disengaged_at": state.disengaged_at,
        "disengaged_by": state.disengaged_by,
        "disengage_reason": state.disengage_reason,
        "last_cancelled": state.last_cancelled,
        "last_tokens_revoked": state.last_tokens_revoked,
    }


_PRIVACY_SLA_DAYS = 45


class PrivacyRequestCreate(BaseModel):
    request_type: dm.PrivacyRequestType
    requester_mailbox: str = Field(min_length=3, max_length=320)
    campaign_id: uuid.UUID | None = None

    @field_validator("requester_mailbox")
    @classmethod
    def normalize_requester_mailbox(cls, value: str) -> str:
        return _normalize_mailbox(value, max_length=320)


class PrivacyVerification(BaseModel):
    method: str = Field(min_length=1, max_length=64)
    evidence_ref: str = Field(min_length=1, max_length=255)


class PrivacyFulfillment(BaseModel):
    note: str = Field(default="", max_length=2000)
    corrections: dict[str, str | None] | None = None

    @field_validator("corrections")
    @classmethod
    def validate_corrections(cls, value: dict[str, str | None] | None) -> dict[str, str | None] | None:
        if value is None:
            return None
        allowed = {"employee_key", "mailbox", "display_name", "department"}
        if not value or not set(value).issubset(allowed):
            raise ValueError("corrections must contain only supported recipient fields")
        normalized: dict[str, str | None] = {}
        for field_name, field_value in value.items():
            if field_name == "mailbox":
                if field_value is None:
                    raise ValueError("mailbox cannot be empty")
                normalized[field_name] = _normalize_mailbox(field_value, max_length=320)
                continue
            if field_name == "employee_key":
                if field_value is None or not field_value.strip() or len(field_value.strip()) > 256:
                    raise ValueError("employee_key must contain at most 256 characters")
                normalized[field_name] = field_value.strip()
                continue
            if field_value is not None and len(field_value.strip()) > 256:
                raise ValueError(f"{field_name} must contain at most 256 characters")
            normalized[field_name] = field_value.strip() or None if field_value is not None else None
        return normalized


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
    response: Response,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=1_000_000),
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.HANDLE_PRIVACY)),
) -> list[dict[str, Any]]:
    # This response includes requester mailboxes and case notes.  Prevent
    # browser and intermediary caches from retaining that personal data.
    response.headers["Cache-Control"] = "private, no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    rows = (
        session.execute(
            select(PrivacyRequest)
            .order_by(PrivacyRequest.opened_at.desc(), PrivacyRequest.privacy_request_id)
            .limit(limit)
            .offset(offset)
        )
        .scalars()
        .all()
    )
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
        campaign_id=body.campaign_id,
        status="opened",
        opened_at=opened_at,
        sla_deadline=opened_at + timedelta(days=_PRIVACY_SLA_DAYS),
    )
    session.add(request)
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="privacy_request.submit",
        object_type="privacy_request",
        object_id=str(request.privacy_request_id),
        detail={
            "request_type": body.request_type.value,
            "campaign_id": str(body.campaign_id) if body.campaign_id else None,
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
    request_id: uuid.UUID,
    body: PrivacyVerification,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.HANDLE_PRIVACY)),
) -> dict[str, Any]:
    request = session.get(PrivacyRequest, request_id)
    if request is None:
        raise NotFoundError("privacy request not found")
    if request.status != PrivacyRequestStatus.OPENED.value:
        raise ConflictError("only an opened privacy request can be verified")
    request.status = PrivacyRequestStatus.VERIFIED.value
    request.verified_at = datetime.now(UTC)
    request.verification_method = body.method
    request.verification_evidence_ref = body.evidence_ref
    audit.record(
        session=session,
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
    session: Session,
    settings: OperatorApiSettings,
    request: PrivacyRequest,
    *,
    max_rows: int | None = None,
) -> list[Recipient]:
    salt = settings.require_recipient_hash_salt()
    mailbox = request.requester_key
    if not mailbox:
        return []
    digest = hash_mailbox(mailbox, salt)
    statement = select(Recipient).where(Recipient.mailbox_sha256 == digest)
    if max_rows is not None:
        statement = statement.limit(max_rows + 1)
    rows = list(session.execute(statement).scalars().all())
    if max_rows is not None and len(rows) > max_rows:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail="privacy export recipients exceed the supported single-response boundary",
        )
    return rows


_PRIVACY_EXPORT_RECORD_LIMIT = 10_000


def _bounded_privacy_export_rows(session: Session, statement: Any, *, label: str) -> list[Any]:
    """Materialize one export collection without allowing unbounded JSON."""

    rows = list(session.scalars(statement.limit(_PRIVACY_EXPORT_RECORD_LIMIT + 1)))
    if len(rows) > _PRIVACY_EXPORT_RECORD_LIMIT:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"privacy export {label} exceed the supported single-response boundary",
        )
    return rows


@router.post("/privacy/requests/{request_id}/export")
def export_privacy_request(
    request_id: uuid.UUID,
    response: Response,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    settings: OperatorApiSettings = Depends(get_settings),
    principal: Principal = Depends(require_capability(Capability.HANDLE_PRIVACY)),
) -> dict[str, Any]:
    request = session.get(PrivacyRequest, request_id)
    if request is None:
        raise NotFoundError("privacy request not found")
    if request.status not in VERIFIED_PRIVACY_STATES:
        raise ConflictError("privacy request must be verified before export")
    recipients = _recipients_for_request(
        session,
        settings,
        request,
        max_rows=_PRIVACY_EXPORT_RECORD_LIMIT,
    )
    from kp_database.models import RecipientAssignment, RecipientExclusion, TrackingToken, TrainingAssignment

    recipient_ids = [recipient.recipient_id for recipient in recipients]
    assignments = (
        _bounded_privacy_export_rows(
            session,
            select(RecipientAssignment).where(RecipientAssignment.recipient_id.in_(recipient_ids)),
            label="assignments",
        )
        if recipient_ids
        else []
    )
    assignment_ids = [assignment.recipient_assignment_id for assignment in assignments]
    tokens = (
        _bounded_privacy_export_rows(
            session,
            select(TrackingToken).where(TrackingToken.recipient_assignment_id.in_(assignment_ids)),
            label="tracking tokens",
        )
        if assignment_ids
        else []
    )
    token_ids = [token.token_id for token in tokens]
    events = (
        _bounded_privacy_export_rows(
            session,
            select(TrackingEvent).where(
                (TrackingEvent.recipient_id.in_(recipient_ids)) | (TrackingEvent.token_id.in_(token_ids))
            ),
            label="tracking events",
        )
        if recipient_ids or token_ids
        else []
    )
    training = (
        _bounded_privacy_export_rows(
            session,
            select(TrainingAssignment).where(TrainingAssignment.recipient_id.in_(recipient_ids)),
            label="training assignments",
        )
        if recipient_ids
        else []
    )
    exclusions = (
        _bounded_privacy_export_rows(
            session,
            select(RecipientExclusion).where(RecipientExclusion.recipient_id.in_(recipient_ids)),
            label="recipient exclusions",
        )
        if recipient_ids
        else []
    )
    request.exported_at = datetime.now(UTC)
    audit.record(
        session=session,
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
    # This response contains the data subject's identity and activity history.
    # Keep it out of browser, proxy, and intermediary caches even when a
    # deployment later introduces an otherwise cache-friendly API gateway.
    response.headers["Cache-Control"] = "private, no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
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
                "created_by": str(row.created_by) if row.created_by else None,
                "created_at": row.created_at,
                "expires_at": row.expires_at,
                "revoked_at": row.revoked_at,
                "revoked_by": str(row.revoked_by) if row.revoked_by else None,
                "revoke_reason": row.revoke_reason,
            }
            for row in exclusions
        ],
    }


@router.post("/privacy/requests/{request_id}/fulfill")
def fulfill_privacy_request(
    request_id: uuid.UUID,
    body: PrivacyFulfillment,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    settings: OperatorApiSettings = Depends(get_settings),
    principal: Principal = Depends(require_capability(Capability.DELETE_DATA)),
) -> dict[str, Any]:
    request = session.get(PrivacyRequest, request_id)
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
        session=session,
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
    recipient_id: uuid.UUID,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.DELETE_DATA)),
) -> dict[str, Any]:
    recipient = session.get(Recipient, recipient_id)
    if recipient is None or recipient.deleted_at is not None:
        raise NotFoundError("recipient not found")
    erase_recipient_data(session, recipient.recipient_id, erased_at=datetime.now(UTC))
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="recipient.delete",
        object_type="recipient",
        object_id=str(recipient.recipient_id),
    )
    session.commit()
    return {"recipient_id": str(recipient.recipient_id), "deleted_at": recipient.deleted_at}


# --- Sending-domain onboarding wizard + signed Rules-of-Engagement ---------


class SendingDomainChallenge(BaseModel):
    domain: str = Field(min_length=1, max_length=253)
    relay: RelayKind = "smtp"
    relay_address: str | None = Field(default=None, max_length=64)
    dmarc_address: str | None = Field(default=None, max_length=255)


class SendingDomainVerify(BaseModel):
    domain: str = Field(min_length=1, max_length=253)


class LookalikeRequest(BaseModel):
    brand: str = Field(min_length=1, max_length=128)
    base_domain: str = Field(min_length=1, max_length=253)
    limit: int = Field(default=6, ge=1, le=10)
    relay: RelayKind = "smtp"
    relay_address: str | None = Field(default=None, max_length=64)
    dmarc_address: str | None = Field(default=None, max_length=255)


class RoeCreate(BaseModel):
    authorizing_party: str = Field(min_length=1, max_length=255)
    terms: str = Field(min_length=1, max_length=8192)
    window_start: datetime
    window_end: datetime
    target_domains: list[str] = Field(min_length=1, max_length=100)


class RoeRevoke(BaseModel):
    reason: str | None = Field(default=None, max_length=1024)


def _domain_verification_key(settings: OperatorApiSettings) -> bytes:
    try:
        return settings.require_domain_verification_key()
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail="domain verification key is unavailable") from exc


def _roe_signing_key(settings: OperatorApiSettings) -> bytes:
    try:
        return settings.require_roe_signing_key()
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail="Rules-of-Engagement signing key is unavailable") from exc


@router.post("/sending-domains/challenge", status_code=status.HTTP_200_OK)
def sending_domain_challenge(
    body: SendingDomainChallenge,
    request: Request,
    principal: Principal = Depends(require_capability(Capability.VERIFY_DOMAIN)),
) -> dict[str, Any]:
    """Mint the ownership challenge for a sending domain and the DNS records.

    The TXT value is deterministic per domain under the deployment's
    verification key, so re-requesting the challenge never rotates it mid-
    verification. The records block is the exact thing to paste into the
    operator's DNS zone (challenge TXT, provider SPF, DMARC, DKIM placeholder).
    """
    domain = normalize_domain(body.domain)
    if domain is None:
        raise ValidationError_("not a usable domain")
    settings = request.app.state.settings
    key = _domain_verification_key(settings)
    records = required_dns_records(
        domain,
        signing_key=key,
        relay=body.relay,
        relay_address=body.relay_address,
        dmarc_address=body.dmarc_address,
    )
    return {
        "domain": domain,
        "status": "awaiting_dns",
        "dns_records": [
            {"type": r.record_type, "name": r.name, "value": r.value, "ttl": r.ttl, "note": r.note} for r in records
        ],
    }


@router.post("/sending-domains/verify", status_code=status.HTTP_200_OK)
def sending_domain_verify(
    body: SendingDomainVerify,
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.VERIFY_DOMAIN)),
) -> dict[str, Any]:
    """Check the challenge TXT in live DNS and record the proof of control.

    Fail-closed: a DNS error, a missing record, or a wrong value is reported
    as unverified and nothing is recorded. Only after this succeeds may the
    domain be named as an RoE target domain or used as a sending domain.
    """
    settings = request.app.state.settings
    key = _domain_verification_key(settings)
    result = verify_domain(body.domain, signing_key=key)
    if not result.verified:
        raise ValidationError_(_domain_verification_failure(result.error))
    existing = session.scalar(select(VerifiedDomain).where(VerifiedDomain.domain == result.domain))
    now = datetime.now(UTC)
    if existing is None:
        existing = VerifiedDomain(
            verified_domain_id=uuid.uuid4(),
            domain=result.domain,
            challenge_token=result.token or "",
            verified_at=now,
            verified_by=uuid.UUID(principal.principal_id) if principal.principal_id != "anonymous" else None,
        )
        session.add(existing)
    else:
        existing.verified_at = now
        existing.verified_by = uuid.UUID(principal.principal_id) if principal.principal_id != "anonymous" else None
        existing.active = True
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="domain.verify",
        object_type="verified_domain",
        object_id=result.domain,
        detail={"verified": True},
    )
    session.commit()
    return {"domain": result.domain, "verified": True}


@router.get("/sending-domains", status_code=status.HTTP_200_OK)
def list_sending_domains(
    limit: int = Query(default=100, ge=1, le=_GUI_COLLECTION_MAX_LIMIT),
    offset: int = Query(default=0, ge=0, le=_GUI_COLLECTION_MAX_OFFSET),
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.VERIFY_DOMAIN)),
) -> dict[str, Any]:
    rows = list(
        session.scalars(
            select(VerifiedDomain)
            .order_by(VerifiedDomain.verified_at.desc(), VerifiedDomain.verified_domain_id.desc())
            .offset(offset)
            .limit(limit)
        )
    )
    return {"domains": [{"domain": row.domain, "verified_at": row.verified_at, "active": row.active} for row in rows]}


@router.post("/sending-domains/{domain}/revoke", status_code=status.HTTP_200_OK)
def revoke_sending_domain(
    domain: str,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.VERIFY_DOMAIN)),
) -> dict[str, Any]:
    """Retire a verified domain: it can no longer be named in a new RoE.

    Delivery is unaffected: an RoE already signed over the domain remains the
    authorization until that RoE is revoked or its window ends — verification
    is the precondition for signing, not a live delivery check.
    """
    row = session.scalar(select(VerifiedDomain).where(VerifiedDomain.domain == domain))
    if row is None:
        raise NotFoundError("verified domain not found")
    if not row.active:
        raise ConflictError("domain is already revoked")
    row.active = False
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="domain.revoke",
        object_type="verified_domain",
        object_id=domain,
    )
    session.commit()
    return {"domain": domain, "active": False}


@router.get("/sending-domains/generate", status_code=status.HTTP_200_OK)
def lookalike_candidates(
    request: Request,
    brand: str,
    base_domain: str,
    limit: int = 6,
    relay: RelayKind = "smtp",
    relay_address: str | None = None,
    dmarc_address: str | None = None,
    principal: Principal = Depends(require_capability(Capability.VERIFY_DOMAIN)),
) -> dict[str, Any]:
    """Candidate sending hostnames for a lure brand, with ready-to-paste DNS.

    Every candidate is a subdomain of an operator-controlled base domain:
    registerable by definition, and it joins the sending pool only after the
    same DNS challenge verifies.
    """
    settings = request.app.state.settings
    key = _domain_verification_key(settings)
    if normalize_domain(base_domain) is None:
        raise ValidationError_("not a usable base domain")
    candidates = candidate_sending_domains(
        base_domain,
        brand,
        limit=limit,
        signing_key=key,
        relay=relay,
        relay_address=relay_address,
        dmarc_address=dmarc_address,
    )
    return {
        "candidates": [
            {
                "domain": candidate.domain,
                "dns_records": [
                    {"type": r.record_type, "name": r.name, "value": r.value, "ttl": r.ttl, "note": r.note}
                    for r in candidate.records
                ],
            }
            for candidate in candidates
        ]
    }


@router.post("/roe", status_code=status.HTTP_201_CREATED)
def create_roe(
    body: RoeCreate,
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.SIGN_ROE)),
) -> dict[str, Any]:
    """Sign a Rules-of-Engagement over verified target domains.

    Signature version 2 binds the terms hash, authorizing party, normalized
    domain set, full engagement window, signer, and signing time. Every target
    domain must be active and DNS-verified; self-asserted scope is rejected.
    """
    if body.window_end <= body.window_start:
        raise ValidationError_("window_end must be after window_start")
    if body.window_start.tzinfo is None or body.window_end.tzinfo is None:
        raise ValidationError_("RoE window timestamps must include a timezone offset")
    authorizing_party = body.authorizing_party.strip()
    domains: list[str] = []
    for raw in body.target_domains:
        domain = normalize_domain(raw)
        if domain is None:
            raise ValidationError_("not a usable target domain")
        verified = session.scalar(select(VerifiedDomain).where(VerifiedDomain.domain == domain))
        if verified is None or not verified.active:
            raise ValidationError_("one or more target domains are not DNS-verified")
        domains.append(domain)
    domains = list(normalize_roe_domains(domains))

    now = datetime.now(UTC)
    terms_hash = hashlib.sha256(body.terms.encode("utf-8")).hexdigest()
    signing_key = _roe_signing_key(request.app.state.settings)
    signature = roe_signature_hex(
        terms_hash,
        principal.principal_id,
        now,
        authorizing_party=authorizing_party,
        target_domains=domains,
        window_start=body.window_start,
        window_end=body.window_end,
        signature_version=ROE_SIGNATURE_VERSION,
        signing_key=signing_key,
    )
    roe = RulesOfEngagement(
        roe_id=uuid.uuid4(),
        signer=principal.principal_id,
        authorizing_party=authorizing_party,
        terms_text=body.terms,
        terms_hash=terms_hash,
        signature=signature,
        signature_version=ROE_SIGNATURE_VERSION,
        signed_at=now,
        window_start=body.window_start,
        window_end=body.window_end,
        target_domains=domains,
        created_by=uuid.UUID(principal.principal_id) if principal.principal_id != "anonymous" else None,
    )
    session.add(roe)
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="roe.sign",
        object_type="rules_of_engagement",
        object_id=str(roe.roe_id),
        detail={
            "terms_hash": terms_hash,
            "authorizing_party": authorizing_party,
            "window_start": body.window_start.isoformat(),
            "window_end": body.window_end.isoformat(),
            "target_domains": domains,
            "signature": signature,
            "signature_version": ROE_SIGNATURE_VERSION,
        },
    )
    session.commit()
    return {
        "roe_id": str(roe.roe_id),
        "signer": principal.principal_id,
        "terms_hash": terms_hash,
        "signature": signature,
        "signature_version": ROE_SIGNATURE_VERSION,
        "signed_at": now.isoformat(),
    }


@router.get("/roe", status_code=status.HTTP_200_OK)
def list_roes(
    limit: int = Query(default=100, ge=1, le=_GUI_COLLECTION_MAX_LIMIT),
    offset: int = Query(default=0, ge=0, le=_GUI_COLLECTION_MAX_OFFSET),
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.SIGN_ROE)),
) -> dict[str, Any]:
    rows = list(
        session.scalars(
            select(RulesOfEngagement)
            .order_by(RulesOfEngagement.signed_at.desc(), RulesOfEngagement.roe_id.desc())
            .offset(offset)
            .limit(limit)
        )
    )
    return {
        "roes": [
            {
                "roe_id": str(row.roe_id),
                "signer": row.signer,
                "authorizing_party": row.authorizing_party,
                "terms_hash": row.terms_hash,
                "signature": row.signature,
                "signature_version": row.signature_version,
                "signed_at": row.signed_at,
                "window_start": row.window_start,
                "window_end": row.window_end,
                "target_domains": list(row.target_domains or []),
                "revoked_at": row.revoked_at,
                "revoked_reason": row.revoked_reason,
            }
            for row in rows
        ]
    }


@router.post("/roe/{roe_id}/revoke", status_code=status.HTTP_200_OK)
def revoke_roe(
    roe_id: uuid.UUID,
    body: RoeRevoke,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.SIGN_ROE)),
) -> dict[str, Any]:
    """Revoke an RoE immediately: delivery of its campaigns fails closed.

    The row is kept for the audit trail; only the revocation fields change.
    """
    roe = session.get(RulesOfEngagement, roe_id)
    if roe is None:
        raise NotFoundError("rules of engagement not found")
    if roe.revoked_at is not None:
        raise ConflictError("rules of engagement already revoked")
    roe.revoked_at = datetime.now(UTC)
    roe.revoked_by = uuid.UUID(principal.principal_id) if principal.principal_id != "anonymous" else None
    roe.revoked_reason = body.reason
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="roe.revoke",
        object_type="rules_of_engagement",
        object_id=str(roe.roe_id),
        detail={"reason": body.reason},
    )
    session.commit()
    return {"roe_id": str(roe.roe_id), "revoked_at": roe.revoked_at}
