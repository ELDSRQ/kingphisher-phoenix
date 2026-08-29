"""Domain models for Kingphisher-Phoenix.

Mirrors the authoritative data model in the reconstructed specification (§10).
Pydantic models are the typed, validated representation used at service
boundaries. They deliberately do not carry PII plaintext: fields marked `[enc]`
in the spec are excluded or opaque here.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal, Self
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

MAX_CAMPAIGN_RECIPIENTS = 10_000


def _require_aware_timestamp(value: datetime, field_name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must include a timezone offset")


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNVERIFIED = "unverified"


class VerificationState(StrEnum):
    VERIFIED = "verified"
    CORROBORATED = "corroborated"
    SUPPORTED = "supported"
    DISPUTED = "disputed"
    INSUFFICIENT = "insufficient"


class SourceType(StrEnum):
    ADVISORY = "advisory"
    RSS = "rss"
    STIX = "stix"
    BULK_DOWNLOAD = "bulk_download"
    CURATED = "curated"


class QuarantineState(StrEnum):
    ACTIVE = "active"
    QUARANTINED = "quarantined"
    REJECTED = "rejected"


class LureCategory(StrEnum):
    INVOICE = "invoice"
    PASSWORD_RESET = "password_reset"  # noqa: S105 - enum value, not a credential
    SHARED_DOCUMENT = "shared_document"
    EXECUTIVE_REQUEST = "executive_request"
    VENDOR_IMPERSONATION = "vendor_impersonation"
    OAUTH_CONSENT = "oauth_consent"
    QR_PHISHING = "qr_phishing"
    PAYROLL_HR = "payroll_hr"
    CONFERENCE = "conference"
    CALENDAR_INVITE = "calendar_invite"
    URGENT_RESPONSE = "urgent_response"
    CREDENTIAL_REFERENCE = "credential_reference"
    MALWARE_REFERENCE = "malware_reference"
    INVOICE_REFERENCE = "invoice_reference"
    OTHER = "other"


class PatternApprovalState(StrEnum):
    DRAFT = "draft"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class TemplateApprovalState(StrEnum):
    DRAFT = "draft"
    PENDING = "pending"
    APPROVED = "approved"
    SUPERSEDED = "superseded"
    REJECTED = "rejected"


class CampaignState(StrEnum):
    DRAFT = "draft"
    PATTERN_REVIEW = "pattern_review"
    CONTENT_REVIEW = "content_review"
    SECURITY_REVIEW = "security_review"
    PRIVACY_REVIEW = "privacy_review"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    SCHEDULED = "scheduled"
    SENDING = "sending"
    ACTIVE = "active"
    STOPPED = "stopped"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    RECALL_IN_PROGRESS = "recall_in_progress"
    RECALLED = "recalled"
    REJECTED = "rejected"


class CampaignProgramState(StrEnum):
    """Operator-controlled state for a bounded campaign program.

    Completion is derived from the member campaigns rather than stored as a
    second mutable lifecycle value.
    """

    ACTIVE = "active"
    PAUSED = "paused"


class ApprovalType(StrEnum):
    SECURITY = "security"
    PRIVACY = "privacy"
    HR = "hr"
    PATTERN = "pattern"
    CONTENT = "content"


class ApprovalDecision(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"


class RecipientStatus(StrEnum):
    ACTIVE = "active"
    EXCLUDED = "excluded"
    DEPARTED = "departed"


class ExclusionType(StrEnum):
    GLOBAL = "global"
    ACCOMMODATION = "accommodation"
    EXECUTIVE = "executive"
    LEGAL_HOLD = "legal_hold"
    CAMPAIGN_SPECIFIC = "campaign_specific"
    TEST_ACCOUNT = "test_account"


class SendState(StrEnum):
    QUEUED = "queued"
    # A worker owns the only permitted delivery attempt. A duplicate queue
    # message must not send while an assignment is in this state.
    SENDING = "sending"
    ACCEPTED = "accepted"
    # The worker cannot prove whether the provider accepted the message. This
    # is deliberately not retryable without an operator decision because an
    # automatic retry could send a duplicate.
    INDETERMINATE = "indeterminate"
    FAILED = "failed"
    DELIVERED = "delivered"
    EXPIRED = "expired"


class TokenStatus(StrEnum):
    ACTIVE = "active"
    CONSUMED = "consumed"
    EXPIRED = "expired"
    REVOKED = "revoked"
    KILL_SWITCHED = "kill_switched"


class EventType(StrEnum):
    SEND_ACCEPTED = "send_accepted"
    SEND_FAILED = "send_failed"
    OPENED = "opened"
    CLICKED = "clicked"
    LINK_RESOLVED = "link_resolved"
    PAGE_RENDERED = "page_rendered"
    HUMAN_INTERACTION_CONFIRMED = "human_interaction_confirmed"
    MESSAGE_REPORTED = "message_reported"
    TRAINING_STARTED = "training_started"
    TRAINING_COMPLETED = "training_completed"
    EVENT_CORRECTED = "event_corrected"
    REPORT_INGESTED_REAL = "report_ingested_real"
    REPORT_INGESTED_SIMULATED = "report_ingested_simulated"


class TrainingAssignmentStatus(StrEnum):
    """Legacy storage labels retained for existing database rows.

    New API/report state is derived from immutable first-write timestamps via
    :func:`training_state`; reminders are delivery history, not learner state.
    """

    ASSIGNED = "assigned"
    STARTED = "started"
    COMPLETED = "completed"
    EXPIRED = "expired"
    REMINDED = "reminded"


class TrainingState(StrEnum):
    ASSIGNED = "assigned"
    OPENED = "opened"
    COMPLETED = "completed"
    OVERDUE = "overdue"


def training_state(
    *,
    assigned_at: datetime,
    due_at: datetime,
    opened_at: datetime | None,
    completed_at: datetime | None,
    as_of: datetime,
) -> TrainingState:
    """Derive the learner-visible state without overwriting history.

    Completion is terminal. An incomplete assignment becomes overdue at its
    immutable due timestamp, whether or not the learner opened it first.
    """
    for field_name, value in (
        ("assigned_at", assigned_at),
        ("due_at", due_at),
        ("as_of", as_of),
        ("opened_at", opened_at),
        ("completed_at", completed_at),
    ):
        if value is not None:
            _require_aware_timestamp(value, field_name)
    if due_at < assigned_at:
        raise ValueError("training due_at cannot precede assigned_at")
    if as_of < assigned_at:
        raise ValueError("training as_of cannot precede assigned_at")
    if opened_at is not None and opened_at < assigned_at:
        raise ValueError("training opened_at cannot precede assigned_at")
    if completed_at is not None and completed_at < assigned_at:
        raise ValueError("training completed_at cannot precede assigned_at")
    if opened_at is not None and completed_at is not None and completed_at < opened_at:
        raise ValueError("training completed_at cannot precede opened_at")
    if completed_at is not None and completed_at <= as_of:
        return TrainingState.COMPLETED
    if as_of >= due_at:
        return TrainingState.OVERDUE
    if opened_at is not None and opened_at <= as_of:
        return TrainingState.OPENED
    return TrainingState.ASSIGNED


class PrivacyRequestType(StrEnum):
    SEARCH = "search"
    ACCESS_EXPORT = "access_export"
    CORRECTION = "correction"
    DELETION = "deletion"
    EXCEPTION = "exception"


class AuditOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


class BaseEntity(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class Source(BaseEntity):
    source_id: UUID = Field(default_factory=uuid4)
    source_key: str
    name: str
    source_type: SourceType
    base_domain: str
    fetch_path: str = "/"
    license_state_id: UUID | None = None
    enabled: bool = False
    last_success_at: datetime | None = None
    last_attempt_at: datetime | None = None
    consecutive_failures: int = Field(default=0, ge=0)


class SourceTerms(BaseEntity):
    source_terms_id: UUID = Field(default_factory=uuid4)
    source_id: UUID
    terms_reference: str
    terms_hash: str
    commercial_use_ok: bool = False
    automation_ok: bool = False
    redistribution_ok: bool = False
    retention_ok: bool = False
    terms_reviewed_at: datetime
    next_review_at: datetime
    enabled: bool = False


class SourceItem(BaseEntity):
    source_item_id: UUID = Field(default_factory=uuid4)
    source_id: UUID
    publisher: str
    title: str
    published_at: datetime
    retrieved_at: datetime
    sanitized_text: str
    content_hash: str
    source_reference: str
    license_state_id: UUID | None = None
    confidence: Confidence = Confidence.UNVERIFIED
    claimed_actor: str | None = None
    claimed_target_sector: str | None = None
    extracted_indicators: dict[str, Any] = Field(default_factory=dict)
    quarantine_state: QuarantineState = QuarantineState.ACTIVE
    quarantine_reason: str | None = None
    duplicate_of: UUID | None = None


class CampaignPattern(BaseEntity):
    campaign_pattern_id: UUID = Field(default_factory=uuid4)
    pattern_version: int = Field(default=1, ge=1)
    lure_category: LureCategory
    impersonation_category: str | None = None
    target_role_category: str | None = None
    emotional_triggers: list[str] = Field(default_factory=list)
    requested_action: str | None = None
    delivery_method: str | None = None
    warning_cues: list[str] = Field(default_factory=list)
    actor_type: str | None = None
    sector_targeting: str | None = None
    attack_mapping: dict[str, Any] = Field(default_factory=dict)
    confidence: Confidence = Confidence.UNVERIFIED
    supporting_evidence: list[dict[str, str]] = Field(default_factory=list)
    prohibited_content_indicators: list[str] = Field(default_factory=list)
    approval_state: PatternApprovalState = PatternApprovalState.DRAFT
    approved_by: UUID | None = None
    approved_at: datetime | None = None
    created_by: UUID | None = None


class TemplateVersion(BaseEntity):
    template_version_id: UUID = Field(default_factory=uuid4)
    campaign_id: UUID | None = None
    version: int = Field(default=1, ge=1)
    generator_version: str
    prompt_template_version: str
    model_id: str
    input_hash: str
    raw_proposal: dict[str, Any] = Field(default_factory=dict)
    edited_content: dict[str, Any] | None = None
    safe_html: str | None = None
    plain_text: str | None = None
    subject: str | None = None
    synthetic_sender_display: str | None = None
    learning_objectives: list[str] = Field(default_factory=list)
    warning_cues: list[str] = Field(default_factory=list)
    training_explanation: str | None = None
    approval_hash: str | None = None
    approval_state: TemplateApprovalState = TemplateApprovalState.DRAFT
    unicode_validation: dict[str, Any] = Field(default_factory=dict)


class Campaign(BaseEntity):
    campaign_id: UUID = Field(default_factory=uuid4)
    pattern_id: UUID
    current_template_id: UUID | None = None
    title: str
    state: CampaignState = CampaignState.DRAFT
    sender_mailbox: str
    sender_display_name: str | None = None
    roe_id: UUID | None = None
    training_domain: str
    schedule_start: datetime | None = None
    schedule_end: datetime | None = None
    timezone: str = "UTC"
    max_recipients: int = Field(ge=1, le=MAX_CAMPAIGN_RECIPIENTS)
    retention_policy_id: UUID | None = None
    training_resource_id: UUID | None = None
    difficulty: dict[str, Any] = Field(default_factory=dict)
    manifest_hash: str | None = None
    manifest_signed_at: datetime | None = None
    recall_of: UUID | None = None
    created_by: UUID | None = None
    expires_at: datetime

    @model_validator(mode="after")
    def validate_campaign_window(self) -> Self:
        _require_aware_timestamp(self.expires_at, "campaign expires_at")
        if (self.schedule_start is None) != (self.schedule_end is None):
            raise ValueError("campaign schedule_start and schedule_end must be set together")
        if self.schedule_start is not None and self.schedule_end is not None:
            _require_aware_timestamp(self.schedule_start, "campaign schedule_start")
            _require_aware_timestamp(self.schedule_end, "campaign schedule_end")
            if self.schedule_end <= self.schedule_start:
                raise ValueError("campaign schedule_end must be after schedule_start")
            if self.expires_at < self.schedule_end:
                raise ValueError("campaign expires_at cannot precede schedule_end")
        return self


class CampaignProgram(BaseEntity):
    campaign_program_id: UUID = Field(default_factory=uuid4)
    source_campaign_id: UUID
    state: CampaignProgramState = CampaignProgramState.ACTIVE
    version: int = Field(default=1, ge=1)
    cadence_days: Literal[7, 14, 28, 84]
    occurrence_count: int = Field(ge=2, le=12)
    configuration_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_by: UUID | None = None
    created_at: datetime
    updated_at: datetime

    @model_validator(mode="after")
    def validate_program_timestamps(self) -> Self:
        _require_aware_timestamp(self.created_at, "campaign program created_at")
        _require_aware_timestamp(self.updated_at, "campaign program updated_at")
        if self.updated_at < self.created_at:
            raise ValueError("campaign program updated_at cannot precede created_at")
        return self


class CampaignProgramOccurrence(BaseEntity):
    campaign_program_occurrence_id: UUID = Field(default_factory=uuid4)
    campaign_program_id: UUID
    occurrence_number: int = Field(ge=1)
    campaign_id: UUID
    schedule_start: datetime
    schedule_end: datetime

    @model_validator(mode="after")
    def validate_occurrence_window(self) -> Self:
        _require_aware_timestamp(self.schedule_start, "campaign program occurrence schedule_start")
        _require_aware_timestamp(self.schedule_end, "campaign program occurrence schedule_end")
        if self.schedule_end <= self.schedule_start:
            raise ValueError("campaign program occurrence schedule_end must be after schedule_start")
        return self


class CampaignApproval(BaseEntity):
    campaign_approval_id: UUID = Field(default_factory=uuid4)
    campaign_id: UUID
    approval_type: ApprovalType
    approver_id: UUID
    decision: ApprovalDecision
    rationale: str | None = None
    decided_at: datetime
    template_version_id: UUID


class Recipient(BaseEntity):
    """Opaque recipient record. `mailbox` is encrypted at rest in the database."""

    recipient_id: UUID = Field(default_factory=uuid4)
    employee_key: str
    mailbox: str
    display_name: str | None = None
    department: str | None = None
    is_test_account: bool = False
    status: RecipientStatus = RecipientStatus.ACTIVE
    last_snapshot_source: str | None = None
    directory_source: str | None = None
    directory_object_id_hash: str | None = None
    directory_generation: int | None = Field(default=None, ge=0)
    directory_owned: bool = False
    deleted_at: datetime | None = None


class RecipientExclusion(BaseEntity):
    recipient_exclusion_id: UUID = Field(default_factory=uuid4)
    recipient_id: UUID
    exclusion_type: ExclusionType
    campaign_id: UUID | None = None
    reason: str | None = None
    created_by: UUID | None = None
    expires_at: datetime | None = None


class TrackingToken(BaseEntity):
    token_id: UUID = Field(default_factory=uuid4)
    token_hash: str
    token_prefix: str
    campaign_id: UUID
    recipient_assignment_id: UUID
    pepper_version: int = Field(ge=1)
    status: TokenStatus = TokenStatus.ACTIVE
    expires_at: datetime
    revoked_at: datetime | None = None
    revoked_reason: str | None = None


class TrackingEvent(BaseEntity):
    event_id: UUID = Field(default_factory=uuid4)
    event_type: EventType
    token_id: UUID | None = None
    recipient_id: UUID | None = None
    campaign_id: UUID | None = None
    confidence: Confidence = Confidence.LOW
    occurred_at: datetime
    client_ip: str | None = None
    user_agent: str | None = None
    correction_of: UUID | None = None
    corrected_by: UUID | None = None
    correction_rationale: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)


class TrainingResource(BaseEntity):
    training_resource_id: UUID = Field(default_factory=uuid4)
    title: str
    kind: Literal["module", "article"]
    content: str
    version: int = Field(default=1, ge=1)
    requires_completion: bool = True
    source_ref: str | None = None
    approval_state: TemplateApprovalState = TemplateApprovalState.DRAFT


class PrivacyRequest(BaseEntity):
    privacy_request_id: UUID = Field(default_factory=uuid4)
    request_type: PrivacyRequestType
    requester_key: str
    campaign_id: UUID | None = None
    status: Literal["open", "in_progress", "completed", "exception_recorded"] = "open"
    opened_at: datetime
    sla_deadline: datetime
    completed_at: datetime | None = None
    completion_note: str | None = None


class AuditEvent(BaseEntity):
    audit_event_id: UUID = Field(default_factory=uuid4)
    actor: str
    action: str
    object_type: str
    object_id: str
    outcome: AuditOutcome
    occurred_at: datetime
    detail: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str = ""
    event_hash: str = ""
    nonce: str = ""


class AlertSubscription(BaseEntity):
    """Operator subscription to campaign lifecycle alerts (ported from the
    original King Phisher `alert_subscriptions` table)."""

    alert_subscription_id: UUID = Field(default_factory=uuid4)
    user_id: UUID
    campaign_id: UUID
    channel: Literal["web", "sms", "email"] = "web"
    active: bool = True


class RetentionAction(BaseEntity):
    retention_action_id: UUID = Field(default_factory=uuid4)
    retention_policy_id: UUID | None = None
    executed_at: datetime
    target_table: str
    row_count_deleted: int = Field(default=0, ge=0)
    idempotency_key: str
