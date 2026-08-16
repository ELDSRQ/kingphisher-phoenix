"""SQLAlchemy models for the Kingphisher-Phoenix data model.

Mirrors §10 of the reconstructed spec. PII columns (mailbox, display_name,
department, exclusion reason, employee_key) are stored as opaque ciphertext by
the `CipherText` type — application-level envelope encryption (R-SEC-002). The
encryption key is never stored in the database.
"""

from __future__ import annotations

import base64
import os
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from kp_domain_models import models as dm
from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy import (
    text as sa_text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import TypeDecorator

from kp_database.base import Base


class CipherText(TypeDecorator[str]):
    """AES-256-GCM ciphertext-at-rest for PII columns.

    The wrapping key (KEK) is injected at process start from the secret store
    (Azure Key Vault / 1Password). The raw value is stored base64url-encoded as
    `iv|nonce|ciphertext`; search is not supported on these columns (lookups
    use the plaintext-adjacent opaque id where needed).
    """

    impl = Text
    cache_ok = True

    _kek: bytes | None = None

    @classmethod
    def configure_key(cls, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("KEK must be 32 bytes")
        cls._kek = key

    @classmethod
    def _encrypt(cls, value: str) -> str:
        if cls._kek is None:
            raise RuntimeError("CipherText key not configured")
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(cls._kek), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(value.encode("utf-8")) + encryptor.finalize()
        tag = encryptor.tag
        return base64.urlsafe_b64encode(iv + tag + ct).decode("ascii")

    @classmethod
    def _decrypt(cls, blob: str) -> str:
        if cls._kek is None:
            raise RuntimeError("CipherText key not configured")
        raw = base64.urlsafe_b64decode(blob.encode("ascii"))
        iv, tag, ct = raw[:12], raw[12:28], raw[28:]
        cipher = Cipher(algorithms.AES(cls._kek), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        return (decryptor.update(ct) + decryptor.finalize()).decode("utf-8")

    def process_bind_param(self, value: str | None, dialect: object) -> str | None:
        return self._encrypt(value) if value is not None else None

    def process_result_value(self, value: str | None, dialect: object) -> str | None:
        return self._decrypt(value) if value is not None else None


def _pk() -> Mapped[Any]:
    return mapped_column(UUID(as_uuid=True), primary_key=True)


class Source(Base):
    __tablename__ = "sources"

    source_id = _pk()
    source_key: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(255))
    source_type: Mapped[dm.SourceType] = mapped_column(Enum(dm.SourceType, name="source_type"))
    base_domain: Mapped[str] = mapped_column(String(255))
    license_state_id = mapped_column(UUID(as_uuid=True), ForeignKey("source_terms.source_terms_id"), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    last_success_at = mapped_column(DateTime(timezone=True), nullable=True)
    last_attempt_at = mapped_column(DateTime(timezone=True), nullable=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)


class SourceTerms(Base):
    __tablename__ = "source_terms"

    source_terms_id = _pk()
    source_id = mapped_column(UUID(as_uuid=True), ForeignKey("sources.source_id", ondelete="CASCADE"), nullable=False)
    terms_reference: Mapped[str] = mapped_column(Text)
    terms_hash: Mapped[str] = mapped_column(String(64))
    commercial_use_ok: Mapped[bool] = mapped_column(Boolean, default=False)
    automation_ok: Mapped[bool] = mapped_column(Boolean, default=False)
    redistribution_ok: Mapped[bool] = mapped_column(Boolean, default=False)
    retention_ok: Mapped[bool] = mapped_column(Boolean, default=False)
    terms_reviewed_at = mapped_column(DateTime(timezone=True), nullable=False)
    next_review_at = mapped_column(DateTime(timezone=True), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)


class SourceItem(Base):
    __tablename__ = "source_items"

    source_item_id = _pk()
    source_id = mapped_column(UUID(as_uuid=True), ForeignKey("sources.source_id", ondelete="CASCADE"), nullable=False)
    publisher: Mapped[str] = mapped_column(String(255))
    title: Mapped[str] = mapped_column(Text)
    published_at = mapped_column(DateTime(timezone=True), nullable=False)
    retrieved_at = mapped_column(DateTime(timezone=True), nullable=False)
    sanitized_text: Mapped[str] = mapped_column(Text)
    content_hash: Mapped[str] = mapped_column(String(64))
    source_reference: Mapped[str] = mapped_column(Text)
    license_state_id = mapped_column(UUID(as_uuid=True), nullable=True)
    confidence: Mapped[dm.Confidence] = mapped_column(Enum(dm.Confidence, name="confidence"))
    claimed_actor: Mapped[str | None] = mapped_column(Text, nullable=True)
    claimed_target_sector: Mapped[str | None] = mapped_column(Text, nullable=True)
    extracted_indicators: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    quarantine_state: Mapped[dm.QuarantineState] = mapped_column(
        Enum(dm.QuarantineState, name="quarantine_state"), default=dm.QuarantineState.ACTIVE
    )
    quarantine_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    duplicate_of = mapped_column(UUID(as_uuid=True), nullable=True)
    __table_args__ = (UniqueConstraint("source_id", "content_hash", name="uq_source_items_dedup"),)


class CampaignPattern(Base):
    __tablename__ = "campaign_patterns"

    campaign_pattern_id = _pk()
    pattern_version: Mapped[int] = mapped_column(Integer, default=1)
    lure_category: Mapped[dm.LureCategory] = mapped_column(Enum(dm.LureCategory, name="lure_category"))
    impersonation_category: Mapped[str | None] = mapped_column(Text, nullable=True)
    target_role_category: Mapped[str | None] = mapped_column(Text, nullable=True)
    emotional_triggers: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    requested_action: Mapped[str | None] = mapped_column(Text, nullable=True)
    delivery_method: Mapped[str | None] = mapped_column(Text, nullable=True)
    warning_cues: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    actor_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    sector_targeting: Mapped[str | None] = mapped_column(Text, nullable=True)
    attack_mapping: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    confidence: Mapped[dm.Confidence] = mapped_column(Enum(dm.Confidence, name="confidence"))
    supporting_evidence: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    prohibited_content_indicators: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    approval_state: Mapped[dm.PatternApprovalState] = mapped_column(
        Enum(dm.PatternApprovalState, name="pattern_approval_state"), default=dm.PatternApprovalState.DRAFT
    )
    approved_by = mapped_column(UUID(as_uuid=True), nullable=True)
    approved_at = mapped_column(DateTime(timezone=True), nullable=True)
    created_by = mapped_column(UUID(as_uuid=True), nullable=True)


class TemplateVersion(Base):
    __tablename__ = "template_versions"

    template_version_id = _pk()
    campaign_id = mapped_column(UUID(as_uuid=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    idempotency_key: Mapped[str | None] = mapped_column(String(128), unique=True, nullable=True)
    generator_version: Mapped[str] = mapped_column(String(64))
    prompt_template_version: Mapped[str] = mapped_column(String(64))
    model_id: Mapped[str] = mapped_column(String(128))
    input_hash: Mapped[str] = mapped_column(String(64))
    raw_proposal: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    edited_content: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    safe_html: Mapped[str | None] = mapped_column(Text, nullable=True)
    plain_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    subject: Mapped[str | None] = mapped_column(Text, nullable=True)
    synthetic_sender_display: Mapped[str | None] = mapped_column(Text, nullable=True)
    learning_objectives: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    warning_cues: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    training_explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    approval_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approval_state: Mapped[dm.TemplateApprovalState] = mapped_column(
        Enum(dm.TemplateApprovalState, name="template_approval_state"), default=dm.TemplateApprovalState.DRAFT
    )
    unicode_validation: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)


class Campaign(Base):
    __tablename__ = "campaigns"

    campaign_id = _pk()
    pattern_id = mapped_column(UUID(as_uuid=True), ForeignKey("campaign_patterns.campaign_pattern_id"), nullable=False)
    current_template_id = mapped_column(UUID(as_uuid=True), nullable=True)
    title: Mapped[str] = mapped_column(String(255))
    state: Mapped[dm.CampaignState] = mapped_column(
        Enum(dm.CampaignState, name="campaign_state"), default=dm.CampaignState.DRAFT
    )
    sender_mailbox: Mapped[str] = mapped_column(String(255))
    training_domain: Mapped[str] = mapped_column(String(255))
    schedule_start = mapped_column(DateTime(timezone=True), nullable=True)
    schedule_end = mapped_column(DateTime(timezone=True), nullable=True)
    timezone: Mapped[str] = mapped_column(String(64), default="UTC")
    max_recipients: Mapped[int] = mapped_column(Integer)
    retention_policy_id = mapped_column(
        UUID(as_uuid=True), ForeignKey("retention_policies.retention_policy_id"), nullable=True
    )
    difficulty: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    manifest_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    manifest_signed_at = mapped_column(DateTime(timezone=True), nullable=True)
    recall_of = mapped_column(UUID(as_uuid=True), nullable=True)
    created_by = mapped_column(UUID(as_uuid=True), nullable=True)
    expires_at = mapped_column(DateTime(timezone=True), nullable=False)


class CampaignApproval(Base):
    __tablename__ = "campaign_approvals"

    campaign_approval_id = _pk()
    campaign_id = mapped_column(
        UUID(as_uuid=True), ForeignKey("campaigns.campaign_id", ondelete="CASCADE"), nullable=False
    )
    approval_type: Mapped[dm.ApprovalType] = mapped_column(Enum(dm.ApprovalType, name="approval_type"))
    approver_id = mapped_column(UUID(as_uuid=True), nullable=False)
    decision: Mapped[dm.ApprovalDecision] = mapped_column(Enum(dm.ApprovalDecision, name="approval_decision"))
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    decided_at = mapped_column(DateTime(timezone=True), nullable=False)
    template_version_id = mapped_column(UUID(as_uuid=True), nullable=False)


class Recipient(Base):
    __tablename__ = "recipients"

    recipient_id = _pk()
    employee_key: Mapped[str] = mapped_column(CipherText, unique=False)
    mailbox: Mapped[str] = mapped_column(CipherText)
    mailbox_sha256: Mapped[str] = mapped_column(String(64), index=True)
    display_name: Mapped[str | None] = mapped_column(CipherText, nullable=True)
    department: Mapped[str | None] = mapped_column(CipherText, nullable=True)
    is_test_account: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[dm.RecipientStatus] = mapped_column(
        Enum(dm.RecipientStatus, name="recipient_status"), default=dm.RecipientStatus.ACTIVE
    )
    last_snapshot_source: Mapped[str | None] = mapped_column(String(128), nullable=True)
    deleted_at = mapped_column(DateTime(timezone=True), nullable=True)
    __table_args__ = (
        Index(
            "uq_recipients_mailbox_sha256_active",
            "mailbox_sha256",
            unique=True,
            postgresql_where=sa_text("deleted_at IS NULL"),
        ),
    )


class RecipientExclusion(Base):
    __tablename__ = "recipient_exclusions"

    recipient_exclusion_id = _pk()
    recipient_id = mapped_column(
        UUID(as_uuid=True), ForeignKey("recipients.recipient_id", ondelete="CASCADE"), nullable=False
    )
    exclusion_type: Mapped[dm.ExclusionType] = mapped_column(Enum(dm.ExclusionType, name="exclusion_type"))
    campaign_id = mapped_column(UUID(as_uuid=True), nullable=True)
    reason: Mapped[str | None] = mapped_column(CipherText, nullable=True)
    created_by = mapped_column(UUID(as_uuid=True), nullable=True)
    expires_at = mapped_column(DateTime(timezone=True), nullable=True)


class TrackingToken(Base):
    __tablename__ = "tracking_tokens"

    token_id = _pk()
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    token_prefix: Mapped[str] = mapped_column(String(6))
    campaign_id = mapped_column(
        UUID(as_uuid=True), ForeignKey("campaigns.campaign_id", ondelete="CASCADE"), nullable=False
    )
    recipient_assignment_id = mapped_column(UUID(as_uuid=True), nullable=False)
    pepper_version: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[dm.TokenStatus] = mapped_column(
        Enum(dm.TokenStatus, name="token_status"), default=dm.TokenStatus.ACTIVE
    )
    expires_at = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_reason: Mapped[str | None] = mapped_column(Text, nullable=True)


class RecipientAssignment(Base):
    __tablename__ = "recipient_assignments"

    recipient_assignment_id = _pk()
    campaign_id = mapped_column(
        UUID(as_uuid=True), ForeignKey("campaigns.campaign_id", ondelete="CASCADE"), nullable=False
    )
    recipient_id = mapped_column(
        UUID(as_uuid=True), ForeignKey("recipients.recipient_id", ondelete="CASCADE"), nullable=False
    )
    snapshot_version: Mapped[int] = mapped_column(Integer, default=1)
    token_id = mapped_column(UUID(as_uuid=True), nullable=True)
    send_state: Mapped[dm.SendState] = mapped_column(Enum(dm.SendState, name="send_state"), default=dm.SendState.QUEUED)
    created_at = mapped_column(DateTime(timezone=True), nullable=False, server_default=sa_text("now()"))
    idempotency_key: Mapped[str] = mapped_column(String(128), unique=True)


class TrackingEvent(Base):
    __tablename__ = "events"

    event_id = _pk()
    event_type: Mapped[dm.EventType] = mapped_column(Enum(dm.EventType, name="event_type"))
    token_id = mapped_column(UUID(as_uuid=True), nullable=True)
    recipient_id = mapped_column(UUID(as_uuid=True), nullable=True)
    campaign_id = mapped_column(UUID(as_uuid=True), nullable=True)
    confidence: Mapped[dm.Confidence] = mapped_column(Enum(dm.Confidence, name="confidence"), default=dm.Confidence.LOW)
    occurred_at = mapped_column(DateTime(timezone=True), nullable=False)
    client_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    correction_of = mapped_column(UUID(as_uuid=True), nullable=True)
    corrected_by = mapped_column(UUID(as_uuid=True), nullable=True)
    correction_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)


class TrainingResource(Base):
    __tablename__ = "training_resources"

    training_resource_id = _pk()
    title: Mapped[str] = mapped_column(String(255))
    kind: Mapped[str] = mapped_column(String(16))
    content: Mapped[str] = mapped_column(Text)
    version: Mapped[int] = mapped_column(Integer, default=1)
    requires_completion: Mapped[bool] = mapped_column(Boolean, default=True)
    source_ref: Mapped[str | None] = mapped_column(Text, nullable=True)
    approval_state: Mapped[dm.TemplateApprovalState] = mapped_column(
        Enum(dm.TemplateApprovalState, name="template_approval_state"), default=dm.TemplateApprovalState.DRAFT
    )


class TrainingAssignment(Base):
    __tablename__ = "training_assignments"

    training_assignment_id = _pk()
    recipient_id = mapped_column(UUID(as_uuid=True), nullable=False)
    resource_id = mapped_column(
        UUID(as_uuid=True), ForeignKey("training_resources.training_resource_id", ondelete="CASCADE"), nullable=False
    )
    campaign_id = mapped_column(UUID(as_uuid=True), nullable=True)
    assigned_at = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[dm.TrainingAssignmentStatus] = mapped_column(
        Enum(dm.TrainingAssignmentStatus, name="training_assignment_status"),
        default=dm.TrainingAssignmentStatus.ASSIGNED,
    )
    followup_sent_at = mapped_column(DateTime(timezone=True), nullable=True)


class PrivacyRequest(Base):
    __tablename__ = "privacy_requests"

    privacy_request_id = _pk()
    request_type: Mapped[dm.PrivacyRequestType] = mapped_column(
        Enum(dm.PrivacyRequestType, name="privacy_request_type")
    )
    requester_key: Mapped[str] = mapped_column(CipherText)
    campaign_id = mapped_column(UUID(as_uuid=True), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="opened")
    opened_at = mapped_column(DateTime(timezone=True), nullable=False)
    # CCPA regs §7024: complete DSRs within 45 days of the request.
    sla_deadline = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at = mapped_column(DateTime(timezone=True), nullable=True)
    completion_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    verified_at = mapped_column(DateTime(timezone=True), nullable=True)
    verification_method: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verification_evidence_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    exported_at = mapped_column(DateTime(timezone=True), nullable=True)


class PrivacyNotice(Base):
    """Current consumer privacy notice / monitoring disclosure (CRIT-08, MED-20)."""

    __tablename__ = "privacy_notices"

    notice_id = _pk()
    version: Mapped[int] = mapped_column(Integer, default=1)
    notice_text: Mapped[str] = mapped_column(Text)
    effective_at = mapped_column(DateTime(timezone=True), nullable=False)
    is_current: Mapped[bool] = mapped_column(Boolean, default=False)


class RetentionPolicy(Base):
    __tablename__ = "retention_policies"

    retention_policy_id = _pk()
    name: Mapped[str] = mapped_column(String(128))
    data_category: Mapped[str] = mapped_column(String(64))
    retention_days: Mapped[int] = mapped_column(Integer)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at = mapped_column(DateTime(timezone=True), nullable=False, server_default=sa_text("now()"))


class AuditEvent(Base):
    """Append-only hash-chained audit. INSERT-only at the DB level (audit_writer role)."""

    __tablename__ = "audit_events"

    audit_event_id = _pk()
    actor: Mapped[str] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(128))
    object_type: Mapped[str] = mapped_column(String(128))
    object_id: Mapped[str] = mapped_column(String(255))
    outcome: Mapped[str] = mapped_column(String(16))
    occurred_at = mapped_column(DateTime(timezone=True), nullable=False)
    detail: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64), index=True)
    nonce: Mapped[str] = mapped_column(String(64))


class RetentionAction(Base):
    __tablename__ = "retention_actions"

    retention_action_id = _pk()
    retention_policy_id = mapped_column(
        UUID(as_uuid=True), ForeignKey("retention_policies.retention_policy_id"), nullable=True
    )
    executed_at = mapped_column(DateTime(timezone=True), nullable=False)
    target_table: Mapped[str] = mapped_column(String(128))
    row_count_deleted: Mapped[int] = mapped_column(Integer, default=0)
    idempotency_key: Mapped[str] = mapped_column(String(128), unique=True)


class AlertSubscription(Base):
    __tablename__ = "alert_subscriptions"

    alert_subscription_id = _pk()
    user_id = mapped_column(UUID(as_uuid=True), nullable=False)
    campaign_id = mapped_column(UUID(as_uuid=True), ForeignKey("campaigns.campaign_id"), nullable=False)
    channel: Mapped[str] = mapped_column(String(16), default="web")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
