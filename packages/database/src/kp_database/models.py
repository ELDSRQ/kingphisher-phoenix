"""SQLAlchemy models for the Kingphisher-Phoenix data model.

Mirrors §10 of the reconstructed spec. PII columns (mailbox, display_name,
department, exclusion reason, employee_key) are stored as opaque ciphertext by
the :class:`CipherText` type using application-layer authenticated encryption
(R-SEC-002). Encryption keys are never stored in the database.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import uuid
from collections.abc import Mapping
from datetime import date
from typing import Any, ClassVar

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from kp_domain_models import models as dm
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    Enum,
    ForeignKey,
    ForeignKeyConstraint,
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


class CipherTextError(ValueError):
    """A stable, non-secret ciphertext decoding failure."""


class CipherText(TypeDecorator[str]):
    """AES-256-GCM ciphertext-at-rest for sensitive columns.

    New values use ``kpct.1.<key-id>.<payload>``. The version and non-secret
    key identifier are authenticated as format-domain AAD, and the payload is
    base64url-encoded ``nonce|tag|ciphertext``. Pre-versioning values remain
    readable during a bounded key rotation. Search is intentionally unsupported
    on these columns.

    This is direct application-layer encryption, not envelope encryption: the
    process receives the AES keys from its secret store. The shared SQLAlchemy
    type does not expose a reliable model/column identity while processing a
    value, so the AAD binds the format domain rather than claiming row/column
    binding.
    """

    impl = Text
    cache_ok = True

    _FORMAT_NAME: ClassVar[str] = "kpct"
    _FORMAT_VERSION: ClassVar[str] = "1"
    _AAD_DOMAIN: ClassVar[bytes] = b"kingphisher-phoenix:ciphertext"
    _KEY_ID: ClassVar[re.Pattern[str]] = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}\Z")
    _MAX_PRIOR_KEYS: ClassVar[int] = 4

    _active_key_id: ClassVar[str | None] = None
    _active_key: ClassVar[bytes | None] = None
    _prior_keys: ClassVar[dict[str, bytes]] = {}

    @classmethod
    def configure_key(cls, key: bytes) -> None:
        """Configure one key while preserving the original caller contract."""
        cls.configure_keyring("default", key)

    @classmethod
    def configure_keyring(
        cls,
        active_key_id: str,
        active_key: bytes,
        prior_keys: Mapping[str, bytes] | None = None,
    ) -> None:
        """Configure one write key and up to four prior decrypt-only keys."""
        if cls._KEY_ID.fullmatch(active_key_id) is None:
            raise ValueError("CipherText active key identifier is invalid")
        if len(active_key) != 32:
            raise ValueError("CipherText active key must be 32 bytes")
        configured_prior = dict(prior_keys or {})
        if len(configured_prior) > cls._MAX_PRIOR_KEYS:
            raise ValueError("CipherText supports at most four prior keys")
        if active_key_id in configured_prior:
            raise ValueError("CipherText key identifiers must be unique")
        if any(cls._KEY_ID.fullmatch(key_id) is None for key_id in configured_prior):
            raise ValueError("CipherText prior key identifier is invalid")
        if any(len(key) != 32 for key in configured_prior.values()):
            raise ValueError("CipherText prior keys must be 32 bytes")
        all_keys = [active_key, *configured_prior.values()]
        if len(set(all_keys)) != len(all_keys):
            raise ValueError("CipherText key material must not be reused")

        cls._active_key_id = active_key_id
        cls._active_key = active_key
        cls._prior_keys = configured_prior

    @classmethod
    def _aad(cls, key_id: str, *, aad_domain: bytes | None = None) -> bytes:
        domain = cls._AAD_DOMAIN if aad_domain is None else aad_domain
        return b"|".join(
            (
                domain,
                cls._FORMAT_NAME.encode("ascii"),
                cls._FORMAT_VERSION.encode("ascii"),
                key_id.encode("ascii"),
            )
        )

    @staticmethod
    def _decode_payload(payload: str) -> bytes:
        try:
            raw = base64.b64decode(payload.encode("ascii"), altchars=b"-_", validate=True)
        except (UnicodeEncodeError, binascii.Error, ValueError):
            raise CipherTextError("CipherText ciphertext is malformed") from None
        if len(raw) < 28:
            raise CipherTextError("CipherText ciphertext is malformed")
        return raw

    @classmethod
    def _decrypt_payload(cls, raw: bytes, key: bytes, aad: bytes | None) -> str:
        nonce, tag, ciphertext = raw[:12], raw[12:28], raw[28:]
        try:
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()
            if aad is not None:
                decryptor.authenticate_additional_data(aad)
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        except (InvalidTag, ValueError):
            raise CipherTextError("CipherText authentication failed") from None
        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError:
            raise CipherTextError("CipherText plaintext is invalid") from None

    @classmethod
    def _configured_keys(cls) -> tuple[str, bytes, dict[str, bytes]]:
        if cls._active_key_id is None or cls._active_key is None:
            raise RuntimeError("CipherText key not configured")
        return cls._active_key_id, cls._active_key, cls._prior_keys.copy()

    @classmethod
    def _encrypt(cls, value: str, *, aad_domain: bytes | None = None) -> str:
        key_id, active_key, _ = cls._configured_keys()
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(active_key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(cls._aad(key_id, aad_domain=aad_domain))
        ciphertext = encryptor.update(value.encode("utf-8")) + encryptor.finalize()
        payload = base64.urlsafe_b64encode(nonce + encryptor.tag + ciphertext).decode("ascii")
        return f"{cls._FORMAT_NAME}.{cls._FORMAT_VERSION}.{key_id}.{payload}"

    @classmethod
    def _decrypt(cls, blob: str, *, aad_domain: bytes | None = None) -> str:
        active_key_id, active_key, prior_keys = cls._configured_keys()
        if blob.startswith(f"{cls._FORMAT_NAME}."):
            parts = blob.split(".")
            if len(parts) != 4 or not parts[1] or not parts[2] or not parts[3]:
                raise CipherTextError("CipherText ciphertext is malformed")
            _, version, key_id, payload = parts
            if version != cls._FORMAT_VERSION:
                raise CipherTextError("CipherText ciphertext version is unsupported")
            if cls._KEY_ID.fullmatch(key_id) is None:
                raise CipherTextError("CipherText ciphertext is malformed")
            key = active_key if key_id == active_key_id else prior_keys.get(key_id)
            if key is None:
                raise CipherTextError("CipherText key identifier is unavailable")
            raw = cls._decode_payload(payload)
            return cls._decrypt_payload(raw, key, cls._aad(key_id, aad_domain=aad_domain))

        # Legacy values carried no key identifier or AAD. During rotation try
        # the active key first, then the explicitly bounded prior key set.
        raw = cls._decode_payload(blob)
        for key in (active_key, *prior_keys.values()):
            try:
                return cls._decrypt_payload(raw, key, None)
            except CipherTextError as exc:
                if str(exc) != "CipherText authentication failed":
                    raise
        raise CipherTextError("CipherText authentication failed")

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
    fetch_path: Mapped[str] = mapped_column(String(1024), default="/")
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
    __table_args__ = (
        CheckConstraint(
            "training_resource_version IS NULL OR training_resource_version > 0",
            name="training_resource_version_positive",
        ),
        CheckConstraint(
            "training_resource_digest IS NULL OR training_resource_digest ~ '^[0-9a-f]{64}$'",
            name="training_resource_digest_hex",
        ),
    )

    campaign_id = _pk()
    pattern_id = mapped_column(UUID(as_uuid=True), ForeignKey("campaign_patterns.campaign_pattern_id"), nullable=False)
    current_template_id = mapped_column(UUID(as_uuid=True), nullable=True)
    title: Mapped[str] = mapped_column(String(255))
    state: Mapped[dm.CampaignState] = mapped_column(
        Enum(dm.CampaignState, name="campaign_state"), default=dm.CampaignState.DRAFT
    )
    sender_mailbox: Mapped[str] = mapped_column(String(255))
    #: Display name shown in the From header (e.g. "IT Service Desk"). The
    #: primary impersonation vector; free-form and varied per campaign.
    sender_display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    #: Signed Rules-of-Engagement this campaign was scheduled under. Delivery
    #: fails closed without an active RoE covering the campaign.
    roe_id = mapped_column(UUID(as_uuid=True), ForeignKey("rules_of_engagement.roe_id"), nullable=True)
    training_domain: Mapped[str] = mapped_column(String(255))
    schedule_start = mapped_column(DateTime(timezone=True), nullable=True)
    schedule_end = mapped_column(DateTime(timezone=True), nullable=True)
    timezone: Mapped[str] = mapped_column(String(64), default="UTC")
    max_recipients: Mapped[int] = mapped_column(Integer)
    retention_policy_id = mapped_column(
        UUID(as_uuid=True), ForeignKey("retention_policies.retention_policy_id"), nullable=True
    )
    training_resource_id = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("training_resources.training_resource_id", ondelete="RESTRICT"),
        nullable=True,
    )
    # Review binds both the human-selected lesson and the exact content that
    # was approved. These remain nullable so pre-0028 campaigns can be
    # retained without guessing or silently blessing legacy content; launch
    # gates treat any incomplete binding as requiring reconfiguration.
    training_resource_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    training_resource_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    difficulty: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    manifest_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    manifest_signed_at = mapped_column(DateTime(timezone=True), nullable=True)
    recall_of = mapped_column(UUID(as_uuid=True), nullable=True)
    created_by = mapped_column(UUID(as_uuid=True), nullable=True)
    expires_at = mapped_column(DateTime(timezone=True), nullable=False)


class CampaignProgram(Base):
    """A finite set of independently governed campaign occurrences."""

    __tablename__ = "campaign_programs"
    __table_args__ = (
        CheckConstraint("version > 0", name="version_positive"),
        CheckConstraint("cadence_days IN (7, 14, 28, 84)", name="cadence_allowlist"),
        CheckConstraint(
            "occurrence_count BETWEEN 2 AND 12",
            name="occurrence_count_bounded",
        ),
        CheckConstraint(
            "configuration_hash ~ '^[0-9a-f]{64}$'",
            name="configuration_hash_hex",
        ),
    )

    campaign_program_id = _pk()
    source_campaign_id = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("campaigns.campaign_id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    )
    state: Mapped[dm.CampaignProgramState] = mapped_column(
        Enum(dm.CampaignProgramState, name="campaign_program_state"),
        default=dm.CampaignProgramState.ACTIVE,
    )
    version: Mapped[int] = mapped_column(Integer, default=1, server_default=sa_text("1"))
    cadence_days: Mapped[int] = mapped_column(Integer)
    occurrence_count: Mapped[int] = mapped_column(Integer)
    configuration_hash: Mapped[str] = mapped_column(String(64))
    created_by = mapped_column(UUID(as_uuid=True), nullable=True)
    created_at = mapped_column(DateTime(timezone=True), nullable=False, server_default=sa_text("now()"))
    updated_at = mapped_column(DateTime(timezone=True), nullable=False, server_default=sa_text("now()"))


class CampaignProgramOccurrence(Base):
    """One durable campaign binding in a program's reviewed timeline."""

    __tablename__ = "campaign_program_occurrences"
    __table_args__ = (
        UniqueConstraint(
            "campaign_program_id",
            "occurrence_number",
            name="uq_campaign_program_occurrence_number",
        ),
        CheckConstraint(
            "occurrence_number > 0",
            name="occurrence_number_positive",
        ),
        CheckConstraint(
            "schedule_end > schedule_start",
            name="window_ordered",
        ),
    )

    campaign_program_occurrence_id = _pk()
    campaign_program_id = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "campaign_programs.campaign_program_id",
            name="fk_program_occurrences_program",
            ondelete="CASCADE",
        ),
        nullable=False,
    )
    occurrence_number: Mapped[int] = mapped_column(Integer)
    campaign_id = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("campaigns.campaign_id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    )
    schedule_start = mapped_column(DateTime(timezone=True), nullable=False)
    schedule_end = mapped_column(DateTime(timezone=True), nullable=False)


class CampaignApproval(Base):
    __tablename__ = "campaign_approvals"
    __table_args__ = (
        CheckConstraint(
            "launch_manifest_hash IS NULL OR length(launch_manifest_hash) = 64",
            name="ck_campaign_approvals_launch_manifest_hash",
        ),
    )

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
    # The decision applies only to the exact campaign/audience/content/RoE
    # review manifest.  Legacy NULL values are intentionally not accepted by
    # launch gates; an operator must perform a new review.
    launch_manifest_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)


class CampaignLaunchGate(Base):
    """Durable, fail-closed canary prerequisite for full publication."""

    __tablename__ = "campaign_launch_gates"
    __table_args__ = (
        CheckConstraint(
            "state IN ('reviewed', 'canary_queued', 'canary_succeeded', 'canary_failed', 'expired', 'full_published')",
            name="ck_campaign_launch_gate_state",
        ),
        CheckConstraint("length(review_manifest_hash) = 64", name="ck_campaign_launch_review_hash"),
        CheckConstraint("length(content_manifest_hash) = 64", name="ck_campaign_launch_content_hash"),
        CheckConstraint("length(template_approval_hash) = 64", name="ck_campaign_launch_template_hash"),
        CheckConstraint("length(audience_manifest_hash) = 64", name="ck_campaign_launch_audience_hash"),
        CheckConstraint("length(canary_manifest_hash) = 64", name="ck_campaign_launch_canary_hash"),
        CheckConstraint(
            "provider_config_hash IS NULL OR length(provider_config_hash) = 64",
            name="ck_campaign_launch_provider_config_hash",
        ),
        CheckConstraint(
            "canary_evidence_hash IS NULL OR length(canary_evidence_hash) = 64",
            name="ck_campaign_launch_evidence_hash",
        ),
        CheckConstraint(
            "state NOT IN ('canary_queued', 'canary_succeeded', 'full_published') OR "
            "(canary_queued_at IS NOT NULL AND canary_expires_at IS NOT NULL)",
            name="ck_campaign_launch_queued_evidence",
        ),
        CheckConstraint(
            "state NOT IN ('canary_succeeded', 'full_published') OR "
            "(provider IS NOT NULL AND provider_config_hash IS NOT NULL "
            "AND canary_evidence_hash IS NOT NULL AND canary_succeeded_at IS NOT NULL)",
            name="ck_campaign_launch_success_evidence",
        ),
        CheckConstraint(
            "state <> 'full_published' OR full_published_at IS NOT NULL",
            name="ck_campaign_launch_full_publication_time",
        ),
    )

    campaign_id = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("campaigns.campaign_id", ondelete="CASCADE"),
        primary_key=True,
    )
    review_manifest_hash: Mapped[str] = mapped_column(String(64))
    content_manifest_hash: Mapped[str] = mapped_column(String(64))
    template_approval_hash: Mapped[str] = mapped_column(String(64))
    audience_manifest_hash: Mapped[str] = mapped_column(String(64))
    canary_manifest_hash: Mapped[str] = mapped_column(String(64))
    roe_id = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("rules_of_engagement.roe_id", ondelete="RESTRICT"),
        nullable=False,
    )
    state: Mapped[str] = mapped_column(String(32), default="reviewed", server_default="reviewed")
    canary_queued_at = mapped_column(DateTime(timezone=True), nullable=True)
    canary_expires_at = mapped_column(DateTime(timezone=True), nullable=True)
    provider: Mapped[str | None] = mapped_column(String(64), nullable=True)
    provider_config_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    canary_evidence_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    canary_succeeded_at = mapped_column(DateTime(timezone=True), nullable=True)
    full_published_at = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at = mapped_column(DateTime(timezone=True), nullable=False, server_default=sa_text("now()"))


class CampaignCanaryRecipient(Base):
    """One recipient explicitly locked into the reviewed canary cohort."""

    __tablename__ = "campaign_canary_recipients"
    __table_args__ = (
        UniqueConstraint("campaign_id", "ordinal", name="uq_campaign_canary_recipient_ordinal"),
        CheckConstraint("ordinal >= 0", name="ck_campaign_canary_recipient_ordinal_nonnegative"),
        CheckConstraint("length(recipient_hash) = 64", name="ck_campaign_canary_recipient_hash"),
        Index("ix_campaign_canary_recipient_recipient", "recipient_id"),
    )

    campaign_id = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("campaign_launch_gates.campaign_id", ondelete="CASCADE"),
        primary_key=True,
    )
    recipient_id = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("recipients.recipient_id", ondelete="RESTRICT"),
        primary_key=True,
    )
    ordinal: Mapped[int] = mapped_column(Integer)
    recipient_hash: Mapped[str] = mapped_column(String(64))
    created_at = mapped_column(DateTime(timezone=True), nullable=False, server_default=sa_text("now()"))


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
    directory_source: Mapped[str | None] = mapped_column(String(32), nullable=True)
    directory_object_id_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    directory_generation: Mapped[int | None] = mapped_column(Integer, nullable=True)
    directory_owned: Mapped[bool] = mapped_column(Boolean, default=False, server_default=sa_text("false"))
    deleted_at = mapped_column(DateTime(timezone=True), nullable=True)
    __table_args__ = (
        Index(
            "uq_recipients_mailbox_sha256_active",
            "mailbox_sha256",
            unique=True,
            postgresql_where=sa_text("deleted_at IS NULL"),
        ),
        Index(
            "uq_recipients_directory_object_active",
            "directory_source",
            "directory_object_id_hash",
            unique=True,
            postgresql_where=sa_text("directory_object_id_hash IS NOT NULL AND deleted_at IS NULL"),
        ),
    )


class RecipientExclusion(Base):
    __tablename__ = "recipient_exclusions"
    __table_args__ = (
        Index("ix_recipient_exclusions_recipient_created", "recipient_id", "created_at"),
        Index(
            "ix_recipient_exclusions_active_scope",
            "recipient_id",
            "campaign_id",
            postgresql_where=sa_text("revoked_at IS NULL"),
        ),
    )

    recipient_exclusion_id = _pk()
    recipient_id = mapped_column(
        UUID(as_uuid=True), ForeignKey("recipients.recipient_id", ondelete="CASCADE"), nullable=False
    )
    exclusion_type: Mapped[dm.ExclusionType] = mapped_column(Enum(dm.ExclusionType, name="exclusion_type"))
    campaign_id = mapped_column(UUID(as_uuid=True), nullable=True)
    reason: Mapped[str | None] = mapped_column(CipherText, nullable=True)
    created_by = mapped_column(UUID(as_uuid=True), nullable=True)
    expires_at = mapped_column(DateTime(timezone=True), nullable=True)
    created_at = mapped_column(DateTime(timezone=True), nullable=False, server_default=sa_text("now()"))
    revoked_at = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by = mapped_column(UUID(as_uuid=True), nullable=True)
    revoke_reason: Mapped[str | None] = mapped_column(CipherText, nullable=True)


class AudienceGroup(Base):
    """A simple, operator-maintained static recipient group.

    A configured ``directory_group_ref`` is encrypted and resolved only by a
    reviewed directory preview/apply. Membership changes invalidate affected
    frozen campaign audiences; they never expand an existing manifest.
    """

    __tablename__ = "audience_groups"

    audience_group_id = _pk()
    name: Mapped[str] = mapped_column(String(120), unique=True)
    directory_group_ref: Mapped[str | None] = mapped_column(CipherText, nullable=True)
    directory_group_ref_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, unique=True)
    created_by = mapped_column(UUID(as_uuid=True), nullable=True)
    created_at = mapped_column(DateTime(timezone=True), nullable=False, server_default=sa_text("now()"))
    updated_at = mapped_column(DateTime(timezone=True), nullable=False, server_default=sa_text("now()"))


class AudienceGroupMember(Base):
    __tablename__ = "audience_group_members"
    __table_args__ = (
        UniqueConstraint("audience_group_id", "recipient_id", name="uq_audience_group_member"),
        Index("ix_audience_group_members_recipient", "recipient_id"),
    )

    audience_group_member_id = _pk()
    audience_group_id = mapped_column(
        UUID(as_uuid=True), ForeignKey("audience_groups.audience_group_id", ondelete="CASCADE"), nullable=False
    )
    recipient_id = mapped_column(
        UUID(as_uuid=True), ForeignKey("recipients.recipient_id", ondelete="CASCADE"), nullable=False
    )


class CampaignAudience(Base):
    """Versioned audience definition and its current frozen-manifest digest."""

    __tablename__ = "campaign_audiences"
    __table_args__ = (
        UniqueConstraint(
            "campaign_id",
            "version",
            name="uq_campaign_audiences_version_binding",
        ),
        CheckConstraint("version > 0", name="ck_campaign_audience_version_positive"),
        CheckConstraint("sample_size IS NULL OR sample_size > 0", name="ck_campaign_audience_sample_positive"),
    )

    campaign_id = mapped_column(
        UUID(as_uuid=True), ForeignKey("campaigns.campaign_id", ondelete="CASCADE"), primary_key=True
    )
    version: Mapped[int] = mapped_column(Integer, default=1, server_default=sa_text("1"))
    group_ids: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    departments: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    statuses: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    include_recipient_ids: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    exclude_recipient_ids: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    sample_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sample_seed: Mapped[str | None] = mapped_column(String(128), nullable=True)
    configuration_hash: Mapped[str] = mapped_column(String(64))
    preview_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    manifest_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    frozen_at = mapped_column(DateTime(timezone=True), nullable=True)
    legacy_requires_configuration: Mapped[bool] = mapped_column(Boolean, default=False, server_default=sa_text("false"))
    updated_at = mapped_column(DateTime(timezone=True), nullable=False, server_default=sa_text("now()"))


class CampaignAudienceManifest(Base):
    """Exact recipient snapshot used by launch preparation; rows are never updated."""

    __tablename__ = "campaign_audience_manifest"
    __table_args__ = (
        ForeignKeyConstraint(
            ["campaign_id", "audience_version"],
            ["campaign_audiences.campaign_id", "campaign_audiences.version"],
            name="fk_campaign_audience_manifest_version",
            ondelete="CASCADE",
        ),
        UniqueConstraint("campaign_id", "ordinal", name="uq_campaign_audience_manifest_ordinal"),
        Index("ix_campaign_audience_manifest_recipient", "recipient_id"),
        CheckConstraint("ordinal >= 0", name="ck_campaign_audience_manifest_ordinal_nonnegative"),
    )

    campaign_id = mapped_column(
        UUID(as_uuid=True), ForeignKey("campaigns.campaign_id", ondelete="CASCADE"), primary_key=True
    )
    recipient_id = mapped_column(
        UUID(as_uuid=True), ForeignKey("recipients.recipient_id", ondelete="RESTRICT"), primary_key=True
    )
    audience_version: Mapped[int] = mapped_column(Integer)
    ordinal: Mapped[int] = mapped_column(Integer)
    recipient_hash: Mapped[str] = mapped_column(String(64))
    created_at = mapped_column(DateTime(timezone=True), nullable=False, server_default=sa_text("now()"))


class TrackingToken(Base):
    __tablename__ = "tracking_tokens"
    __table_args__ = (
        ForeignKeyConstraint(
            ["recipient_assignment_id", "campaign_id"],
            ["recipient_assignments.recipient_assignment_id", "recipient_assignments.campaign_id"],
            name="fk_tracking_tokens_assignment_campaign",
            ondelete="CASCADE",
        ),
    )

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
    __table_args__ = (
        Index("ix_recipient_assignments_delivery_recovery", "send_state", "delivery_claimed_at"),
        UniqueConstraint(
            "recipient_assignment_id",
            "delivery_attempt_id",
            name="uq_recipient_assignments_attempt_binding",
        ),
        UniqueConstraint(
            "recipient_assignment_id",
            "campaign_id",
            name="uq_recipient_assignments_campaign_binding",
        ),
        UniqueConstraint(
            "recipient_assignment_id",
            "campaign_id",
            "recipient_id",
            name="uq_recipient_assignments_identity_binding",
        ),
        CheckConstraint(
            "delivery_attempt_count >= 0",
            name="attempt_count_nonnegative",
        ),
    )

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
    #: Why a send failed, when the cause is a policy decision rather than a
    #: transport error (e.g. "domain_not_allowed", "stale_queued_reconcile").
    #: NULL on success and on failures predating migration 0011.
    failure_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: One durable identifier for the sole automatic provider attempt. Once
    #: populated, a duplicate queue message cannot claim the assignment.
    delivery_attempt_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    delivery_attempt_count: Mapped[int] = mapped_column(Integer, default=0, server_default=sa_text("0"))
    delivery_claimed_at = mapped_column(DateTime(timezone=True), nullable=True)
    #: Provider acceptance is not proof that a message reached the mailbox.
    provider_accepted_at = mapped_column(DateTime(timezone=True), nullable=True)
    #: Provider delivery receipt time. For ACS this proves handoff to the
    #: destination MTA; it does not prove inbox placement, display, or reading.
    #: SMTP without a receipt integration leaves this NULL and stops at ACCEPTED.
    delivery_confirmed_at = mapped_column(DateTime(timezone=True), nullable=True)
    provider_message_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at = mapped_column(DateTime(timezone=True), nullable=False, server_default=sa_text("now()"))
    idempotency_key: Mapped[str] = mapped_column(String(128), unique=True)


class DeliveryReportCorrelation(Base):
    """Retry-stable, purpose-scoped correlation for one provider attempt."""

    __tablename__ = "delivery_report_correlations"
    __table_args__ = (
        ForeignKeyConstraint(
            ["recipient_assignment_id", "delivery_attempt_id"],
            ["recipient_assignments.recipient_assignment_id", "recipient_assignments.delivery_attempt_id"],
            name="fk_delivery_report_correlation_attempt",
            ondelete="CASCADE",
        ),
        UniqueConstraint(
            "recipient_assignment_id",
            "delivery_attempt_id",
            name="uq_delivery_report_correlations_attempt_binding",
        ),
    )

    delivery_attempt_id = mapped_column(UUID(as_uuid=True), primary_key=True)
    recipient_assignment_id = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        unique=True,
    )
    report_verifier: Mapped[str] = mapped_column(CipherText)
    verifier_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    message_id: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    provider_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    provider_status: Mapped[str | None] = mapped_column(String(64), nullable=True)
    provider_accepted_at = mapped_column(DateTime(timezone=True), nullable=True)
    created_at = mapped_column(DateTime(timezone=True), nullable=False, server_default=sa_text("now()"))


class DeliveryProviderEvent(Base):
    """One privacy-minimized, idempotent provider delivery receipt.

    Event Grid identifiers are stored only as hashes.  The provider operation
    ID is already durable on :class:`DeliveryReportCorrelation`; this row
    binds the receipt to the exact claimed attempt without retaining the
    recipient address or the provider's free-form diagnostic text.
    """

    __tablename__ = "delivery_provider_events"
    __table_args__ = (
        ForeignKeyConstraint(
            ["recipient_assignment_id", "delivery_attempt_id"],
            [
                "delivery_report_correlations.recipient_assignment_id",
                "delivery_report_correlations.delivery_attempt_id",
            ],
            name="fk_delivery_provider_events_attempt_binding",
            ondelete="CASCADE",
        ),
        CheckConstraint("provider IN ('acs')", name="ck_delivery_provider_events_provider"),
        CheckConstraint(
            "status IN ('delivered', 'bounced', 'suppressed', 'quarantined', 'filtered_spam', 'expanded', 'failed')",
            name="ck_delivery_provider_events_status",
        ),
        Index("ix_delivery_provider_events_assignment", "recipient_assignment_id", "occurred_at"),
    )

    delivery_provider_event_id = _pk()
    provider: Mapped[str] = mapped_column(String(16), nullable=False)
    external_event_id_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    delivery_attempt_id = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("delivery_report_correlations.delivery_attempt_id", ondelete="CASCADE"),
        nullable=False,
    )
    recipient_assignment_id = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("recipient_assignments.recipient_assignment_id", ondelete="CASCADE"),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    status_detail_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    occurred_at = mapped_column(DateTime(timezone=True), nullable=False)
    created_at = mapped_column(DateTime(timezone=True), nullable=False, server_default=sa_text("now()"))


class RecipientDeliverySuppression(Base):
    """Durable provider suppression enforced before any transport attempt."""

    __tablename__ = "recipient_delivery_suppressions"
    __table_args__ = (
        CheckConstraint("provider IN ('acs')", name="ck_recipient_delivery_suppressions_provider"),
        CheckConstraint(
            "reason IN ('bounced', 'suppressed', 'filtered_spam')",
            name="ck_recipient_delivery_suppressions_reason",
        ),
    )

    recipient_id = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("recipients.recipient_id", ondelete="CASCADE"),
        primary_key=True,
    )
    provider: Mapped[str] = mapped_column(String(16), nullable=False)
    reason: Mapped[str] = mapped_column(String(24), nullable=False)
    source_event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default=sa_text("true"))
    created_at = mapped_column(DateTime(timezone=True), nullable=False, server_default=sa_text("now()"))
    updated_at = mapped_column(DateTime(timezone=True), nullable=False, server_default=sa_text("now()"))


class DeliveryPacingState(Base):
    """Single-row durable ACS quota/ramp reservation state."""

    __tablename__ = "delivery_pacing_states"
    __table_args__ = (
        CheckConstraint("provider IN ('acs')", name="ck_delivery_pacing_states_provider"),
        CheckConstraint("minute_count >= 0 AND daily_count >= 0", name="ck_delivery_pacing_states_counts"),
    )

    provider: Mapped[str] = mapped_column(String(16), primary_key=True)
    minute_window_started_at = mapped_column(DateTime(timezone=True), nullable=False)
    minute_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default=sa_text("0"))
    day_started_at = mapped_column(DateTime(timezone=True), nullable=False)
    daily_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default=sa_text("0"))
    next_batch_at = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at = mapped_column(DateTime(timezone=True), nullable=False, server_default=sa_text("now()"))


class Microsoft365IntegrationState(Base):
    """Durable cursor, preview and health for one integration scope."""

    __tablename__ = "microsoft365_integration_states"
    __table_args__ = (
        UniqueConstraint("kind", "scope_hash", name="uq_m365_integration_kind_scope"),
        CheckConstraint("kind IN ('directory', 'mailbox')", name="ck_m365_integration_kind"),
        CheckConstraint("provider IN ('microsoft365', 'mailpit')", name="ck_m365_integration_provider"),
        CheckConstraint("generation >= 0", name="ck_m365_integration_generation"),
        CheckConstraint(
            "status IN ('never', 'configuration_changed', 'error', 'truncated', 'rejected', "
            "'preview_ready', 'healthy', 'expired', 'discarded')",
            name="ck_m365_integration_status",
        ),
        CheckConstraint(
            "(pending_preview_id IS NULL AND pending_preview_hash IS NULL AND pending_payload IS NULL "
            "AND pending_created_at IS NULL AND pending_expires_at IS NULL) OR "
            "(kind = 'directory' AND status = 'preview_ready' AND pending_preview_id IS NOT NULL "
            "AND pending_preview_hash IS NOT NULL AND pending_payload IS NOT NULL "
            "AND pending_created_at IS NOT NULL AND pending_expires_at > pending_created_at)",
            name="ck_m365_integration_pending_preview",
        ),
        CheckConstraint(
            "(active_job_key IS NULL AND lease_expires_at IS NULL) OR "
            "(kind = 'mailbox' AND active_job_key IS NOT NULL AND lease_expires_at IS NOT NULL)",
            name="ck_m365_integration_mailbox_lease",
        ),
    )

    integration_state_id = _pk()
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    scope_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    config_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    cursor: Mapped[str | None] = mapped_column(CipherText, nullable=True)
    cursor_kind: Mapped[str | None] = mapped_column(String(16), nullable=True)
    status: Mapped[str] = mapped_column(String(24), nullable=False, server_default=sa_text("'never'"))
    generation: Mapped[int] = mapped_column(Integer, nullable=False, server_default=sa_text("0"))
    pending_preview_id = mapped_column(UUID(as_uuid=True), nullable=True)
    pending_preview_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    pending_payload: Mapped[str | None] = mapped_column(CipherText, nullable=True)
    pending_created_at = mapped_column(DateTime(timezone=True), nullable=True)
    pending_expires_at = mapped_column(DateTime(timezone=True), nullable=True)
    active_job_key: Mapped[str | None] = mapped_column(String(255), nullable=True)
    lease_expires_at = mapped_column(DateTime(timezone=True), nullable=True)
    last_job_key: Mapped[str | None] = mapped_column(String(255), nullable=True)
    last_counts: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default=sa_text("'{}'::jsonb"))
    last_attempt_at = mapped_column(DateTime(timezone=True), nullable=True)
    last_success_at = mapped_column(DateTime(timezone=True), nullable=True)
    last_applied_at = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(128), nullable=True)
    updated_at = mapped_column(DateTime(timezone=True), nullable=False, server_default=sa_text("now()"))


class ReportedMailReceipt(Base):
    """Durable replay boundary for one externally reported message."""

    __tablename__ = "reported_mail_receipts"
    __table_args__ = (UniqueConstraint("provider", "scope_hash", "external_id_hash", name="uq_reported_mail_external"),)

    reported_mail_receipt_id = _pk()
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    scope_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    external_id: Mapped[str] = mapped_column(CipherText)
    external_id_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    recipient_assignment_id = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("recipient_assignments.recipient_assignment_id", ondelete="SET NULL"),
        nullable=True,
    )
    event_id = mapped_column(UUID(as_uuid=True), ForeignKey("events.event_id", ondelete="SET NULL"), nullable=True)
    disposition: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    received_at = mapped_column(DateTime(timezone=True), nullable=False)
    created_at = mapped_column(DateTime(timezone=True), nullable=False, server_default=sa_text("now()"))


class TrackingEvent(Base):
    __tablename__ = "events"
    __table_args__ = (
        # metric-integrity: first OPENED/CLICKED event per token wins; the
        # partial unique index makes application dedup race-safe. Enum labels
        # are the SQLAlchemy Enum member names.
        Index(
            "uq_events_open_click_dedup",
            "token_id",
            "event_type",
            unique=True,
            postgresql_where=sa_text("event_type IN ('OPENED', 'CLICKED')"),
        ),
        Index(
            "uq_events_training_dedup",
            "token_id",
            "event_type",
            unique=True,
            postgresql_where=sa_text("event_type IN ('TRAINING_STARTED', 'TRAINING_COMPLETED')"),
        ),
        Index(
            "uq_events_human_interaction_dedup",
            "token_id",
            "event_type",
            unique=True,
            postgresql_where=sa_text("event_type = 'HUMAN_INTERACTION_CONFIRMED'"),
        ),
        Index(
            "uq_events_reported_assignment",
            "recipient_assignment_id",
            unique=True,
            postgresql_where=sa_text("event_type = 'MESSAGE_REPORTED' AND recipient_assignment_id IS NOT NULL"),
        ),
    )

    event_id = _pk()
    event_type: Mapped[dm.EventType] = mapped_column(Enum(dm.EventType, name="event_type"))
    token_id = mapped_column(UUID(as_uuid=True), nullable=True)
    recipient_assignment_id = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("recipient_assignments.recipient_assignment_id", ondelete="SET NULL"),
        nullable=True,
    )
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


class AwarenessLedgerEntry(Base):
    """PII-free, campaign-level outcome projection retained beyond raw evidence.

    The recipient reference is a keyed pseudonym generated outside the model;
    no recipient, assignment, mailbox, display-name, or department foreign key
    is retained here. Campaign identifiers intentionally have no foreign key so
    raw campaign cleanup cannot cascade into the five-year projection.
    """

    __tablename__ = "awareness_ledger_entries"
    __table_args__ = (
        UniqueConstraint(
            "tenant_scope",
            "campaign_id",
            "assignment_exposure_pseudonym",
            name="uq_awareness_ledger_scope_campaign_exposure",
        ),
        CheckConstraint(
            "tenant_scope = 'single_tenant_database'",
            name="ck_awareness_ledger_single_tenant_scope",
        ),
        CheckConstraint(
            "recipient_pseudonym ~ '^[0-9a-f]{64}$'",
            name="ck_awareness_ledger_recipient_pseudonym_hex",
        ),
        CheckConstraint(
            "assignment_exposure_pseudonym ~ '^[0-9a-f]{64}$'",
            name="ck_awareness_ledger_assignment_pseudonym_hex",
        ),
        CheckConstraint(
            "char_length(btrim(pseudonym_key_version)) BETWEEN 1 AND 32",
            name="ck_awareness_ledger_key_version_bounded",
        ),
        CheckConstraint(
            "campaign_date_basis IN ('scheduled_start', 'targeted_at')",
            name="ck_awareness_ledger_campaign_date_basis",
        ),
        CheckConstraint(
            "delivered IS FALSE OR accepted IS TRUE",
            name="ck_awareness_ledger_delivered_implies_accepted",
        ),
        CheckConstraint(
            "training_started IS FALSE OR training_assigned IS TRUE",
            name="ck_awareness_ledger_started_implies_assigned",
        ),
        CheckConstraint(
            "training_completed IS FALSE OR training_started IS TRUE",
            name="ck_awareness_ledger_completed_implies_started",
        ),
        CheckConstraint(
            "training_passed IS FALSE OR training_completed IS TRUE",
            name="ck_awareness_ledger_passed_implies_completed",
        ),
        CheckConstraint(
            "(campaign_closed IS TRUE AND no_activity_at_close IS NOT NULL) OR "
            "(campaign_closed IS FALSE AND no_activity_at_close IS NULL)",
            name="ck_awareness_ledger_close_disposition",
        ),
        CheckConstraint(
            "retain_until = campaign_date + 1826",
            name="ck_awareness_ledger_retention_horizon",
        ),
        Index("ix_awareness_ledger_retention", "tenant_scope", "retain_until"),
        Index(
            "ix_awareness_ledger_recipient_history",
            "tenant_scope",
            "recipient_pseudonym",
            "campaign_date",
        ),
    )

    awareness_ledger_entry_id = _pk()
    tenant_scope: Mapped[str] = mapped_column(String(64), nullable=False)
    pseudonym_key_version: Mapped[str] = mapped_column(String(32), nullable=False)
    recipient_pseudonym: Mapped[str] = mapped_column(String(64), nullable=False)
    assignment_exposure_pseudonym: Mapped[str] = mapped_column(String(64), nullable=False)
    campaign_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    campaign_date: Mapped[date] = mapped_column(Date, nullable=False)
    campaign_date_basis: Mapped[str] = mapped_column(String(32), nullable=False)
    targeted: Mapped[bool] = mapped_column(Boolean, nullable=False)
    accepted: Mapped[bool] = mapped_column(Boolean, nullable=False)
    delivered: Mapped[bool] = mapped_column(Boolean, nullable=False)
    observed_open: Mapped[bool] = mapped_column(Boolean, nullable=False)
    observed_click: Mapped[bool] = mapped_column(Boolean, nullable=False)
    reported: Mapped[bool] = mapped_column(Boolean, nullable=False)
    confirmed_interaction: Mapped[bool] = mapped_column(Boolean, nullable=False)
    training_assigned: Mapped[bool] = mapped_column(Boolean, nullable=False)
    training_started: Mapped[bool] = mapped_column(Boolean, nullable=False)
    training_completed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    training_passed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    campaign_closed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    no_activity_at_close: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    projected_at = mapped_column(DateTime(timezone=True), nullable=False)
    retain_until: Mapped[date] = mapped_column(Date, nullable=False)


class TrainingResource(Base):
    __tablename__ = "training_resources"
    __table_args__ = (
        CheckConstraint("char_length(btrim(title)) BETWEEN 1 AND 160", name="title_bounded"),
        CheckConstraint("char_length(btrim(content)) BETWEEN 1 AND 20000", name="content_bounded"),
        CheckConstraint("source_ref IS NULL OR char_length(source_ref) <= 500", name="source_ref_bounded"),
        CheckConstraint("version > 0", name="version_positive"),
    )

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
    created_by = mapped_column(UUID(as_uuid=True), nullable=True)
    created_at = mapped_column(DateTime(timezone=True), nullable=False, server_default=sa_text("now()"))
    submitted_at = mapped_column(DateTime(timezone=True), nullable=True)
    reviewed_by = mapped_column(UUID(as_uuid=True), nullable=True)
    reviewed_at = mapped_column(DateTime(timezone=True), nullable=True)
    review_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)


class TrainingAssignment(Base):
    __tablename__ = "training_assignments"
    __table_args__ = (
        ForeignKeyConstraint(
            ["recipient_assignment_id", "campaign_id", "recipient_id"],
            [
                "recipient_assignments.recipient_assignment_id",
                "recipient_assignments.campaign_id",
                "recipient_assignments.recipient_id",
            ],
            name="fk_training_assignments_recipient_identity",
            ondelete="CASCADE",
        ),
        UniqueConstraint("recipient_assignment_id", name="uq_training_assignment_recipient_assignment"),
        CheckConstraint("due_at >= assigned_at", name="ck_training_assignment_due_after_assigned"),
        CheckConstraint(
            "opened_at IS NULL OR opened_at >= assigned_at",
            name="ck_training_assignment_opened_after_assigned",
        ),
        CheckConstraint(
            "completed_at IS NULL OR completed_at >= assigned_at",
            name="ck_training_assignment_completed_after_assigned",
        ),
        CheckConstraint(
            "access_expires_at > due_at",
            name="ck_training_assignment_access_after_due",
        ),
        Index(
            "ix_training_assignments_reminder_due",
            "due_at",
            postgresql_where=sa_text("completed_at IS NULL AND followup_sent_at IS NULL"),
        ),
    )

    training_assignment_id = _pk()
    recipient_assignment_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("recipient_assignments.recipient_assignment_id", ondelete="CASCADE"),
        nullable=True,
    )
    recipient_id = mapped_column(UUID(as_uuid=True), nullable=False)
    resource_id = mapped_column(
        UUID(as_uuid=True), ForeignKey("training_resources.training_resource_id", ondelete="CASCADE"), nullable=False
    )
    campaign_id = mapped_column(UUID(as_uuid=True), nullable=True)
    assigned_at = mapped_column(DateTime(timezone=True), nullable=False)
    opened_at = mapped_column(DateTime(timezone=True), nullable=True)
    due_at = mapped_column(DateTime(timezone=True), nullable=False)
    access_expires_at = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at = mapped_column(DateTime(timezone=True), nullable=True)
    training_token_hash: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)
    training_completion_token_hash: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)
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
    __table_args__ = (
        Index(
            "uq_privacy_notices_single_current",
            "is_current",
            unique=True,
            postgresql_where=sa_text("is_current IS TRUE"),
        ),
    )

    notice_id = _pk()
    version: Mapped[int] = mapped_column(Integer, default=1)
    notice_text: Mapped[str] = mapped_column(Text)
    effective_at = mapped_column(DateTime(timezone=True), nullable=False)
    is_current: Mapped[bool] = mapped_column(Boolean, default=False)


class RetentionPolicy(Base):
    __tablename__ = "retention_policies"
    __table_args__ = (
        CheckConstraint(
            "retention_days BETWEEN 1 AND 365",
            # The MetaData naming convention expands this to
            # ck_retention_policies_days_bounded, matching migration 0032.
            name="days_bounded",
        ),
        Index(
            "uq_retention_policies_single_default",
            "is_default",
            unique=True,
            postgresql_where=sa_text("is_default IS TRUE"),
        ),
    )

    retention_policy_id = _pk()
    name: Mapped[str] = mapped_column(String(128))
    data_category: Mapped[str] = mapped_column(String(64))
    retention_days: Mapped[int] = mapped_column(Integer)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at = mapped_column(DateTime(timezone=True), nullable=False, server_default=sa_text("now()"))


class SystemSafetyState(Base):
    """Persistent, singleton delivery safety state.

    The database row is the source of truth shared by every API and worker
    replica.  Delivery workers take a shared row lock while contacting a mail
    provider; engaging the emergency stop takes the exclusive lock, giving
    the stop operation a clear ordering relative to an in-flight send.
    """

    __tablename__ = "system_safety_state"
    __table_args__ = (CheckConstraint("singleton_id = 1", name="ck_system_safety_state_singleton"),)

    singleton_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    emergency_stop_engaged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    generation: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default=sa_text("0"))
    engaged_at = mapped_column(DateTime(timezone=True), nullable=True)
    engaged_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    engage_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    disengaged_at = mapped_column(DateTime(timezone=True), nullable=True)
    disengaged_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    disengage_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_cancelled: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default=sa_text("0"))
    last_tokens_revoked: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default=sa_text("0"))
    updated_at = mapped_column(DateTime(timezone=True), nullable=False, server_default=sa_text("now()"))


class AuditEvent(Base):
    """Append-only hash-chained evidence, writable only by the DB dispatcher."""

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
    outbox_id = mapped_column(UUID(as_uuid=True), unique=True, nullable=True)
    origin_role: Mapped[str | None] = mapped_column(String(128), nullable=True)
    canonical_payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    chain_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default=sa_text("1"))


class TransactionalOutbox(Base):
    """Durable audit or queue intent committed with its business mutation."""

    __tablename__ = "transactional_outbox"
    __table_args__ = (
        CheckConstraint("kind IN ('audit', 'queue')", name="kind"),
        CheckConstraint("status IN ('pending', 'dispatching', 'dispatched', 'failed')", name="status"),
        CheckConstraint(
            "(kind = 'audit' AND topic IS NULL) OR (kind = 'queue' AND topic IS NOT NULL AND length(trim(topic)) > 0)",
            name="topic_matches_kind",
        ),
        CheckConstraint("attempts >= 0", name="attempts_nonnegative"),
    )

    outbox_id = _pk()
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    topic: Mapped[str | None] = mapped_column(String(64), nullable=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    origin_role: Mapped[str] = mapped_column(String(128), nullable=False, server_default=sa_text("session_user"))
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default=sa_text("'pending'"))
    available_at = mapped_column(DateTime(timezone=True), nullable=False, server_default=sa_text("now()"))
    lease_until = mapped_column(DateTime(timezone=True), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default=sa_text("0"))
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at = mapped_column(DateTime(timezone=True), nullable=False, server_default=sa_text("now()"))
    dispatched_at = mapped_column(DateTime(timezone=True), nullable=True)


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
    destination_url: Mapped[str | None] = mapped_column(CipherText, nullable=True)
    signing_secret: Mapped[str | None] = mapped_column(CipherText, nullable=True)
    last_delivery_at = mapped_column(DateTime(timezone=True), nullable=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class VerifiedDomain(Base):
    """A domain the operator has proven control of via the DNS TXT challenge.

    Verified domains are the only legitimate RoE target domains (recipients)
    and the only candidates for the sending-domain pool (lookalike senders).
    `active=False` revokes the proof without deleting the history.
    """

    __tablename__ = "verified_domains"

    verified_domain_id = _pk()
    domain: Mapped[str] = mapped_column(String(253), unique=True)
    challenge_token: Mapped[str] = mapped_column(String(64))
    verified_at = mapped_column(DateTime(timezone=True), nullable=False)
    verified_by = mapped_column(UUID(as_uuid=True), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at = mapped_column(DateTime(timezone=True), nullable=False, server_default=sa_text("now()"))


class RulesOfEngagement(Base):
    """Operator-signed authorization to run training engagements.

    One signed artifact binds the signer, authorizing party, engagement
    window, and the operator-verified target domains to the terms text.
    A campaign may only be scheduled and delivered under an unrevoked RoE
    whose window contains the delivery window. Signature version 2 is a
    canonical HMAC-SHA256 artifact binding every authorization field
    (kp_domain_models.roe).
    """

    __tablename__ = "rules_of_engagement"

    roe_id = _pk()
    signer: Mapped[str] = mapped_column(String(255))
    authorizing_party: Mapped[str] = mapped_column(String(255))
    terms_text: Mapped[str] = mapped_column(Text)
    terms_hash: Mapped[str] = mapped_column(String(64))
    signature: Mapped[str] = mapped_column(String(64))
    signature_version: Mapped[int] = mapped_column(Integer, default=2, server_default=sa_text("2"))
    signed_at = mapped_column(DateTime(timezone=True), nullable=False)
    window_start = mapped_column(DateTime(timezone=True), nullable=False)
    window_end = mapped_column(DateTime(timezone=True), nullable=False)
    target_domains: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    created_by = mapped_column(UUID(as_uuid=True), nullable=True)
    revoked_at = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by = mapped_column(UUID(as_uuid=True), nullable=True)
    revoked_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at = mapped_column(DateTime(timezone=True), nullable=False, server_default=sa_text("now()"))
