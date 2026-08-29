"""Create the immutable initial database schema.

Revision ID: 0001_initial
Revises:
Create Date: 2026-08-02

Alembic revisions are historical records. The first revision must not import
the application's current ORM metadata: doing that makes a fresh install
create columns and tables that later revisions also create. This module owns
a static description of the schema as it existed at revision 0001.
"""

from __future__ import annotations

import contextlib

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None

_METADATA = sa.MetaData(
    naming_convention={
        "ix": "ix_%(column_0_label)s",
        "uq": "uq_%(table_name)s_%(column_0_name)s",
        "ck": "ck_%(table_name)s_%(constraint_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
        "pk": "pk_%(table_name)s",
    }
)
_UUID = UUID(as_uuid=True)


def _enum(name: str, *labels: str) -> sa.Enum:
    return sa.Enum(*labels, name=name)


SOURCE_TYPE = _enum("source_type", "ADVISORY", "RSS", "STIX", "BULK_DOWNLOAD", "CURATED")
CONFIDENCE = _enum("confidence", "HIGH", "MEDIUM", "LOW", "UNVERIFIED")
QUARANTINE_STATE = _enum("quarantine_state", "ACTIVE", "QUARANTINED", "REJECTED")
LURE_CATEGORY = _enum(
    "lure_category",
    "INVOICE",
    "PASSWORD_RESET",
    "SHARED_DOCUMENT",
    "EXECUTIVE_REQUEST",
    "VENDOR_IMPERSONATION",
    "OAUTH_CONSENT",
    "QR_PHISHING",
    "PAYROLL_HR",
    "CONFERENCE",
    "CALENDAR_INVITE",
    "URGENT_RESPONSE",
    "CREDENTIAL_REFERENCE",
    "MALWARE_REFERENCE",
    "INVOICE_REFERENCE",
    "OTHER",
)
PATTERN_APPROVAL_STATE = _enum("pattern_approval_state", "DRAFT", "PENDING", "APPROVED", "REJECTED")
TEMPLATE_APPROVAL_STATE = _enum("template_approval_state", "DRAFT", "PENDING", "APPROVED", "SUPERSEDED", "REJECTED")
CAMPAIGN_STATE = _enum(
    "campaign_state",
    "DRAFT",
    "PATTERN_REVIEW",
    "CONTENT_REVIEW",
    "SECURITY_REVIEW",
    "PRIVACY_REVIEW",
    "PENDING_APPROVAL",
    "APPROVED",
    "SCHEDULED",
    "SENDING",
    "ACTIVE",
    "STOPPED",
    "COMPLETED",
    "CANCELLED",
    "EXPIRED",
    "RECALL_IN_PROGRESS",
    "RECALLED",
    "REJECTED",
)
APPROVAL_TYPE = _enum("approval_type", "SECURITY", "PRIVACY", "HR", "PATTERN", "CONTENT")
APPROVAL_DECISION = _enum("approval_decision", "APPROVED", "REJECTED")
RECIPIENT_STATUS = _enum("recipient_status", "ACTIVE", "EXCLUDED", "DEPARTED")
EXCLUSION_TYPE = _enum(
    "exclusion_type", "GLOBAL", "ACCOMMODATION", "EXECUTIVE", "LEGAL_HOLD", "CAMPAIGN_SPECIFIC", "TEST_ACCOUNT"
)
TOKEN_STATUS = _enum("token_status", "ACTIVE", "CONSUMED", "EXPIRED", "REVOKED", "KILL_SWITCHED")
SEND_STATE = _enum("send_state", "QUEUED", "ACCEPTED", "FAILED", "DELIVERED", "EXPIRED")
EVENT_TYPE = _enum(
    "event_type",
    "SEND_ACCEPTED",
    "SEND_FAILED",
    "OPENED",
    "CLICKED",
    "LINK_RESOLVED",
    "PAGE_RENDERED",
    "HUMAN_INTERACTION_CONFIRMED",
    "MESSAGE_REPORTED",
    "TRAINING_STARTED",
    "TRAINING_COMPLETED",
    "EVENT_CORRECTED",
    "REPORT_INGESTED_REAL",
    "REPORT_INGESTED_SIMULATED",
)
TRAINING_ASSIGNMENT_STATUS = _enum(
    "training_assignment_status", "ASSIGNED", "STARTED", "COMPLETED", "EXPIRED", "REMINDED"
)
PRIVACY_REQUEST_TYPE = _enum("privacy_request_type", "SEARCH", "ACCESS_EXPORT", "CORRECTION", "DELETION", "EXCEPTION")

sa.Table(
    "sources",
    _METADATA,
    sa.Column("source_id", _UUID, primary_key=True),
    sa.Column("source_key", sa.String(64), nullable=False, unique=True),
    sa.Column("name", sa.String(255), nullable=False),
    sa.Column("source_type", SOURCE_TYPE, nullable=False),
    sa.Column("base_domain", sa.String(255), nullable=False),
    sa.Column("license_state_id", _UUID, sa.ForeignKey("source_terms.source_terms_id")),
    sa.Column("enabled", sa.Boolean, nullable=False),
    sa.Column("last_success_at", sa.DateTime(timezone=True)),
    sa.Column("last_attempt_at", sa.DateTime(timezone=True)),
    sa.Column("consecutive_failures", sa.Integer, nullable=False),
)
sa.Table(
    "source_terms",
    _METADATA,
    sa.Column("source_terms_id", _UUID, primary_key=True),
    sa.Column("source_id", _UUID, sa.ForeignKey("sources.source_id"), nullable=False),
    sa.Column("terms_reference", sa.Text, nullable=False),
    sa.Column("terms_hash", sa.String(64), nullable=False),
    sa.Column("commercial_use_ok", sa.Boolean, nullable=False),
    sa.Column("automation_ok", sa.Boolean, nullable=False),
    sa.Column("redistribution_ok", sa.Boolean, nullable=False),
    sa.Column("retention_ok", sa.Boolean, nullable=False),
    sa.Column("terms_reviewed_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("next_review_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("enabled", sa.Boolean, nullable=False),
)
sa.Table(
    "source_items",
    _METADATA,
    sa.Column("source_item_id", _UUID, primary_key=True),
    sa.Column("source_id", _UUID, sa.ForeignKey("sources.source_id"), nullable=False),
    sa.Column("publisher", sa.String(255), nullable=False),
    sa.Column("title", sa.Text, nullable=False),
    sa.Column("published_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("retrieved_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("sanitized_text", sa.Text, nullable=False),
    sa.Column("content_hash", sa.String(64), nullable=False),
    sa.Column("source_reference", sa.Text, nullable=False),
    sa.Column("license_state_id", _UUID),
    sa.Column("confidence", CONFIDENCE, nullable=False),
    sa.Column("claimed_actor", sa.Text),
    sa.Column("claimed_target_sector", sa.Text),
    sa.Column("extracted_indicators", JSONB, nullable=False),
    sa.Column("quarantine_state", QUARANTINE_STATE, nullable=False),
    sa.Column("quarantine_reason", sa.Text),
    sa.Column("duplicate_of", _UUID),
    sa.UniqueConstraint("source_id", "content_hash", name="uq_source_items_dedup"),
)
sa.Table(
    "campaign_patterns",
    _METADATA,
    sa.Column("campaign_pattern_id", _UUID, primary_key=True),
    sa.Column("pattern_version", sa.Integer, nullable=False),
    sa.Column("lure_category", LURE_CATEGORY, nullable=False),
    sa.Column("impersonation_category", sa.Text),
    sa.Column("target_role_category", sa.Text),
    sa.Column("emotional_triggers", JSONB, nullable=False),
    sa.Column("requested_action", sa.Text),
    sa.Column("delivery_method", sa.Text),
    sa.Column("warning_cues", JSONB, nullable=False),
    sa.Column("actor_type", sa.Text),
    sa.Column("sector_targeting", sa.Text),
    sa.Column("attack_mapping", JSONB, nullable=False),
    sa.Column("confidence", CONFIDENCE, nullable=False),
    sa.Column("supporting_evidence", JSONB, nullable=False),
    sa.Column("prohibited_content_indicators", JSONB, nullable=False),
    sa.Column("approval_state", PATTERN_APPROVAL_STATE, nullable=False),
    sa.Column("approved_by", _UUID),
    sa.Column("approved_at", sa.DateTime(timezone=True)),
    sa.Column("created_by", _UUID),
)
sa.Table(
    "template_versions",
    _METADATA,
    sa.Column("template_version_id", _UUID, primary_key=True),
    sa.Column("campaign_id", _UUID),
    sa.Column("version", sa.Integer, nullable=False),
    sa.Column("idempotency_key", sa.String(128), unique=True),
    sa.Column("generator_version", sa.String(64), nullable=False),
    sa.Column("prompt_template_version", sa.String(64), nullable=False),
    sa.Column("model_id", sa.String(128), nullable=False),
    sa.Column("input_hash", sa.String(64), nullable=False),
    sa.Column("raw_proposal", JSONB, nullable=False),
    sa.Column("edited_content", JSONB),
    sa.Column("safe_html", sa.Text),
    sa.Column("plain_text", sa.Text),
    sa.Column("subject", sa.Text),
    sa.Column("synthetic_sender_display", sa.Text),
    sa.Column("learning_objectives", JSONB, nullable=False),
    sa.Column("warning_cues", JSONB, nullable=False),
    sa.Column("training_explanation", sa.Text),
    sa.Column("approval_hash", sa.String(64)),
    sa.Column("approval_state", TEMPLATE_APPROVAL_STATE, nullable=False),
    sa.Column("unicode_validation", JSONB, nullable=False),
)
sa.Table(
    "campaigns",
    _METADATA,
    sa.Column("campaign_id", _UUID, primary_key=True),
    sa.Column("pattern_id", _UUID, sa.ForeignKey("campaign_patterns.campaign_pattern_id"), nullable=False),
    sa.Column("current_template_id", _UUID),
    sa.Column("title", sa.String(255), nullable=False),
    sa.Column("state", CAMPAIGN_STATE, nullable=False),
    sa.Column("sender_mailbox", sa.String(255), nullable=False),
    sa.Column("training_domain", sa.String(255), nullable=False),
    sa.Column("schedule_start", sa.DateTime(timezone=True)),
    sa.Column("schedule_end", sa.DateTime(timezone=True)),
    sa.Column("timezone", sa.String(64), nullable=False),
    sa.Column("max_recipients", sa.Integer, nullable=False),
    sa.Column("retention_policy_id", _UUID),
    sa.Column("difficulty", JSONB, nullable=False),
    sa.Column("manifest_hash", sa.String(64)),
    sa.Column("manifest_signed_at", sa.DateTime(timezone=True)),
    sa.Column("recall_of", _UUID),
    sa.Column("created_by", _UUID),
    sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
)
sa.Table(
    "campaign_approvals",
    _METADATA,
    sa.Column("campaign_approval_id", _UUID, primary_key=True),
    sa.Column("campaign_id", _UUID, sa.ForeignKey("campaigns.campaign_id"), nullable=False),
    sa.Column("approval_type", APPROVAL_TYPE, nullable=False),
    sa.Column("approver_id", _UUID, nullable=False),
    sa.Column("decision", APPROVAL_DECISION, nullable=False),
    sa.Column("rationale", sa.Text),
    sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("template_version_id", _UUID, nullable=False),
)
sa.Table(
    "recipients",
    _METADATA,
    sa.Column("recipient_id", _UUID, primary_key=True),
    sa.Column("employee_key", sa.Text, nullable=False),
    sa.Column("mailbox", sa.Text, nullable=False),
    sa.Column("mailbox_sha256", sa.String(64), nullable=False),
    sa.Column("display_name", sa.Text),
    sa.Column("department", sa.Text),
    sa.Column("is_test_account", sa.Boolean, nullable=False),
    sa.Column("status", RECIPIENT_STATUS, nullable=False),
    sa.Column("last_snapshot_source", sa.String(128)),
)
sa.Index("ix_recipients_mailbox_sha256", _METADATA.tables["recipients"].c.mailbox_sha256, unique=True)
sa.Table(
    "recipient_exclusions",
    _METADATA,
    sa.Column("recipient_exclusion_id", _UUID, primary_key=True),
    sa.Column("recipient_id", _UUID, sa.ForeignKey("recipients.recipient_id"), nullable=False),
    sa.Column("exclusion_type", EXCLUSION_TYPE, nullable=False),
    sa.Column("campaign_id", _UUID),
    sa.Column("reason", sa.Text),
    sa.Column("created_by", _UUID),
    sa.Column("expires_at", sa.DateTime(timezone=True)),
)
sa.Table(
    "tracking_tokens",
    _METADATA,
    sa.Column("token_id", _UUID, primary_key=True),
    sa.Column("token_hash", sa.String(64), nullable=False),
    sa.Column("token_prefix", sa.String(6), nullable=False),
    sa.Column("campaign_id", _UUID, sa.ForeignKey("campaigns.campaign_id"), nullable=False),
    sa.Column("recipient_assignment_id", _UUID, nullable=False),
    sa.Column("pepper_version", sa.Integer, nullable=False),
    sa.Column("status", TOKEN_STATUS, nullable=False),
    sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("revoked_at", sa.DateTime(timezone=True)),
    sa.Column("revoked_reason", sa.Text),
)
sa.Index("ix_tracking_tokens_token_hash", _METADATA.tables["tracking_tokens"].c.token_hash, unique=True)
sa.Table(
    "recipient_assignments",
    _METADATA,
    sa.Column("recipient_assignment_id", _UUID, primary_key=True),
    sa.Column("campaign_id", _UUID, sa.ForeignKey("campaigns.campaign_id"), nullable=False),
    sa.Column("recipient_id", _UUID, sa.ForeignKey("recipients.recipient_id"), nullable=False),
    sa.Column("snapshot_version", sa.Integer, nullable=False),
    sa.Column("token_id", _UUID),
    sa.Column("send_state", SEND_STATE, nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    sa.Column("idempotency_key", sa.String(128), nullable=False, unique=True),
)
sa.Table(
    "events",
    _METADATA,
    sa.Column("event_id", _UUID, primary_key=True),
    sa.Column("event_type", EVENT_TYPE, nullable=False),
    sa.Column("token_id", _UUID),
    sa.Column("recipient_id", _UUID),
    sa.Column("campaign_id", _UUID),
    sa.Column("confidence", CONFIDENCE, nullable=False),
    sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("client_ip", sa.String(45)),
    sa.Column("user_agent", sa.Text),
    sa.Column("correction_of", _UUID),
    sa.Column("corrected_by", _UUID),
    sa.Column("correction_rationale", sa.Text),
    sa.Column("payload", JSONB, nullable=False),
)
sa.Table(
    "training_resources",
    _METADATA,
    sa.Column("training_resource_id", _UUID, primary_key=True),
    sa.Column("title", sa.String(255), nullable=False),
    sa.Column("kind", sa.String(16), nullable=False),
    sa.Column("content", sa.Text, nullable=False),
    sa.Column("version", sa.Integer, nullable=False),
    sa.Column("requires_completion", sa.Boolean, nullable=False),
    sa.Column("source_ref", sa.Text),
    sa.Column("approval_state", TEMPLATE_APPROVAL_STATE, nullable=False),
)
sa.Table(
    "training_assignments",
    _METADATA,
    sa.Column("training_assignment_id", _UUID, primary_key=True),
    sa.Column("recipient_id", _UUID, nullable=False),
    sa.Column("resource_id", _UUID, sa.ForeignKey("training_resources.training_resource_id"), nullable=False),
    sa.Column("campaign_id", _UUID),
    sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("completed_at", sa.DateTime(timezone=True)),
    sa.Column("status", TRAINING_ASSIGNMENT_STATUS, nullable=False),
    sa.Column("followup_sent_at", sa.DateTime(timezone=True)),
)
sa.Table(
    "privacy_requests",
    _METADATA,
    sa.Column("privacy_request_id", _UUID, primary_key=True),
    sa.Column("request_type", PRIVACY_REQUEST_TYPE, nullable=False),
    sa.Column("requester_key", sa.Text, nullable=False),
    sa.Column("campaign_id", _UUID),
    sa.Column("status", sa.String(32), nullable=False),
    sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("completed_at", sa.DateTime(timezone=True)),
    sa.Column("completion_note", sa.Text),
)
sa.Table(
    "audit_events",
    _METADATA,
    sa.Column("audit_event_id", _UUID, primary_key=True),
    sa.Column("actor", sa.String(255), nullable=False),
    sa.Column("action", sa.String(128), nullable=False),
    sa.Column("object_type", sa.String(128), nullable=False),
    sa.Column("object_id", sa.String(255), nullable=False),
    sa.Column("outcome", sa.String(16), nullable=False),
    sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("detail", JSONB, nullable=False),
    sa.Column("prev_hash", sa.String(64), nullable=False),
    sa.Column("event_hash", sa.String(64), nullable=False, index=True),
    sa.Column("nonce", sa.String(64), nullable=False),
)
sa.Table(
    "retention_actions",
    _METADATA,
    sa.Column("retention_action_id", _UUID, primary_key=True),
    sa.Column("retention_policy_id", _UUID),
    sa.Column("executed_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("target_table", sa.String(128), nullable=False),
    sa.Column("row_count_deleted", sa.Integer, nullable=False),
    sa.Column("idempotency_key", sa.String(128), nullable=False, unique=True),
)
sa.Table(
    "alert_subscriptions",
    _METADATA,
    sa.Column("alert_subscription_id", _UUID, primary_key=True),
    sa.Column("user_id", _UUID, nullable=False),
    sa.Column("campaign_id", _UUID, sa.ForeignKey("campaigns.campaign_id"), nullable=False),
    sa.Column("channel", sa.String(16), nullable=False),
    sa.Column("active", sa.Boolean, nullable=False),
)


def upgrade() -> None:
    _METADATA.create_all(bind=op.get_bind())
    bind = op.get_bind()
    with contextlib.suppress(Exception):
        bind.exec_driver_sql("REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM PUBLIC")
        bind.exec_driver_sql("GRANT SELECT, INSERT ON audit_events TO audit_writer")


def downgrade() -> None:
    _METADATA.drop_all(bind=op.get_bind())
