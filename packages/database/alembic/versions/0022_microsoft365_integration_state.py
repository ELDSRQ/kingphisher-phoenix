"""Durable Microsoft 365 directory and reported-mail integration state.

Revision ID: 0022_m365_integration
Revises: 0021_frozen_campaign_audiences
Create Date: 2026-08-27
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0022_m365_integration"
down_revision = "0021_frozen_campaign_audiences"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 0021 references were explicitly inert. Clear any pre-production raw
    # value rather than carrying a stable Entra group identifier forward in
    # plaintext; operators can reselect it through the GUI after this upgrade.
    op.execute("UPDATE audience_groups SET directory_group_ref = NULL WHERE directory_group_ref IS NOT NULL")
    op.alter_column("audience_groups", "directory_group_ref", type_=sa.Text(), existing_type=sa.String(256))
    op.add_column("audience_groups", sa.Column("directory_group_ref_hash", sa.String(length=64), nullable=True))
    op.create_unique_constraint(
        "uq_audience_groups_directory_group_ref_hash",
        "audience_groups",
        ["directory_group_ref_hash"],
    )
    op.add_column("recipients", sa.Column("directory_source", sa.String(length=32), nullable=True))
    op.add_column("recipients", sa.Column("directory_object_id_hash", sa.String(length=64), nullable=True))
    op.add_column("recipients", sa.Column("directory_generation", sa.Integer(), nullable=True))
    op.add_column(
        "recipients",
        sa.Column("directory_owned", sa.Boolean(), server_default=sa.text("false"), nullable=False),
    )
    op.create_index(
        "uq_recipients_directory_object_active",
        "recipients",
        ["directory_source", "directory_object_id_hash"],
        unique=True,
        postgresql_where=sa.text("directory_object_id_hash IS NOT NULL AND deleted_at IS NULL"),
    )

    op.create_table(
        "microsoft365_integration_states",
        sa.Column("integration_state_id", sa.UUID(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("scope_hash", sa.String(length=64), nullable=False),
        sa.Column("config_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("cursor", sa.Text(), nullable=True),
        sa.Column("cursor_kind", sa.String(length=16), nullable=True),
        sa.Column("status", sa.String(length=24), server_default="never", nullable=False),
        sa.Column("generation", sa.Integer(), server_default="0", nullable=False),
        sa.Column("pending_preview_id", sa.UUID(), nullable=True),
        sa.Column("pending_preview_hash", sa.String(length=64), nullable=True),
        sa.Column("pending_payload", sa.Text(), nullable=True),
        sa.Column("pending_created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("pending_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("active_job_key", sa.String(length=255), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_job_key", sa.String(length=255), nullable=True),
        sa.Column(
            "last_counts",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_applied_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(length=128), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("kind IN ('directory', 'mailbox')", name="ck_m365_integration_kind"),
        sa.CheckConstraint("provider IN ('microsoft365', 'mailpit')", name="ck_m365_integration_provider"),
        sa.CheckConstraint("generation >= 0", name="ck_m365_integration_generation"),
        sa.CheckConstraint(
            "status IN ('never', 'configuration_changed', 'error', 'truncated', 'rejected', "
            "'preview_ready', 'healthy', 'expired', 'discarded')",
            name="ck_m365_integration_status",
        ),
        sa.CheckConstraint(
            "(pending_preview_id IS NULL AND pending_preview_hash IS NULL AND pending_payload IS NULL "
            "AND pending_created_at IS NULL AND pending_expires_at IS NULL) OR "
            "(kind = 'directory' AND status = 'preview_ready' AND pending_preview_id IS NOT NULL "
            "AND pending_preview_hash IS NOT NULL AND pending_payload IS NOT NULL "
            "AND pending_created_at IS NOT NULL AND pending_expires_at > pending_created_at)",
            name="ck_m365_integration_pending_preview",
        ),
        sa.CheckConstraint(
            "(active_job_key IS NULL AND lease_expires_at IS NULL) OR "
            "(kind = 'mailbox' AND active_job_key IS NOT NULL AND lease_expires_at IS NOT NULL)",
            name="ck_m365_integration_mailbox_lease",
        ),
        sa.PrimaryKeyConstraint("integration_state_id"),
        sa.UniqueConstraint("kind", "scope_hash", name="uq_m365_integration_kind_scope"),
    )

    op.create_unique_constraint(
        "uq_recipient_assignments_attempt_binding",
        "recipient_assignments",
        ["recipient_assignment_id", "delivery_attempt_id"],
    )

    op.create_table(
        "delivery_report_correlations",
        sa.Column("delivery_attempt_id", sa.UUID(), nullable=False),
        sa.Column("recipient_assignment_id", sa.UUID(), nullable=False),
        sa.Column("report_verifier", sa.Text(), nullable=False),
        sa.Column("verifier_hash", sa.String(length=64), nullable=False),
        sa.Column("message_id", sa.String(length=255), nullable=False),
        sa.Column("provider_id", sa.String(length=512), nullable=True),
        sa.Column("provider_status", sa.String(length=64), nullable=True),
        sa.Column("provider_accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(
            ["recipient_assignment_id", "delivery_attempt_id"],
            ["recipient_assignments.recipient_assignment_id", "recipient_assignments.delivery_attempt_id"],
            name="fk_delivery_report_correlation_attempt",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("delivery_attempt_id"),
        sa.UniqueConstraint("message_id", name="uq_delivery_report_correlations_message_id"),
        sa.UniqueConstraint("recipient_assignment_id", name="uq_delivery_report_correlations_assignment"),
        sa.UniqueConstraint("verifier_hash", name="uq_delivery_report_correlations_verifier"),
    )
    op.create_table(
        "reported_mail_receipts",
        sa.Column("reported_mail_receipt_id", sa.UUID(), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("scope_hash", sa.String(length=64), nullable=False),
        sa.Column("external_id", sa.Text(), nullable=False),
        sa.Column("external_id_hash", sa.String(length=64), nullable=False),
        sa.Column("recipient_assignment_id", sa.UUID(), nullable=True),
        sa.Column("event_id", sa.UUID(), nullable=True),
        sa.Column("disposition", sa.String(length=32), nullable=False),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(
            ["recipient_assignment_id"],
            ["recipient_assignments.recipient_assignment_id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(["event_id"], ["events.event_id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("reported_mail_receipt_id"),
        sa.UniqueConstraint("provider", "scope_hash", "external_id_hash", name="uq_reported_mail_external"),
    )

    op.add_column("events", sa.Column("recipient_assignment_id", sa.UUID(), nullable=True))
    op.create_foreign_key(
        "fk_events_recipient_assignment",
        "events",
        "recipient_assignments",
        ["recipient_assignment_id"],
        ["recipient_assignment_id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "uq_events_reported_assignment",
        "events",
        ["recipient_assignment_id"],
        unique=True,
        postgresql_where=sa.text("event_type = 'MESSAGE_REPORTED' AND recipient_assignment_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_events_reported_assignment", table_name="events")
    op.drop_constraint("fk_events_recipient_assignment", "events", type_="foreignkey")
    op.drop_column("events", "recipient_assignment_id")
    op.drop_table("reported_mail_receipts")
    op.drop_table("delivery_report_correlations")
    op.drop_constraint("uq_recipient_assignments_attempt_binding", "recipient_assignments", type_="unique")
    op.drop_table("microsoft365_integration_states")
    op.drop_index("uq_recipients_directory_object_active", table_name="recipients")
    op.drop_column("recipients", "directory_owned")
    op.drop_column("recipients", "directory_generation")
    op.drop_column("recipients", "directory_object_id_hash")
    op.drop_column("recipients", "directory_source")
    op.drop_constraint("uq_audience_groups_directory_group_ref_hash", "audience_groups", type_="unique")
    op.drop_column("audience_groups", "directory_group_ref_hash")
    op.alter_column("audience_groups", "directory_group_ref", type_=sa.String(256), existing_type=sa.Text())
