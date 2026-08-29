"""Durable ACS delivery receipts, suppressions, and pacing state.

Revision ID: 0023_acs_delivery_receipts
Revises: 0022_m365_integration
Create Date: 2026-08-27
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0023_acs_delivery_receipts"
down_revision = "0022_m365_integration"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "delivery_provider_events",
        sa.Column("delivery_provider_event_id", sa.UUID(), nullable=False),
        sa.Column("provider", sa.String(length=16), nullable=False),
        sa.Column("external_event_id_hash", sa.String(length=64), nullable=False),
        sa.Column("delivery_attempt_id", sa.UUID(), nullable=False),
        sa.Column("recipient_assignment_id", sa.UUID(), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("status_detail_hash", sa.String(length=64), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("provider IN ('acs')", name="ck_delivery_provider_events_provider"),
        sa.CheckConstraint(
            "status IN ('delivered', 'bounced', 'suppressed', 'quarantined', 'filtered_spam', 'expanded', 'failed')",
            name="ck_delivery_provider_events_status",
        ),
        sa.ForeignKeyConstraint(
            ["delivery_attempt_id"],
            ["delivery_report_correlations.delivery_attempt_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["recipient_assignment_id"],
            ["recipient_assignments.recipient_assignment_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("delivery_provider_event_id"),
        sa.UniqueConstraint("external_event_id_hash", name="uq_delivery_provider_events_external_hash"),
    )
    op.create_index(
        "ix_delivery_provider_events_assignment",
        "delivery_provider_events",
        ["recipient_assignment_id", "occurred_at"],
    )
    op.create_table(
        "recipient_delivery_suppressions",
        sa.Column("recipient_id", sa.UUID(), nullable=False),
        sa.Column("provider", sa.String(length=16), nullable=False),
        sa.Column("reason", sa.String(length=24), nullable=False),
        sa.Column("source_event_hash", sa.String(length=64), nullable=False),
        sa.Column("active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("provider IN ('acs')", name="ck_recipient_delivery_suppressions_provider"),
        sa.CheckConstraint(
            "reason IN ('bounced', 'suppressed', 'filtered_spam')",
            name="ck_recipient_delivery_suppressions_reason",
        ),
        sa.ForeignKeyConstraint(["recipient_id"], ["recipients.recipient_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("recipient_id"),
    )
    op.create_table(
        "delivery_pacing_states",
        sa.Column("provider", sa.String(length=16), nullable=False),
        sa.Column("minute_window_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("minute_count", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("day_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("daily_count", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("next_batch_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("provider IN ('acs')", name="ck_delivery_pacing_states_provider"),
        sa.CheckConstraint("minute_count >= 0 AND daily_count >= 0", name="ck_delivery_pacing_states_counts"),
        sa.PrimaryKeyConstraint("provider"),
    )
    op.create_index(
        "uq_delivery_report_correlations_provider_id",
        "delivery_report_correlations",
        ["provider_id"],
        unique=True,
        postgresql_where=sa.text("provider_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_delivery_report_correlations_provider_id", table_name="delivery_report_correlations")
    op.drop_table("delivery_pacing_states")
    op.drop_table("recipient_delivery_suppressions")
    op.drop_index("ix_delivery_provider_events_assignment", table_name="delivery_provider_events")
    op.drop_table("delivery_provider_events")
