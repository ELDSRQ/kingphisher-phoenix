"""Require durable canary evidence before full campaign publication.

Revision ID: 0029_campaign_canary_gate
Revises: 0028_campaign_training_binding
Create Date: 2026-08-28
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0029_campaign_canary_gate"
down_revision = "0028_campaign_training_binding"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # A NULL binding on legacy approval rows is deliberate: those decisions
    # cannot authorize a manifest that did not yet exist.
    op.add_column(
        "campaign_approvals",
        sa.Column("launch_manifest_hash", sa.String(length=64), nullable=True),
    )
    op.create_check_constraint(
        "ck_campaign_approvals_launch_manifest_hash",
        "campaign_approvals",
        "launch_manifest_hash IS NULL OR length(launch_manifest_hash) = 64",
        postgresql_not_valid=True,
    )
    op.create_table(
        "campaign_launch_gates",
        sa.Column("campaign_id", sa.UUID(), nullable=False),
        sa.Column("review_manifest_hash", sa.String(length=64), nullable=False),
        sa.Column("content_manifest_hash", sa.String(length=64), nullable=False),
        sa.Column("template_approval_hash", sa.String(length=64), nullable=False),
        sa.Column("audience_manifest_hash", sa.String(length=64), nullable=False),
        sa.Column("canary_manifest_hash", sa.String(length=64), nullable=False),
        sa.Column("roe_id", sa.UUID(), nullable=False),
        sa.Column("state", sa.String(length=32), server_default="reviewed", nullable=False),
        sa.Column("canary_queued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("canary_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("provider", sa.String(length=64), nullable=True),
        sa.Column("provider_config_hash", sa.String(length=64), nullable=True),
        sa.Column("canary_evidence_hash", sa.String(length=64), nullable=True),
        sa.Column("canary_succeeded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("full_published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint(
            "state IN ('reviewed', 'canary_queued', 'canary_succeeded', 'canary_failed', 'expired', 'full_published')",
            name="ck_campaign_launch_gate_state",
        ),
        sa.CheckConstraint("length(review_manifest_hash) = 64", name="ck_campaign_launch_review_hash"),
        sa.CheckConstraint("length(content_manifest_hash) = 64", name="ck_campaign_launch_content_hash"),
        sa.CheckConstraint("length(template_approval_hash) = 64", name="ck_campaign_launch_template_hash"),
        sa.CheckConstraint("length(audience_manifest_hash) = 64", name="ck_campaign_launch_audience_hash"),
        sa.CheckConstraint("length(canary_manifest_hash) = 64", name="ck_campaign_launch_canary_hash"),
        sa.CheckConstraint(
            "provider_config_hash IS NULL OR length(provider_config_hash) = 64",
            name="ck_campaign_launch_provider_config_hash",
        ),
        sa.CheckConstraint(
            "canary_evidence_hash IS NULL OR length(canary_evidence_hash) = 64",
            name="ck_campaign_launch_evidence_hash",
        ),
        sa.CheckConstraint(
            "state NOT IN ('canary_queued', 'canary_succeeded', 'full_published') OR "
            "(canary_queued_at IS NOT NULL AND canary_expires_at IS NOT NULL)",
            name="ck_campaign_launch_queued_evidence",
        ),
        sa.CheckConstraint(
            "state NOT IN ('canary_succeeded', 'full_published') OR "
            "(provider IS NOT NULL AND provider_config_hash IS NOT NULL "
            "AND canary_evidence_hash IS NOT NULL AND canary_succeeded_at IS NOT NULL)",
            name="ck_campaign_launch_success_evidence",
        ),
        sa.CheckConstraint(
            "state <> 'full_published' OR full_published_at IS NOT NULL",
            name="ck_campaign_launch_full_publication_time",
        ),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.campaign_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["roe_id"], ["rules_of_engagement.roe_id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("campaign_id"),
    )
    op.create_table(
        "campaign_canary_recipients",
        sa.Column("campaign_id", sa.UUID(), nullable=False),
        sa.Column("recipient_id", sa.UUID(), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("recipient_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("ordinal >= 0", name="ck_campaign_canary_recipient_ordinal_nonnegative"),
        sa.CheckConstraint("length(recipient_hash) = 64", name="ck_campaign_canary_recipient_hash"),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaign_launch_gates.campaign_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["recipient_id"], ["recipients.recipient_id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("campaign_id", "recipient_id"),
        sa.UniqueConstraint("campaign_id", "ordinal", name="uq_campaign_canary_recipient_ordinal"),
    )
    op.create_index(
        "ix_campaign_canary_recipient_recipient",
        "campaign_canary_recipients",
        ["recipient_id"],
    )
    # Reviewed cohort rows are append-only within a review. Replacing a still
    # unlaunched review deletes the gate and cascades the whole old cohort;
    # individual row mutation is never legitimate.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION kp_guard_campaign_canary_update()
        RETURNS trigger LANGUAGE plpgsql AS $function$
        BEGIN
            RAISE EXCEPTION 'reviewed campaign canary recipient rows cannot be updated';
        END
        $function$;
        CREATE TRIGGER campaign_canary_recipient_no_update
        BEFORE UPDATE ON campaign_canary_recipients
        FOR EACH ROW EXECUTE FUNCTION kp_guard_campaign_canary_update();
        """
    )
    op.execute(
        """
        DO $grant$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'operator_api') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON campaign_launch_gates,
                    campaign_canary_recipients TO operator_api;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'worker') THEN
                GRANT SELECT, UPDATE ON campaign_launch_gates TO worker;
                GRANT SELECT ON campaign_canary_recipients TO worker;
            END IF;
        END
        $grant$;
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS campaign_canary_recipient_no_update ON campaign_canary_recipients")
    op.execute("DROP FUNCTION IF EXISTS kp_guard_campaign_canary_update()")
    op.drop_index("ix_campaign_canary_recipient_recipient", table_name="campaign_canary_recipients")
    op.drop_table("campaign_canary_recipients")
    op.drop_table("campaign_launch_gates")
    op.drop_constraint(
        "ck_campaign_approvals_launch_manifest_hash",
        "campaign_approvals",
        type_="check",
    )
    op.drop_column("campaign_approvals", "launch_manifest_hash")
