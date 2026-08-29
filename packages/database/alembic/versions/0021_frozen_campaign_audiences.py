"""Static campaign audiences and immutable frozen manifests.

Revision ID: 0021_frozen_campaign_audiences
Revises: 0020_transactional_audit_outbox
Create Date: 2026-08-27
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0021_frozen_campaign_audiences"
down_revision = "0020_transactional_audit_outbox"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audience_groups",
        sa.Column("audience_group_id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("directory_group_ref", sa.String(length=256), nullable=True),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("audience_group_id"),
        sa.UniqueConstraint("name", name="uq_audience_groups_name"),
    )
    op.create_table(
        "audience_group_members",
        sa.Column("audience_group_member_id", sa.UUID(), nullable=False),
        sa.Column("audience_group_id", sa.UUID(), nullable=False),
        sa.Column("recipient_id", sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(["audience_group_id"], ["audience_groups.audience_group_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["recipient_id"], ["recipients.recipient_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("audience_group_member_id"),
        sa.UniqueConstraint("audience_group_id", "recipient_id", name="uq_audience_group_member"),
    )
    op.create_index("ix_audience_group_members_recipient", "audience_group_members", ["recipient_id"], unique=False)
    op.create_table(
        "campaign_audiences",
        sa.Column("campaign_id", sa.UUID(), nullable=False),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.Column("group_ids", postgresql.JSONB(astext_type=sa.Text()), server_default="[]", nullable=False),
        sa.Column("departments", postgresql.JSONB(astext_type=sa.Text()), server_default="[]", nullable=False),
        sa.Column("statuses", postgresql.JSONB(astext_type=sa.Text()), server_default="[]", nullable=False),
        sa.Column(
            "include_recipient_ids", postgresql.JSONB(astext_type=sa.Text()), server_default="[]", nullable=False
        ),
        sa.Column(
            "exclude_recipient_ids", postgresql.JSONB(astext_type=sa.Text()), server_default="[]", nullable=False
        ),
        sa.Column("sample_size", sa.Integer(), nullable=True),
        sa.Column("sample_seed", sa.String(length=128), nullable=True),
        sa.Column("configuration_hash", sa.String(length=64), nullable=False),
        sa.Column("preview_hash", sa.String(length=64), nullable=True),
        sa.Column("manifest_hash", sa.String(length=64), nullable=True),
        sa.Column("frozen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("legacy_requires_configuration", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("version > 0", name="ck_campaign_audience_version_positive"),
        sa.CheckConstraint("sample_size IS NULL OR sample_size > 0", name="ck_campaign_audience_sample_positive"),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.campaign_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("campaign_id"),
    )
    op.create_table(
        "campaign_audience_manifest",
        sa.Column("campaign_id", sa.UUID(), nullable=False),
        sa.Column("recipient_id", sa.UUID(), nullable=False),
        sa.Column("audience_version", sa.Integer(), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("recipient_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("ordinal >= 0", name="ck_campaign_audience_manifest_ordinal_nonnegative"),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.campaign_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["recipient_id"], ["recipients.recipient_id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("campaign_id", "recipient_id"),
        sa.UniqueConstraint("campaign_id", "ordinal", name="uq_campaign_audience_manifest_ordinal"),
    )
    op.create_index(
        "ix_campaign_audience_manifest_recipient", "campaign_audience_manifest", ["recipient_id"], unique=False
    )

    # Existing campaigns are intentionally blocked, not inferred from the
    # current recipient directory. An operator must configure, preview and
    # freeze each one before any future schedule can create assignments.
    op.execute(
        """
        INSERT INTO campaign_audiences (
            campaign_id, version, group_ids, departments, statuses,
            include_recipient_ids, exclude_recipient_ids, configuration_hash,
            legacy_requires_configuration
        )
        SELECT campaign_id, 1, '[]'::jsonb, '[]'::jsonb, '[]'::jsonb,
               '[]'::jsonb, '[]'::jsonb,
               encode(digest('legacy-unconfigured:' || campaign_id::text, 'sha256'), 'hex'), true
          FROM campaigns
        ON CONFLICT (campaign_id) DO NOTHING
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION kp_guard_campaign_manifest_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $function$
        DECLARE
            target_campaign_id uuid;
            current_version integer;
            current_frozen_at timestamptz;
        BEGIN
            IF TG_OP = 'UPDATE' THEN
                RAISE EXCEPTION 'campaign audience manifest rows are immutable; invalidate and refreeze instead';
            END IF;
            target_campaign_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.campaign_id ELSE NEW.campaign_id END;
            SELECT version, frozen_at
              INTO current_version, current_frozen_at
              FROM campaign_audiences
             WHERE campaign_id = target_campaign_id;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'campaign audience definition is required before manifest mutation';
            END IF;
            IF current_frozen_at IS NOT NULL THEN
                RAISE EXCEPTION 'frozen campaign audience manifest is immutable; invalidate it first';
            END IF;
            IF TG_OP = 'INSERT' AND NEW.audience_version <> current_version THEN
                RAISE EXCEPTION 'campaign audience manifest version is stale';
            END IF;
            IF TG_OP = 'DELETE' THEN
                RETURN OLD;
            END IF;
            RETURN NEW;
        END
        $function$;
        CREATE TRIGGER campaign_audience_manifest_immutable
        BEFORE INSERT OR UPDATE OR DELETE ON campaign_audience_manifest
        FOR EACH ROW EXECUTE FUNCTION kp_guard_campaign_manifest_mutation();
        """
    )
    op.execute(
        """
        DO $grant$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'operator_api') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON audience_groups,
                    audience_group_members, campaign_audiences,
                    campaign_audience_manifest TO operator_api;
            END IF;
        END
        $grant$;
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS campaign_audience_manifest_immutable ON campaign_audience_manifest")
    op.execute("DROP FUNCTION IF EXISTS kp_guard_campaign_manifest_mutation()")
    op.drop_index("ix_campaign_audience_manifest_recipient", table_name="campaign_audience_manifest")
    op.drop_table("campaign_audience_manifest")
    op.drop_table("campaign_audiences")
    op.drop_index("ix_audience_group_members_recipient", table_name="audience_group_members")
    op.drop_table("audience_group_members")
    op.drop_table("audience_groups")
