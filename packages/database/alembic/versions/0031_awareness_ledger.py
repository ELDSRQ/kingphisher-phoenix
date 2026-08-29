"""Add confirmed-human dedup and the pseudonymous awareness ledger.

Revision ID: 0031_awareness_ledger
Revises: 0030_default_privacy_notice
Create Date: 2026-08-29
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0031_awareness_ledger"
down_revision = "0030_default_privacy_notice"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "uq_events_human_interaction_dedup",
        "events",
        ["token_id", "event_type"],
        unique=True,
        postgresql_where=sa.text("event_type = 'HUMAN_INTERACTION_CONFIRMED'"),
    )
    op.create_table(
        "awareness_ledger_entries",
        sa.Column("awareness_ledger_entry_id", sa.UUID(), nullable=False),
        sa.Column("tenant_scope", sa.String(length=64), nullable=False),
        sa.Column("pseudonym_key_version", sa.String(length=32), nullable=False),
        sa.Column("recipient_pseudonym", sa.String(length=64), nullable=False),
        sa.Column("assignment_exposure_pseudonym", sa.String(length=64), nullable=False),
        # Intentionally not a foreign key: a projection must survive raw
        # assignment/campaign cleanup for its independent retention period.
        sa.Column("campaign_id", sa.UUID(), nullable=False),
        sa.Column("campaign_date", sa.Date(), nullable=False),
        sa.Column("campaign_date_basis", sa.String(length=32), nullable=False),
        sa.Column("targeted", sa.Boolean(), nullable=False),
        sa.Column("accepted", sa.Boolean(), nullable=False),
        sa.Column("delivered", sa.Boolean(), nullable=False),
        sa.Column("observed_open", sa.Boolean(), nullable=False),
        sa.Column("observed_click", sa.Boolean(), nullable=False),
        sa.Column("reported", sa.Boolean(), nullable=False),
        sa.Column("confirmed_interaction", sa.Boolean(), nullable=False),
        sa.Column("training_assigned", sa.Boolean(), nullable=False),
        sa.Column("training_started", sa.Boolean(), nullable=False),
        sa.Column("training_completed", sa.Boolean(), nullable=False),
        sa.Column("training_passed", sa.Boolean(), nullable=False),
        sa.Column("campaign_closed", sa.Boolean(), nullable=False),
        sa.Column("no_activity_at_close", sa.Boolean(), nullable=True),
        sa.Column("projected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("retain_until", sa.Date(), nullable=False),
        sa.CheckConstraint(
            "tenant_scope = 'single_tenant_database'",
            name="ck_awareness_ledger_single_tenant_scope",
        ),
        sa.CheckConstraint(
            "recipient_pseudonym ~ '^[0-9a-f]{64}$'",
            name="ck_awareness_ledger_recipient_pseudonym_hex",
        ),
        sa.CheckConstraint(
            "assignment_exposure_pseudonym ~ '^[0-9a-f]{64}$'",
            name="ck_awareness_ledger_assignment_pseudonym_hex",
        ),
        sa.CheckConstraint(
            "char_length(btrim(pseudonym_key_version)) BETWEEN 1 AND 32",
            name="ck_awareness_ledger_key_version_bounded",
        ),
        sa.CheckConstraint(
            "campaign_date_basis IN ('scheduled_start', 'targeted_at')",
            name="ck_awareness_ledger_campaign_date_basis",
        ),
        sa.CheckConstraint(
            "delivered IS FALSE OR accepted IS TRUE",
            name="ck_awareness_ledger_delivered_implies_accepted",
        ),
        sa.CheckConstraint(
            "training_started IS FALSE OR training_assigned IS TRUE",
            name="ck_awareness_ledger_started_implies_assigned",
        ),
        sa.CheckConstraint(
            "training_completed IS FALSE OR training_started IS TRUE",
            name="ck_awareness_ledger_completed_implies_started",
        ),
        sa.CheckConstraint(
            "training_passed IS FALSE OR training_completed IS TRUE",
            name="ck_awareness_ledger_passed_implies_completed",
        ),
        sa.CheckConstraint(
            "(campaign_closed IS TRUE AND no_activity_at_close IS NOT NULL) OR "
            "(campaign_closed IS FALSE AND no_activity_at_close IS NULL)",
            name="ck_awareness_ledger_close_disposition",
        ),
        sa.CheckConstraint(
            "retain_until = campaign_date + 1826",
            name="ck_awareness_ledger_retention_horizon",
        ),
        sa.PrimaryKeyConstraint("awareness_ledger_entry_id"),
        sa.UniqueConstraint(
            "tenant_scope",
            "campaign_id",
            "assignment_exposure_pseudonym",
            name="uq_awareness_ledger_scope_campaign_exposure",
        ),
    )
    op.create_index(
        "ix_awareness_ledger_retention",
        "awareness_ledger_entries",
        ["tenant_scope", "retain_until"],
    )
    op.create_index(
        "ix_awareness_ledger_recipient_history",
        "awareness_ledger_entries",
        ["tenant_scope", "recipient_pseudonym", "campaign_date"],
    )
    # This lane exposes projection only to the retention worker. Named/API
    # access and exports require separate capability, audit, and notice work.
    op.execute("REVOKE ALL ON awareness_ledger_entries FROM PUBLIC")
    op.execute(
        """
        DO $grant$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'worker') THEN
                GRANT SELECT, INSERT, UPDATE ON awareness_ledger_entries TO worker;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kp_worker_retention') THEN
                GRANT SELECT, INSERT, UPDATE ON awareness_ledger_entries TO kp_worker_retention;
            END IF;
        END
        $grant$;
        """
    )


def downgrade() -> None:
    op.drop_index("ix_awareness_ledger_recipient_history", table_name="awareness_ledger_entries")
    op.drop_index("ix_awareness_ledger_retention", table_name="awareness_ledger_entries")
    op.drop_table("awareness_ledger_entries")
    op.drop_index("uq_events_human_interaction_dedup", table_name="events")
