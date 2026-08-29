"""Add finite, independently governed campaign programs.

Revision ID: 0025_campaign_programs
Revises: 0024_database_invariants
Create Date: 2026-08-27
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0025_campaign_programs"
down_revision = "0024_database_invariants"
branch_labels = None
depends_on = None


def upgrade() -> None:
    program_state = postgresql.ENUM("ACTIVE", "PAUSED", name="campaign_program_state", create_type=False)
    program_state.create(op.get_bind(), checkfirst=True)
    op.create_table(
        "campaign_programs",
        sa.Column("campaign_program_id", sa.UUID(), nullable=False),
        sa.Column("source_campaign_id", sa.UUID(), nullable=False),
        sa.Column("state", program_state, nullable=False),
        sa.Column("version", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.Column("cadence_days", sa.Integer(), nullable=False),
        sa.Column("occurrence_count", sa.Integer(), nullable=False),
        sa.Column("configuration_hash", sa.String(length=64), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("version > 0", name="version_positive"),
        sa.CheckConstraint(
            "cadence_days IN (7, 14, 28, 84)",
            name="cadence_allowlist",
        ),
        sa.CheckConstraint(
            "occurrence_count BETWEEN 2 AND 12",
            name="occurrence_count_bounded",
        ),
        sa.CheckConstraint(
            "configuration_hash ~ '^[0-9a-f]{64}$'",
            name="configuration_hash_hex",
        ),
        sa.ForeignKeyConstraint(
            ["source_campaign_id"],
            ["campaigns.campaign_id"],
            name="fk_campaign_programs_source_campaign_id_campaigns",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("campaign_program_id", name="pk_campaign_programs"),
        sa.UniqueConstraint("source_campaign_id", name="uq_campaign_programs_source_campaign_id"),
    )
    op.create_table(
        "campaign_program_occurrences",
        sa.Column("campaign_program_occurrence_id", sa.UUID(), nullable=False),
        sa.Column("campaign_program_id", sa.UUID(), nullable=False),
        sa.Column("occurrence_number", sa.Integer(), nullable=False),
        sa.Column("campaign_id", sa.UUID(), nullable=False),
        sa.Column("schedule_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("schedule_end", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "occurrence_number > 0",
            name="occurrence_number_positive",
        ),
        sa.CheckConstraint(
            "schedule_end > schedule_start",
            name="window_ordered",
        ),
        sa.ForeignKeyConstraint(
            ["campaign_id"],
            ["campaigns.campaign_id"],
            name="fk_campaign_program_occurrences_campaign_id_campaigns",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["campaign_program_id"],
            ["campaign_programs.campaign_program_id"],
            name="fk_program_occurrences_program",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "campaign_program_occurrence_id",
            name="pk_campaign_program_occurrences",
        ),
        sa.UniqueConstraint("campaign_id", name="uq_campaign_program_occurrences_campaign_id"),
        sa.UniqueConstraint(
            "campaign_program_id",
            "occurrence_number",
            name="uq_campaign_program_occurrence_number",
        ),
    )


def downgrade() -> None:
    op.drop_table("campaign_program_occurrences")
    op.drop_table("campaign_programs")
    postgresql.ENUM(name="campaign_program_state").drop(op.get_bind(), checkfirst=True)
