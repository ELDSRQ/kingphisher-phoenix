"""Recurring cue-adaptive campaign programs (W4-03).

Lets an operator run a reviewed program as an ``adaptive`` blueprint whose later
iterations are materialized over time by a worker instead of eagerly. Every
materialized iteration is a DRAFT campaign that must still clear the normal
approval, Rules-of-Engagement, and schedule gates; nothing here sends, approves,
or advances a campaign past DRAFT.

Additive only:

* ``campaign_programs.generation_mode`` -- a new NOT NULL column with
  server_default ``'fixed_schedule'`` so every existing program keeps the
  original eager whole-timeline behavior. Only ``'adaptive'`` defers iteration
  generation to the worker. A NULL-free CHECK allowlists the two values.
* ``campaign_program_adaptations`` -- the durable, human-readable record of why
  each adaptive iteration adapted: the prior iteration's signals, the exact
  deterministic draft changes, and the enrollment decision (including which
  recipients were dropped as opt-out/suppressed or as scanner-only automation).
  Its unique ``(campaign_program_id, iteration_number)`` is the idempotency key
  that makes worker iteration generation safe across restarts and replicas.

No existing object is altered or dropped.

Revision ID: 0052_adaptive_programs
Revises: 0050_training_cue_coverage
Create Date: 2026-10-29
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0052_adaptive_programs"
down_revision = "0050_training_cue_coverage"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "campaign_programs",
        sa.Column(
            "generation_mode",
            sa.String(length=32),
            nullable=False,
            server_default="fixed_schedule",
        ),
    )
    op.create_check_constraint(
        "ck_campaign_program_generation_mode",
        "campaign_programs",
        "generation_mode IN ('fixed_schedule', 'adaptive')",
    )

    op.create_table(
        "campaign_program_adaptations",
        sa.Column("campaign_program_adaptation_id", sa.UUID(), primary_key=True),
        sa.Column("campaign_program_id", sa.UUID(), nullable=False),
        sa.Column("iteration_number", sa.Integer(), nullable=False),
        sa.Column("iteration_campaign_id", sa.UUID(), nullable=False),
        sa.Column("basis_campaign_id", sa.UUID(), nullable=False),
        sa.Column("signals", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("changes", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("enrollment", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(
            ["campaign_program_id"],
            ["campaign_programs.campaign_program_id"],
            name="fk_program_adaptations_program",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["iteration_campaign_id"],
            ["campaigns.campaign_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["basis_campaign_id"],
            ["campaigns.campaign_id"],
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "campaign_program_id",
            "iteration_number",
            name="uq_campaign_program_adaptation_iteration",
        ),
        sa.CheckConstraint(
            "iteration_number > 1",
            name="ck_campaign_program_adaptation_iteration_min",
        ),
    )


def downgrade() -> None:
    op.drop_table("campaign_program_adaptations")
    op.drop_constraint("ck_campaign_program_generation_mode", "campaign_programs", type_="check")
    op.drop_column("campaign_programs", "generation_mode")
