"""Bind after-click training to simulation cues (W4-01, KP-AUD-015).

A campaign's after-click training must demonstrably teach the social-engineering
cues its simulation relies on. This adds the durable state the coverage
validator and the approval gate check:

* ``training_cue_coverage`` — maps one reviewed training-resource *version* to a
  single simulation cue (``cue_id``) it teaches, recording the ``lesson_section``
  the operator pointed to and the ``quiz_item`` that checks it. A row is drafted
  by a campaign author and only counts toward the gate once an independent
  reviewer marks it reviewed (``reviewed``/``reviewed_by``/``reviewed_at`` move
  together, enforced by a CHECK), mirroring the training-resource review flow.
* ``campaign_cue_coverage_exceptions`` — a bounded, rationale-bearing waiver for
  one required cue that lacks coverage, so a documented exception can permit
  approval instead of silently sending uncovered training.
* ``campaign_launch_gates.cue_coverage_hash`` — a nullable fingerprint of the
  required cues and their reviewed coverage (plus exceptions) at review time.
  The approval gate recomputes it and rejects a decision taken against stale
  coverage; legacy gates keep NULL and must be reviewed again.

Additive only: two new tables and one new nullable column with a NULL-tolerant
CHECK. No existing object is altered or dropped.

Revision ID: 0050_training_cue_coverage
Revises: 0049_session_epoch_rotation
Create Date: 2026-10-29
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0050_training_cue_coverage"
down_revision = "0049_session_epoch_rotation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "training_cue_coverage",
        sa.Column("coverage_id", sa.UUID(), primary_key=True),
        sa.Column("training_resource_id", sa.UUID(), nullable=False),
        sa.Column("resource_version", sa.Integer(), nullable=False),
        sa.Column("cue_id", sa.String(length=128), nullable=False),
        sa.Column("lesson_section", sa.String(length=500), nullable=False),
        sa.Column("quiz_item", sa.String(length=500), nullable=False),
        sa.Column("reviewed", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("reviewed_by", sa.UUID(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["training_resource_id"],
            ["training_resources.training_resource_id"],
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "training_resource_id",
            "resource_version",
            "cue_id",
            name="uq_training_cue_coverage_cue",
        ),
        sa.CheckConstraint("resource_version > 0", name="ck_training_cue_coverage_version_positive"),
        sa.CheckConstraint(
            "char_length(btrim(cue_id)) BETWEEN 1 AND 128",
            name="ck_training_cue_coverage_cue_id",
        ),
        sa.CheckConstraint(
            "char_length(btrim(lesson_section)) BETWEEN 1 AND 500",
            name="ck_training_cue_coverage_lesson_section",
        ),
        sa.CheckConstraint(
            "char_length(btrim(quiz_item)) BETWEEN 1 AND 500",
            name="ck_training_cue_coverage_quiz_item",
        ),
        sa.CheckConstraint(
            "(reviewed IS FALSE AND reviewed_by IS NULL AND reviewed_at IS NULL) OR "
            "(reviewed IS TRUE AND reviewed_by IS NOT NULL AND reviewed_at IS NOT NULL)",
            name="ck_training_cue_coverage_review_all_or_nothing",
        ),
    )
    op.create_index(
        "ix_training_cue_coverage_resource",
        "training_cue_coverage",
        ["training_resource_id", "resource_version"],
    )

    op.create_table(
        "campaign_cue_coverage_exceptions",
        sa.Column("exception_id", sa.UUID(), primary_key=True),
        sa.Column("campaign_id", sa.UUID(), nullable=False),
        sa.Column("cue_id", sa.String(length=128), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("recorded_by", sa.UUID(), nullable=True),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.campaign_id"], ondelete="CASCADE"),
        sa.UniqueConstraint("campaign_id", "cue_id", name="uq_campaign_cue_coverage_exception_cue"),
        sa.CheckConstraint(
            "char_length(btrim(cue_id)) BETWEEN 1 AND 128",
            name="ck_campaign_cue_exception_cue_id",
        ),
        sa.CheckConstraint(
            "char_length(btrim(rationale)) BETWEEN 1 AND 1000",
            name="ck_campaign_cue_exception_rationale",
        ),
    )

    # Fingerprint of the campaign's required cues + their reviewed coverage at
    # review time. Nullable so gates written before this migration keep NULL and
    # are forced through a fresh review before approval.
    op.add_column(
        "campaign_launch_gates",
        sa.Column("cue_coverage_hash", sa.String(length=64), nullable=True),
    )
    op.create_check_constraint(
        "ck_campaign_launch_cue_coverage_hash",
        "campaign_launch_gates",
        "cue_coverage_hash IS NULL OR length(cue_coverage_hash) = 64",
    )


def downgrade() -> None:
    op.drop_constraint("ck_campaign_launch_cue_coverage_hash", "campaign_launch_gates", type_="check")
    op.drop_column("campaign_launch_gates", "cue_coverage_hash")
    op.drop_table("campaign_cue_coverage_exceptions")
    op.drop_index("ix_training_cue_coverage_resource", table_name="training_cue_coverage")
    op.drop_table("training_cue_coverage")
