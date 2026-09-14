"""Add the aggregation_candidates store (M3 background campaign aggregation).

A background aggregation pass ranks current-campaign candidates from the
ingested-item pool and stores them here for operator review. Advisory only:
rows carry public threat-intel facts (never PII), and nothing is acted on until
an operator promotes a candidate into a campaign pattern.

Revision ID: 0039_aggregation_candidates
Revises: 0038_unique_constraint_naming
Create Date: 2026-09-14
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0039_aggregation_candidates"
down_revision = "0038_unique_constraint_naming"
branch_labels = None
depends_on = None

_REVIEW_STATE = postgresql.ENUM(
    "pending",
    "promoted",
    "dismissed",
    name="aggregation_review_state",
    create_type=False,
)


def upgrade() -> None:
    _REVIEW_STATE.create(op.get_bind(), checkfirst=True)
    op.create_table(
        "aggregation_candidates",
        sa.Column("aggregation_candidate_id", sa.UUID(), nullable=False),
        sa.Column("run_id", sa.UUID(), nullable=False),
        sa.Column("rank", sa.Integer(), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("as_of", sa.Text(), nullable=False, server_default=""),
        sa.Column("rationale", sa.Text(), nullable=False, server_default=""),
        sa.Column("model_id", sa.String(length=128), nullable=False),
        sa.Column("record", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("source_item_ids", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("review_state", _REVIEW_STATE, nullable=False, server_default="pending"),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reviewed_by", sa.String(length=255), nullable=True),
        sa.Column("promoted_pattern_id", sa.UUID(), nullable=True),
        sa.CheckConstraint("rank >= 1", name="ck_aggregation_candidates_rank_positive"),
        sa.CheckConstraint("score >= 0 AND score <= 1", name="ck_aggregation_candidates_score_unit"),
        sa.PrimaryKeyConstraint("aggregation_candidate_id"),
    )
    op.create_index("ix_aggregation_candidates_run", "aggregation_candidates", ["run_id", "rank"])
    op.create_index("ix_aggregation_candidates_review", "aggregation_candidates", ["review_state", "created_at"])
    # Least-privilege: only the operator workload reads/writes candidates (it
    # runs the pass, reviews, and promotes). Mirrors the shared grant matrix in
    # kp_database.grants; a missing role is a no-op so non-managed/dev setups are
    # unaffected.
    op.execute("REVOKE ALL ON aggregation_candidates FROM PUBLIC")
    op.execute(
        """
        DO $grant$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kp_operator') THEN
                GRANT SELECT, INSERT, UPDATE ON aggregation_candidates TO kp_operator;
            END IF;
        END
        $grant$;
        """
    )


def downgrade() -> None:
    op.drop_index("ix_aggregation_candidates_review", table_name="aggregation_candidates")
    op.drop_index("ix_aggregation_candidates_run", table_name="aggregation_candidates")
    op.drop_table("aggregation_candidates")
    _REVIEW_STATE.drop(op.get_bind(), checkfirst=True)
