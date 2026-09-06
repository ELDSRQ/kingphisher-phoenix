"""Add btree indexes for campaign-report filter predicates.

The campaign funnel/reporting queries (``kp_database.reporting``) filter on
``campaign_id``/``token_id`` foreign-key columns that carried no standalone
index, forcing sequential scans as event and assignment volume grows. See the
``WHERE``/``JOIN`` predicates in ``kp_database/reporting.py`` (recipient
assignment, event, tracking-token, and training-assignment counts).

Each index name follows the metadata naming convention ``ix_%(column_0_label)s``
(i.e. ``ix_<table>_<column>``), which is exactly what ``index=True`` on the
mapped columns resolves to, so ``alembic revision --autogenerate`` yields an
empty diff after this upgrade. Names are wrapped in ``op.f()`` so the convention
is not re-applied to an already-final name.

Revision ID: 0034_reporting_filter_indexes
Revises: 0033_training_knowledge_check
Create Date: 2026-09-06
"""

from __future__ import annotations

from alembic import op

revision = "0034_reporting_filter_indexes"
down_revision = "0033_training_knowledge_check"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        op.f("ix_recipient_assignments_campaign_id"),
        "recipient_assignments",
        ["campaign_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_tracking_tokens_campaign_id"),
        "tracking_tokens",
        ["campaign_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_events_campaign_id"),
        "events",
        ["campaign_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_events_token_id"),
        "events",
        ["token_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_training_assignments_campaign_id"),
        "training_assignments",
        ["campaign_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_training_assignments_campaign_id"), table_name="training_assignments")
    op.drop_index(op.f("ix_events_token_id"), table_name="events")
    op.drop_index(op.f("ix_events_campaign_id"), table_name="events")
    op.drop_index(op.f("ix_tracking_tokens_campaign_id"), table_name="tracking_tokens")
    op.drop_index(op.f("ix_recipient_assignments_campaign_id"), table_name="recipient_assignments")
