"""Optional send-time spread window for a campaign's full-audience publish.

Operators asked to trickle a real campaign's mail out over a few hours rather
than releasing all of it in one burst, so the send looks less like a single
automated blast. This records the spread window per campaign as an opt-in
integer number of hours.

Nullable by design: every campaign written before this column existed, and
every campaign that does not set it, keeps the original burst behavior. Only a
campaign with a value set is paced, and only its full-audience phase — the
canary phase is never spread. The bound (1..168 hours) mirrors the model
CheckConstraint.

Revision ID: 0040_campaign_send_time_spread
Revises: 0039_aggregation_candidates
Create Date: 2026-09-27
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0040_campaign_send_time_spread"
down_revision = "0039_aggregation_candidates"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "campaigns",
        sa.Column("spread_over_hours", sa.Integer(), nullable=True),
    )
    op.create_check_constraint(
        "spread_over_hours_bounded",
        "campaigns",
        "spread_over_hours IS NULL OR (spread_over_hours BETWEEN 1 AND 168)",
    )


def downgrade() -> None:
    op.drop_constraint("spread_over_hours_bounded", "campaigns", type_="check")
    op.drop_column("campaigns", "spread_over_hours")
