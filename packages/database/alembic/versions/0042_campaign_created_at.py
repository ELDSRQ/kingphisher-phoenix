"""Record when each campaign was created.

The Campaign table had no creation timestamp and the console listed campaigns
in random-UUID order, so an operator could not tell which campaigns were the
most recent. Add a ``created_at`` column so the "All campaigns" view can show
and sort by recency.

NOT NULL with ``server_default now()``: campaigns written before this column
existed are backfilled to the migration time (their true creation instant is
unrecoverable, and the migration time is a safe, monotonic lower bound for
"recent-ness" relative to campaigns created afterward). New rows get now()
unless the application sets it explicitly.

Revision ID: 0042_campaign_created_at
Revises: 0041_ai_generation_providers
Create Date: 2026-10-04
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0042_campaign_created_at"
down_revision = "0041_ai_generation_providers"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "campaigns",
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )


def downgrade() -> None:
    op.drop_column("campaigns", "created_at")
