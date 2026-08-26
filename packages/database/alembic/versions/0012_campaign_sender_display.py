"""Per-campaign sender display name.

Revision ID: 0012_campaign_sender_display
Revises: 0011_assignment_failure_reason
Create Date: 2026-08-26

The From header carried only a bare address, so the platform could not do the
display-name impersonation that is the primary vector in a phishing simulation
("Microsoft 365 Security <...>"). This adds the display name to the campaign, so
an operator can vary it per campaign alongside the local part and the (pool)
domain — the sender-persona model commercial awareness tools expose.

Nullable: existing campaigns keep a NULL display name and render as a bare
address exactly as before.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0012_campaign_sender_display"
down_revision = "0011_assignment_failure_reason"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("campaigns", sa.Column("sender_display_name", sa.String(length=255), nullable=True))


def downgrade() -> None:
    op.drop_column("campaigns", "sender_display_name")
