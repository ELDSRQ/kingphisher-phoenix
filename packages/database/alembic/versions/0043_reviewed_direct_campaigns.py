"""Allow an explicitly reviewed whole-roster send without fabricated canary evidence.

Existing campaigns keep their canary policy and evidence. New console campaigns
choose reviewed_direct; the delivery mode is part of their immutable review.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0043_reviewed_direct_campaigns"
down_revision = "0042_campaign_created_at"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "campaigns",
        sa.Column("delivery_mode", sa.String(32), nullable=False, server_default="canary"),
    )
    op.create_check_constraint(
        "ck_campaign_delivery_mode", "campaigns", "delivery_mode IN ('canary', 'reviewed_direct')"
    )
    op.drop_constraint("ck_campaign_launch_gate_state", "campaign_launch_gates", type_="check")
    op.create_check_constraint(
        "ck_campaign_launch_gate_state",
        "campaign_launch_gates",
        "state IN ('reviewed', 'canary_queued', 'canary_succeeded', 'canary_failed', 'expired', "
        "'full_published', 'direct_published')",
    )
    op.drop_constraint("ck_campaign_launch_full_publication_time", "campaign_launch_gates", type_="check")
    op.create_check_constraint(
        "ck_campaign_launch_full_publication_time",
        "campaign_launch_gates",
        "state NOT IN ('full_published', 'direct_published') OR full_published_at IS NOT NULL",
    )
    op.create_check_constraint(
        "ck_campaign_launch_direct_no_canary",
        "campaign_launch_gates",
        "state <> 'direct_published' OR (canary_queued_at IS NULL AND canary_expires_at IS NULL "
        "AND canary_succeeded_at IS NULL AND canary_evidence_hash IS NULL)",
    )


def downgrade() -> None:
    # Refuse downgrade once a direct send exists; never reinterpret its evidence.
    connection = op.get_bind()
    if connection.scalar(sa.text("SELECT EXISTS (SELECT 1 FROM campaigns WHERE delivery_mode = 'reviewed_direct')")):
        raise RuntimeError("reviewed direct campaigns must be preserved; downgrade is unavailable")
    op.drop_constraint("ck_campaign_launch_direct_no_canary", "campaign_launch_gates", type_="check")
    op.drop_constraint("ck_campaign_launch_gate_state", "campaign_launch_gates", type_="check")
    op.create_check_constraint(
        "ck_campaign_launch_gate_state",
        "campaign_launch_gates",
        "state IN ('reviewed', 'canary_queued', 'canary_succeeded', 'canary_failed', 'expired', 'full_published')",
    )
    op.drop_constraint("ck_campaign_launch_full_publication_time", "campaign_launch_gates", type_="check")
    op.create_check_constraint(
        "ck_campaign_launch_full_publication_time",
        "campaign_launch_gates",
        "state <> 'full_published' OR full_published_at IS NOT NULL",
    )
    op.drop_constraint("ck_campaign_delivery_mode", "campaigns", type_="check")
    op.drop_column("campaigns", "delivery_mode")
