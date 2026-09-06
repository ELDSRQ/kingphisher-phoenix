"""Record the submitting operator on a campaign launch gate.

The two-person approval rule must compare distinct people, not distinct lanes.
Persisting who submitted a campaign for review lets the approval endpoint bar
that operator (the last-mutator advancing the review) from also approving,
independently of the campaign's original ``created_by``.

Revision ID: 0036_launch_gate_submitted_by
Revises: 0035_audit_owner_separation
Create Date: 2026-09-06
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0036_launch_gate_submitted_by"
down_revision = "0035_audit_owner_separation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Nullable: gates written before this column existed carry no submitter and
    # the approval endpoint simply falls back to the ``created_by`` block for
    # those legacy reviews.
    op.add_column(
        "campaign_launch_gates",
        sa.Column("submitted_by", sa.UUID(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("campaign_launch_gates", "submitted_by")
