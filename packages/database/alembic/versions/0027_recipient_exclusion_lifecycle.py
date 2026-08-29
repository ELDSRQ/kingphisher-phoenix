"""Add append-only recipient exclusion lifecycle metadata.

Revision ID: 0027_recipient_exclusions
Revises: 0026_training_resource_library
Create Date: 2026-08-27
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0027_recipient_exclusions"
down_revision = "0026_training_resource_library"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # The server default safely timestamps existing exclusions without
    # rewriting their reason or changing whether they are currently active.
    op.add_column(
        "recipient_exclusions",
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.add_column("recipient_exclusions", sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("recipient_exclusions", sa.Column("revoked_by", sa.UUID(), nullable=True))
    op.add_column("recipient_exclusions", sa.Column("revoke_reason", sa.Text(), nullable=True))
    op.create_index(
        "ix_recipient_exclusions_recipient_created",
        "recipient_exclusions",
        ["recipient_id", "created_at"],
    )
    op.create_index(
        "ix_recipient_exclusions_active_scope",
        "recipient_exclusions",
        ["recipient_id", "campaign_id"],
        postgresql_where=sa.text("revoked_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_recipient_exclusions_active_scope", table_name="recipient_exclusions")
    op.drop_index("ix_recipient_exclusions_recipient_created", table_name="recipient_exclusions")
    op.drop_column("recipient_exclusions", "revoke_reason")
    op.drop_column("recipient_exclusions", "revoked_by")
    op.drop_column("recipient_exclusions", "revoked_at")
    op.drop_column("recipient_exclusions", "created_at")
