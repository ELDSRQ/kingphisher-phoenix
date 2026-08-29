"""Make outbound delivery claims durable and duplicate-safe.

Revision ID: 0015_delivery_attempt_state
Revises: 0014_recipient_soft_delete_index
Create Date: 2026-08-27

The claim is committed before the external provider call. A worker loss can
therefore leave SENDING behind; reconciliation moves that state to
INDETERMINATE and never automatically resends it. ACCEPTED means provider
handoff only, while DELIVERED is reserved for a future delivery receipt.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0015_delivery_attempt_state"
down_revision = "0014_recipient_soft_delete_index"
branch_labels = None
depends_on = None

TABLE = "recipient_assignments"
ENUM_NAME = "send_state"


def upgrade() -> None:
    # SQLAlchemy persists StrEnum member names, not their lower-case values.
    op.execute("ALTER TYPE send_state ADD VALUE IF NOT EXISTS 'SENDING' AFTER 'QUEUED'")
    op.execute("ALTER TYPE send_state ADD VALUE IF NOT EXISTS 'INDETERMINATE' AFTER 'ACCEPTED'")
    op.add_column(TABLE, sa.Column("delivery_attempt_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column(
        TABLE,
        sa.Column("delivery_attempt_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
    )
    op.add_column(TABLE, sa.Column("delivery_claimed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(TABLE, sa.Column("provider_accepted_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(TABLE, sa.Column("delivery_confirmed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(TABLE, sa.Column("provider_message_id", sa.String(length=255), nullable=True))
    op.create_index(
        "ix_recipient_assignments_delivery_recovery",
        TABLE,
        ["send_state", "delivery_claimed_at"],
        unique=False,
    )


def downgrade() -> None:
    connection = op.get_bind()
    unsafe = connection.scalar(
        sa.text("SELECT count(*) FROM recipient_assignments WHERE send_state::text IN ('SENDING', 'INDETERMINATE')")
    )
    if unsafe:
        raise RuntimeError("resolve SENDING and INDETERMINATE assignments before downgrade")

    op.drop_index("ix_recipient_assignments_delivery_recovery", table_name=TABLE)
    op.drop_column(TABLE, "provider_message_id")
    op.drop_column(TABLE, "delivery_confirmed_at")
    op.drop_column(TABLE, "provider_accepted_at")
    op.drop_column(TABLE, "delivery_claimed_at")
    op.drop_column(TABLE, "delivery_attempt_count")
    op.drop_column(TABLE, "delivery_attempt_id")

    # PostgreSQL cannot remove enum values in place. Rebuild the type only
    # after proving no row uses a new state.
    op.alter_column(TABLE, "send_state", type_=sa.Text(), postgresql_using="send_state::text")
    op.execute("DROP TYPE send_state")
    legacy = postgresql.ENUM(
        "QUEUED",
        "ACCEPTED",
        "FAILED",
        "DELIVERED",
        "EXPIRED",
        name=ENUM_NAME,
    )
    legacy.create(connection)
    op.alter_column(
        TABLE,
        "send_state",
        type_=legacy,
        postgresql_using="send_state::send_state",
    )
