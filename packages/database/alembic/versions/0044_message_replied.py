"""Recipient reply-ingestion: MESSAGE_REPLIED event and reply_mail_receipts.

Adds the MESSAGE_REPLIED tracking-event label, a durable reply replay-boundary
table mirroring reported_mail_receipts, a partial unique index enforcing one
MESSAGE_REPLIED event per assignment, and widens the Microsoft 365 integration
state to carry a 'reply_mailbox' lease scope. Data-minimizing: the reply table
stores only the encrypted external id, its hash, and a bounded disposition —
never the reply body or the sender address.

Revision ID: 0044_message_replied
Revises: 0043_reviewed_direct_campaigns
Create Date: 2026-10-11
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0044_message_replied"
down_revision = "0043_reviewed_direct_campaigns"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # PostgreSQL cannot ADD VALUE to an enum inside a transaction that then uses
    # the new label, and Alembic wraps each migration in a transaction. Add the
    # label in an autocommit block so the CREATE INDEX below (whose WHERE clause
    # references 'MESSAGE_REPLIED') can see a committed enum value. SQLAlchemy
    # persists StrEnum member names, so the label is the upper-case member name.
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE event_type ADD VALUE IF NOT EXISTS 'MESSAGE_REPLIED'")

    # Widen the integration-state kind and lease to carry a reply_mailbox scope.
    op.drop_constraint("ck_m365_integration_kind", "microsoft365_integration_states", type_="check")
    op.create_check_constraint(
        "ck_m365_integration_kind",
        "microsoft365_integration_states",
        "kind IN ('directory', 'mailbox', 'reply_mailbox')",
    )
    op.drop_constraint("ck_m365_integration_mailbox_lease", "microsoft365_integration_states", type_="check")
    op.create_check_constraint(
        "ck_m365_integration_mailbox_lease",
        "microsoft365_integration_states",
        "(active_job_key IS NULL AND lease_expires_at IS NULL) OR "
        "(kind IN ('mailbox', 'reply_mailbox') AND active_job_key IS NOT NULL "
        "AND lease_expires_at IS NOT NULL)",
    )

    op.create_table(
        "reply_mail_receipts",
        sa.Column("reply_mail_receipt_id", sa.UUID(), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("scope_hash", sa.String(length=64), nullable=False),
        sa.Column("external_id", sa.Text(), nullable=False),
        sa.Column("external_id_hash", sa.String(length=64), nullable=False),
        sa.Column("recipient_assignment_id", sa.UUID(), nullable=True),
        sa.Column("event_id", sa.UUID(), nullable=True),
        sa.Column("disposition", sa.String(length=32), nullable=False),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(
            ["recipient_assignment_id"],
            ["recipient_assignments.recipient_assignment_id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(["event_id"], ["events.event_id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("reply_mail_receipt_id"),
        sa.UniqueConstraint("provider", "scope_hash", "external_id_hash", name="uq_reply_mail_external"),
    )

    op.create_index(
        "uq_events_replied_assignment",
        "events",
        ["recipient_assignment_id"],
        unique=True,
        postgresql_where=sa.text("event_type = 'MESSAGE_REPLIED' AND recipient_assignment_id IS NOT NULL"),
    )


def downgrade() -> None:
    # Preserve recorded reply ingestion: refuse downgrade once a reply_mailbox
    # scope exists, mirroring the reviewed-direct preservation guard. The
    # MESSAGE_REPLIED enum label is intentionally left in place: PostgreSQL
    # cannot drop a single enum value, and rebuilding event_type to remove it
    # would require rewriting every row in events — not worth the risk for a
    # reversible-schema downgrade when no MESSAGE_REPLIED row can remain.
    connection = op.get_bind()
    if connection.scalar(
        sa.text("SELECT EXISTS (SELECT 1 FROM microsoft365_integration_states WHERE kind = 'reply_mailbox')")
    ):
        raise RuntimeError("reply mailbox integration state must be preserved; downgrade is unavailable")

    op.drop_index("uq_events_replied_assignment", table_name="events")
    op.drop_table("reply_mail_receipts")

    op.drop_constraint("ck_m365_integration_mailbox_lease", "microsoft365_integration_states", type_="check")
    op.create_check_constraint(
        "ck_m365_integration_mailbox_lease",
        "microsoft365_integration_states",
        "(active_job_key IS NULL AND lease_expires_at IS NULL) OR "
        "(kind = 'mailbox' AND active_job_key IS NOT NULL AND lease_expires_at IS NOT NULL)",
    )
    op.drop_constraint("ck_m365_integration_kind", "microsoft365_integration_states", type_="check")
    op.create_check_constraint(
        "ck_m365_integration_kind",
        "microsoft365_integration_states",
        "kind IN ('directory', 'mailbox')",
    )
