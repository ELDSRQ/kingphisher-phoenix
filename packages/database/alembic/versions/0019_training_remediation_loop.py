"""Add immutable training progress and purpose-scoped bearer verifier.

Revision ID: 0019_training_remediation_loop
Revises: 0018_persistent_emergency_stop
Create Date: 2026-08-27
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0019_training_remediation_loop"
down_revision = "0018_persistent_emergency_stop"
branch_labels = None
depends_on = None

TABLE = "training_assignments"
BUILTIN_RESOURCE_ID = "00000000-0000-4000-8000-000000000019"


def upgrade() -> None:
    op.add_column(TABLE, sa.Column("recipient_assignment_id", sa.UUID(), nullable=True))
    op.add_column(TABLE, sa.Column("opened_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(TABLE, sa.Column("due_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(TABLE, sa.Column("access_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(TABLE, sa.Column("training_token_hash", sa.String(length=64), nullable=True))
    op.add_column(TABLE, sa.Column("training_completion_token_hash", sa.String(length=64), nullable=True))

    # Preserve existing history. Only one legacy row may bind to a delivery
    # assignment; duplicates remain visible as legacy rows rather than being
    # deleted to satisfy a new uniqueness invariant.
    op.execute(
        """
        WITH matches AS (
            SELECT ta.training_assignment_id,
                   ra.recipient_assignment_id,
                   row_number() OVER (
                       PARTITION BY ra.recipient_assignment_id
                       ORDER BY ta.assigned_at, ta.training_assignment_id
                   ) AS match_rank
              FROM training_assignments ta
              JOIN recipient_assignments ra
                ON ra.recipient_id = ta.recipient_id
               AND ra.campaign_id = ta.campaign_id
        )
        UPDATE training_assignments ta
           SET recipient_assignment_id = matches.recipient_assignment_id
          FROM matches
         WHERE ta.training_assignment_id = matches.training_assignment_id
           AND matches.match_rank = 1
        """
    )
    op.execute(
        """
        UPDATE training_assignments
           SET opened_at = CASE
                   WHEN status = 'COMPLETED' THEN COALESCE(completed_at, assigned_at)
                   WHEN status = 'STARTED' THEN assigned_at
                   ELSE NULL
               END,
               due_at = assigned_at + interval '72 hours',
               access_expires_at = assigned_at + interval '90 days'
        """
    )
    op.alter_column(TABLE, "due_at", nullable=False)
    op.alter_column(TABLE, "access_expires_at", nullable=False)
    op.create_foreign_key(
        "fk_training_assignment_recipient_assignment",
        TABLE,
        "recipient_assignments",
        ["recipient_assignment_id"],
        ["recipient_assignment_id"],
        ondelete="CASCADE",
    )
    op.create_unique_constraint(
        "uq_training_assignment_recipient_assignment",
        TABLE,
        ["recipient_assignment_id"],
    )
    op.create_unique_constraint("uq_training_assignment_token_hash", TABLE, ["training_token_hash"])
    op.create_unique_constraint(
        "uq_training_assignment_completion_token_hash",
        TABLE,
        ["training_completion_token_hash"],
    )
    op.create_check_constraint("ck_training_assignment_due_after_assigned", TABLE, "due_at >= assigned_at")
    op.create_check_constraint(
        "ck_training_assignment_opened_after_assigned",
        TABLE,
        "opened_at IS NULL OR opened_at >= assigned_at",
    )
    op.create_check_constraint(
        "ck_training_assignment_completed_after_assigned",
        TABLE,
        "completed_at IS NULL OR completed_at >= assigned_at",
    )
    op.create_check_constraint(
        "ck_training_assignment_access_after_due",
        TABLE,
        "access_expires_at > due_at",
    )
    op.create_index(
        "ix_training_assignments_reminder_due",
        TABLE,
        ["due_at"],
        unique=False,
        postgresql_where=sa.text("completed_at IS NULL AND followup_sent_at IS NULL"),
    )
    # Older builds did not storage-deduplicate these events. Preserve the first
    # observation and remove only metric-equivalent replays before installing
    # the concurrency-safe unique index.
    op.execute(
        """
        WITH ranked AS (
            SELECT event_id,
                   row_number() OVER (
                       PARTITION BY token_id, event_type
                       ORDER BY occurred_at, event_id
                   ) AS replay_rank
              FROM events
             WHERE token_id IS NOT NULL
               AND event_type IN ('TRAINING_STARTED', 'TRAINING_COMPLETED')
        )
        DELETE FROM events e
         USING ranked
         WHERE e.event_id = ranked.event_id
           AND ranked.replay_rank > 1
        """
    )
    op.create_index(
        "uq_events_training_dedup",
        "events",
        ["token_id", "event_type"],
        unique=True,
        postgresql_where=sa.text("event_type IN ('TRAINING_STARTED', 'TRAINING_COMPLETED')"),
    )

    # A safe text-only lesson makes a fresh deployment functional without a
    # hidden seed-script prerequisite. API rendering always HTML-escapes it.
    op.execute(
        sa.text(
            """
        INSERT INTO training_resources (
            training_resource_id, title, kind, content, version,
            requires_completion, source_ref, approval_state
        ) VALUES (
            CAST(:resource_id AS uuid),
            'Recognize and report phishing',
            'article',
            'Pause before acting on urgency. Verify the sender and destination independently. '
            'Never enter credentials after following an unexpected link. '
            'Report suspicious messages to your security team.',
            1,
            true,
            'builtin:training-remediation-v1',
            'APPROVED'
        ) ON CONFLICT (training_resource_id) DO NOTHING
        """
        ).bindparams(resource_id=BUILTIN_RESOURCE_ID)
    )


def downgrade() -> None:
    op.drop_index("uq_events_training_dedup", table_name="events")
    op.drop_index("ix_training_assignments_reminder_due", table_name=TABLE)
    op.drop_constraint("ck_training_assignment_access_after_due", TABLE, type_="check")
    op.drop_constraint("ck_training_assignment_completed_after_assigned", TABLE, type_="check")
    op.drop_constraint("ck_training_assignment_opened_after_assigned", TABLE, type_="check")
    op.drop_constraint("ck_training_assignment_due_after_assigned", TABLE, type_="check")
    op.drop_constraint("uq_training_assignment_completion_token_hash", TABLE, type_="unique")
    op.drop_constraint("uq_training_assignment_token_hash", TABLE, type_="unique")
    op.drop_constraint("uq_training_assignment_recipient_assignment", TABLE, type_="unique")
    op.drop_constraint("fk_training_assignment_recipient_assignment", TABLE, type_="foreignkey")
    op.drop_column(TABLE, "training_completion_token_hash")
    op.drop_column(TABLE, "training_token_hash")
    op.drop_column(TABLE, "access_expires_at")
    op.drop_column(TABLE, "due_at")
    op.drop_column(TABLE, "opened_at")
    op.drop_column(TABLE, "recipient_assignment_id")
    op.execute(
        sa.text(
            """
        DELETE FROM training_resources r
         WHERE r.training_resource_id = CAST(:resource_id AS uuid)
           AND NOT EXISTS (
               SELECT 1 FROM training_assignments ta
                WHERE ta.resource_id = r.training_resource_id
           )
        """
        ).bindparams(resource_id=BUILTIN_RESOURCE_ID)
    )
