"""Add persistent singleton emergency-stop state.

Revision ID: 0018_persistent_emergency_stop
Revises: 0017_roe_signature_v2
Create Date: 2026-08-27

The prior global kill switch was reconstructed from an audit event and only
cancelled work that existed at that instant.  This row is an operational
interlock shared by every scheduler and delivery-worker replica.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0018_persistent_emergency_stop"
down_revision = "0017_roe_signature_v2"
branch_labels = None
depends_on = None

TABLE = "system_safety_state"


def upgrade() -> None:
    op.create_table(
        TABLE,
        sa.Column("singleton_id", sa.Integer(), nullable=False),
        sa.Column("emergency_stop_engaged", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("generation", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("engaged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("engaged_by", sa.String(length=255), nullable=True),
        sa.Column("engage_reason", sa.Text(), nullable=True),
        sa.Column("disengaged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("disengaged_by", sa.String(length=255), nullable=True),
        sa.Column("disengage_reason", sa.Text(), nullable=True),
        sa.Column("last_cancelled", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("last_tokens_revoked", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint("singleton_id = 1", name="ck_system_safety_state_singleton"),
        sa.PrimaryKeyConstraint("singleton_id"),
    )
    # Preserve the irreversible legacy behavior on upgrade.  If the audit
    # chain contains a prior global engagement, the new persistent state
    # starts engaged and requires the new authorized reset flow.  A clean
    # installation (or one that used only campaign-scoped stops) starts open.
    op.execute(
        sa.text(
            """
            WITH latest_legacy_stop AS (
                SELECT actor, occurred_at
                  FROM audit_events
                 WHERE action = 'kill-switch.engage'
                   AND object_type = 'system'
                   AND object_id = 'delivery'
                 ORDER BY occurred_at DESC
                 LIMIT 1
            )
            INSERT INTO system_safety_state (
                singleton_id, emergency_stop_engaged, generation,
                engaged_at, engaged_by, engage_reason,
                last_cancelled, last_tokens_revoked
            )
            SELECT 1,
                   latest_legacy_stop.occurred_at IS NOT NULL,
                   CASE WHEN latest_legacy_stop.occurred_at IS NULL THEN 0 ELSE 1 END,
                   latest_legacy_stop.occurred_at,
                   latest_legacy_stop.actor,
                   CASE WHEN latest_legacy_stop.occurred_at IS NULL
                        THEN NULL
                        ELSE 'migrated from legacy global kill-switch audit event'
                   END,
                   0,
                   0
              FROM (SELECT 1) AS singleton_seed
              LEFT JOIN latest_legacy_stop ON true
            """
        )
    )


def downgrade() -> None:
    op.drop_table(TABLE)
