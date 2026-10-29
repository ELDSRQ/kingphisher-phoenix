"""Provider-config generation token for cross-store reconcile (W1-04, KP-AUD-008).

Selecting a generation provider commits a durable DB selection and then applies
filesystem/env/restart side effects (the gateway state file, the worker model
pin, a restart signal). Previously those side effects had no generation and no
reconcile, so a fault after the commit could silently leave the gateway/worker
pointed at a stale or inconsistent provider.

This adds a single-row ``provider_config_generation`` table holding a monotonic
generation token. The console bumps ``generation`` in the SAME transaction as a
selection and advances ``applied_generation`` only after the side effects are
written and verified; a gap between the two is an explicit "blocked drift"
state. The committed generation is mirrored to an on-disk marker the stateless
gateway reconciles its state file against (it has no DB handle), failing closed
on a stale generation.

Additive only: one new table seeded with its singleton row at generation 0. No
existing object is altered or dropped.

Revision ID: 0048_provider_config_generation
Revises: 0047_threat_library
Create Date: 2026-10-29
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0048_provider_config_generation"
down_revision = "0047_threat_library"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "provider_config_generation",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("generation", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("applied_generation", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("active_provider", sa.String(length=32), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint("id = 1", name="ck_provider_config_generation_singleton"),
    )
    # Seed the singleton at generation 0 (no provider selected yet) so the
    # console can bump it in place without a create race on first selection.
    op.execute(
        "INSERT INTO provider_config_generation (id, generation, applied_generation, active_provider) "
        "VALUES (1, 0, 0, NULL)"
    )


def downgrade() -> None:
    op.drop_table("provider_config_generation")
