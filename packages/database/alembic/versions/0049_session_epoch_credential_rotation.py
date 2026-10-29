"""Session epoch + credential rotation state machine (W1-07, KP-AUD-019).

Local dev-mode console sessions are stateless HS256 tokens with no server-side
revocation. This adds the authoritative, audited revocation and rotation state:

* ``console_session_epoch`` — a single-row monotonic epoch. The console stamps
  the current epoch into every minted token and bumps it on logout and on a
  successful password rotation; token validation rejects any token whose epoch
  is older than the committed one. A fresh stack keeps epoch 0 and revokes
  nothing until a bump raises the floor.
* ``credential_rotations`` — a per-credential rotation state machine mirroring
  W1-04's committed-generation / reconcile shape. ``generation`` is bumped when
  a rotation begins and ``applied_generation`` is advanced only after the new
  secret is written and verified; the gap is an explicit blocked-drift state
  while the OLD secret stays in place. ``live_gated`` marks credentials whose
  real rotation is performed out of band and never by this service. No secret
  value is ever stored in either table.

Additive only: two new tables, each seeded with the singleton/known row needed
so the console can bump in place without a create race. No existing object is
altered or dropped.

Revision ID: 0049_session_epoch_credential_rotation
Revises: 0048_provider_config_generation
Create Date: 2026-10-29
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0049_session_epoch_credential_rotation"
down_revision = "0048_provider_config_generation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "console_session_epoch",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("epoch", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint("id = 1", name="ck_console_session_epoch_singleton"),
    )
    # Seed the singleton at epoch 0 (no revocation yet) so the console can bump
    # it in place without a create race on first logout/rotation.
    op.execute("INSERT INTO console_session_epoch (id, epoch) VALUES (1, 0)")

    op.create_table(
        "credential_rotations",
        sa.Column("credential", sa.String(length=64), primary_key=True),
        sa.Column("generation", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("applied_generation", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("state", sa.String(length=16), nullable=False, server_default=sa.text("'idle'")),
        sa.Column("live_gated", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint(
            "state IN ('idle', 'rotating', 'applied', 'failed', 'pending_live')",
            name="ck_credential_rotations_state",
        ),
    )
    # Seed the one locally-rotatable credential at generation 0 (settled) so the
    # console bumps it in place without a create race on first rotation.
    op.execute(
        "INSERT INTO credential_rotations (credential, generation, applied_generation, state, live_gated) "
        "VALUES ('console_password', 0, 0, 'idle', false)"
    )


def downgrade() -> None:
    op.drop_table("credential_rotations")
    op.drop_table("console_session_epoch")
