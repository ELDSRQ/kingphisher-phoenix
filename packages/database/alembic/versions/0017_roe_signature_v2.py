"""Version complete Rules-of-Engagement signatures and revoke legacy rows.

Revision ID: 0017_roe_signature_v2
Revises: 0016_tracking_token_hmac
Create Date: 2026-08-27

Version 1 signed only terms_hash, signer, and signed_at. It cannot be safely
upgraded because the original signature provides no proof for the structured
authorization fields. Existing unrevoked rows are therefore revoked and must
be reviewed and re-signed through the GUI as version 2 artifacts.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0017_roe_signature_v2"
down_revision = "0016_tracking_token_hmac"
branch_labels = None
depends_on = None

TABLE = "rules_of_engagement"


def upgrade() -> None:
    op.add_column(
        TABLE,
        sa.Column("signature_version", sa.Integer(), nullable=False, server_default=sa.text("1")),
    )
    op.execute(
        """
        UPDATE rules_of_engagement
           SET revoked_at = COALESCE(revoked_at, now()),
               revoked_reason = COALESCE(
                   revoked_reason,
                   'legacy incomplete RoE signature revoked by migration 0017; review and re-sign'
               )
         WHERE signature_version = 1
        """
    )
    op.alter_column(TABLE, "signature_version", server_default=sa.text("2"))


def downgrade() -> None:
    # A v2 artifact cannot become trusted under the weaker v1 interpretation.
    # Revoke it before removing the version discriminator.
    op.execute(
        """
        UPDATE rules_of_engagement
           SET revoked_at = COALESCE(revoked_at, now()),
               revoked_reason = COALESCE(
                   revoked_reason,
                   'RoE revoked during downgrade from signature version 2'
               )
         WHERE signature_version = 2
        """
    )
    op.drop_column(TABLE, "signature_version")
