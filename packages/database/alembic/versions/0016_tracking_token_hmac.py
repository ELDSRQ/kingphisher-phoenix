"""Revoke replayable legacy tracking credentials.

Revision ID: 0016_tracking_token_hmac
Revises: 0015_delivery_attempt_state
Create Date: 2026-08-27

Before this revision, the value stored in ``token_hash`` was also placed in
the public tracking URL and was therefore a bearer credential. New issuance
stores a keyed HMAC verifier (pepper_version 2). Existing active credentials
cannot be transformed without their discarded raw token, so the safe and
simple migration is to revoke them.
"""

from __future__ import annotations

from alembic import op

revision = "0016_tracking_token_hmac"
down_revision = "0015_delivery_attempt_state"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        UPDATE tracking_tokens
           SET status = 'REVOKED',
               revoked_at = now(),
               revoked_reason = 'legacy replayable tracking credential revoked by migration 0016'
         WHERE status = 'ACTIVE'
        """
    )


def downgrade() -> None:
    # Intentionally irreversible: automatically reactivating legacy bearer
    # credentials would reintroduce the database-replay vulnerability.
    pass
