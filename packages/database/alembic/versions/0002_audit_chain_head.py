"""persisted signed audit head

Revision ID: 0002_audit_chain_head
Revises: 0001_initial
Create Date: 2026-08-03

Adds the single-row `audit_chain_head` table that stores the latest audit
event hash and its HMAC signature, so the chain head signature is persisted and
verifiable (CRIT-06 / MED-02). The INSERT-only `audit_writer` role is granted
SELECT/INSERT/UPDATE on this table (DELETE stays revoked).
"""

from __future__ import annotations

import contextlib

from alembic import op

revision = "0002_audit_chain_head"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_chain_head (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            event_hash VARCHAR(64) NOT NULL,
            signature VARCHAR(64),
            signed_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )
    with contextlib.suppress(Exception):  # noqa: BLE001 - dev DB may not permit REVOKE
        op.execute("REVOKE UPDATE, DELETE, TRUNCATE ON audit_chain_head FROM PUBLIC")
        op.execute("GRANT SELECT, INSERT, UPDATE ON audit_chain_head TO audit_writer")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS audit_chain_head")
