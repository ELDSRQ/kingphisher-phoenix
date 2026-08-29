"""Repair the legacy recipient mailbox index for soft deletion.

Revision ID: 0014_recipient_soft_delete_index
Revises: 0013_verified_domains_roe
Create Date: 2026-08-27

Revision 0001 created ``ix_recipients_mailbox_sha256`` as a unique index.
Revision 0005 added the intended partial uniqueness constraint for active
rows, but only looked for a unique *constraint* and therefore left this
unique index in place. That made re-import after soft deletion impossible.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.engine.interfaces import ReflectedIndex

revision = "0014_recipient_soft_delete_index"
down_revision = "0013_verified_domains_roe"
branch_labels = None
depends_on = None

TABLE = "recipients"
INDEX = "ix_recipients_mailbox_sha256"


def _index() -> ReflectedIndex | None:
    return next((item for item in sa.inspect(op.get_bind()).get_indexes(TABLE) if item["name"] == INDEX), None)


def upgrade() -> None:
    existing = _index()
    if existing is not None and existing.get("unique"):
        op.drop_index(INDEX, table_name=TABLE)
        existing = None
    if existing is None:
        op.create_index(INDEX, TABLE, ["mailbox_sha256"], unique=False)


def downgrade() -> None:
    existing = _index()
    if existing is not None:
        op.drop_index(INDEX, table_name=TABLE)
    op.create_index(INDEX, TABLE, ["mailbox_sha256"], unique=True)
