"""Record why a recipient assignment failed to send.

Revision ID: 0011_assignment_failure_reason
Revises: 0010_audit_ownership_separation
Create Date: 2026-08-26

T-06 introduces failures that are policy decisions rather than transport
errors — a recipient outside the configured domain allowlist, or a QUEUED
assignment reconciled after its campaign closed. Collapsing those into a bare
FAILED state leaves an operator with no way to tell "the mail server rejected
this" from "policy refused to send this", which is exactly the distinction an
L1 administrator needs to act on.

Nullable and free of a backfill: pre-existing FAILED rows keep a NULL reason,
which reads correctly as "reason not recorded".
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0011_assignment_failure_reason"
down_revision = "0010_audit_ownership_separation"
branch_labels = None
depends_on = None

TABLE = "recipient_assignments"
COLUMN = "failure_reason"


def upgrade() -> None:
    op.add_column(TABLE, sa.Column(COLUMN, sa.String(length=64), nullable=True))


def downgrade() -> None:
    op.drop_column(TABLE, COLUMN)
