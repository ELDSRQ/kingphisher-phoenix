"""Add evidence-bearing privacy request workflow fields.

Revision ID: 0006_privacy_workflow
Revises: 0005_ccpa_retention
Create Date: 2026-08-16
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0006_privacy_workflow"
down_revision = "0005_ccpa_retention"
branch_labels = None
depends_on = None


def upgrade() -> None:
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("privacy_requests")}
    if "verified_at" not in columns:
        op.add_column("privacy_requests", sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True))
    if "verification_method" not in columns:
        op.add_column("privacy_requests", sa.Column("verification_method", sa.String(length=64), nullable=True))
    if "verification_evidence_ref" not in columns:
        op.add_column("privacy_requests", sa.Column("verification_evidence_ref", sa.String(length=255), nullable=True))
    if "exported_at" not in columns:
        op.add_column("privacy_requests", sa.Column("exported_at", sa.DateTime(timezone=True), nullable=True))

    # Legacy "in_progress" requests were not backed by verification evidence;
    # fail closed and require operators to verify them again.
    op.execute("UPDATE privacy_requests SET status = 'opened' WHERE status = 'open'")
    op.execute("UPDATE privacy_requests SET status = 'opened' WHERE status = 'in_progress' AND verified_at IS NULL")


def downgrade() -> None:
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("privacy_requests")}
    for column in ("exported_at", "verification_evidence_ref", "verification_method", "verified_at"):
        if column in columns:
            op.drop_column("privacy_requests", column)
