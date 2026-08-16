"""Add feed-specific source fetch paths.

Revision ID: 0008_source_fetch_path
Revises: 0007_alert_delivery
Create Date: 2026-08-16
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0008_source_fetch_path"
down_revision = "0007_alert_delivery"
branch_labels = None
depends_on = None


def upgrade() -> None:
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("sources")}
    if "fetch_path" not in columns:
        op.add_column("sources", sa.Column("fetch_path", sa.String(length=1024), nullable=False, server_default="/"))


def downgrade() -> None:
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("sources")}
    if "fetch_path" in columns:
        op.drop_column("sources", "fetch_path")
