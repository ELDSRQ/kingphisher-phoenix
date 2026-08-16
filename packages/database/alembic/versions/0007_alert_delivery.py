"""Add signed outbound alert subscription fields.

Revision ID: 0007_alert_delivery
Revises: 0006_privacy_workflow
Create Date: 2026-08-16
"""

from __future__ import annotations

from typing import Any

import sqlalchemy as sa
from alembic import op

revision = "0007_alert_delivery"
down_revision = "0006_privacy_workflow"
branch_labels = None
depends_on = None


def upgrade() -> None:
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("alert_subscriptions")}
    additions: tuple[tuple[str, sa.Column[Any]], ...] = (
        ("destination_url", sa.Column("destination_url", sa.Text(), nullable=True)),
        ("signing_secret", sa.Column("signing_secret", sa.Text(), nullable=True)),
        ("last_delivery_at", sa.Column("last_delivery_at", sa.DateTime(timezone=True), nullable=True)),
        (
            "consecutive_failures",
            sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
        ),
    )
    for name, column in additions:
        if name not in columns:
            op.add_column("alert_subscriptions", column)


def downgrade() -> None:
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("alert_subscriptions")}
    for name in ("consecutive_failures", "last_delivery_at", "signing_secret", "destination_url"):
        if name in columns:
            op.drop_column("alert_subscriptions", name)
