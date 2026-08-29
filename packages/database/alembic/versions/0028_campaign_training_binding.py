"""Bind campaigns to an exact reviewed training lesson revision.

Revision ID: 0028_campaign_training_binding
Revises: 0027_recipient_exclusions
Create Date: 2026-08-28
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0028_campaign_training_binding"
down_revision = "0027_recipient_exclusions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Deliberately do not infer values for legacy campaigns. A resource ID
    # alone does not prove which version/content an operator reviewed, so those
    # campaigns remain preserved but fail closed until explicitly rebound.
    op.add_column("campaigns", sa.Column("training_resource_version", sa.Integer(), nullable=True))
    op.add_column("campaigns", sa.Column("training_resource_digest", sa.String(length=64), nullable=True))
    op.create_check_constraint(
        "ck_campaigns_training_resource_version_positive",
        "campaigns",
        "training_resource_version IS NULL OR training_resource_version > 0",
        postgresql_not_valid=True,
    )
    op.create_check_constraint(
        "ck_campaigns_training_resource_digest_hex",
        "campaigns",
        "training_resource_digest IS NULL OR training_resource_digest ~ '^[0-9a-f]{64}$'",
        postgresql_not_valid=True,
    )


def downgrade() -> None:
    op.drop_constraint("ck_campaigns_training_resource_digest_hex", "campaigns", type_="check")
    op.drop_constraint("ck_campaigns_training_resource_version_positive", "campaigns", type_="check")
    op.drop_column("campaigns", "training_resource_digest")
    op.drop_column("campaigns", "training_resource_version")
