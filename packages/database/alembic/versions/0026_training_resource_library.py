"""Add governed training resources and immutable campaign bindings.

Revision ID: 0026_training_resource_library
Revises: 0025_campaign_programs
Create Date: 2026-08-27
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0026_training_resource_library"
down_revision = "0025_campaign_programs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("training_resources", sa.Column("created_by", sa.UUID(), nullable=True))
    op.add_column(
        "training_resources",
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.add_column("training_resources", sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("training_resources", sa.Column("reviewed_by", sa.UUID(), nullable=True))
    op.add_column("training_resources", sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("training_resources", sa.Column("review_rationale", sa.Text(), nullable=True))
    # These bounds did not exist when legacy resources were accepted. NOT
    # VALID preserves those rows without truncation while PostgreSQL still
    # enforces every constraint for new inserts and updates.
    op.create_check_constraint(
        "ck_training_resources_title_bounded",
        "training_resources",
        "char_length(btrim(title)) BETWEEN 1 AND 160",
        postgresql_not_valid=True,
    )
    op.create_check_constraint(
        "ck_training_resources_content_bounded",
        "training_resources",
        "char_length(btrim(content)) BETWEEN 1 AND 20000",
        postgresql_not_valid=True,
    )
    op.create_check_constraint(
        "ck_training_resources_source_ref_bounded",
        "training_resources",
        "source_ref IS NULL OR char_length(source_ref) <= 500",
        postgresql_not_valid=True,
    )
    op.create_check_constraint(
        "ck_training_resources_version_positive",
        "training_resources",
        "version > 0",
        postgresql_not_valid=True,
    )

    op.add_column("campaigns", sa.Column("training_resource_id", sa.UUID(), nullable=True))
    op.create_foreign_key(
        "fk_campaigns_training_resource_id_training_resources",
        "campaigns",
        "training_resources",
        ["training_resource_id"],
        ["training_resource_id"],
        ondelete="RESTRICT",
    )
    # Bind legacy campaigns to their earliest persisted assignment without
    # rewriting or deleting any recipient history.
    op.execute(
        """
        UPDATE campaigns AS campaign
           SET training_resource_id = binding.resource_id
          FROM (
              SELECT DISTINCT ON (campaign_id) campaign_id, resource_id
                FROM training_assignments
               WHERE campaign_id IS NOT NULL
               ORDER BY campaign_id, assigned_at, training_assignment_id
          ) AS binding
         WHERE campaign.campaign_id = binding.campaign_id
        """
    )


def downgrade() -> None:
    op.drop_constraint("fk_campaigns_training_resource_id_training_resources", "campaigns", type_="foreignkey")
    op.drop_column("campaigns", "training_resource_id")
    op.drop_constraint("ck_training_resources_version_positive", "training_resources", type_="check")
    op.drop_constraint("ck_training_resources_source_ref_bounded", "training_resources", type_="check")
    op.drop_constraint("ck_training_resources_content_bounded", "training_resources", type_="check")
    op.drop_constraint("ck_training_resources_title_bounded", "training_resources", type_="check")
    op.drop_column("training_resources", "review_rationale")
    op.drop_column("training_resources", "reviewed_at")
    op.drop_column("training_resources", "reviewed_by")
    op.drop_column("training_resources", "submitted_at")
    op.drop_column("training_resources", "created_at")
    op.drop_column("training_resources", "created_by")
