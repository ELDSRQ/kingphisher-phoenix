"""Require explicit curation for preexisting active threat evidence.

Revision ID: 0032_source_explicit_curation
Revises: 0031_awareness_ledger
Create Date: 2026-08-29
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0032_source_explicit_curation"
down_revision = "0031_awareness_ledger"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Older adapters marked every fetched row ACTIVE and immediately built a
    # pattern. Preserve all evidence, but require one audited activation before
    # it can be used again. The marker is stable, bounded, and contains no PII.
    op.execute(
        """
        UPDATE source_items
        SET quarantine_state = 'QUARANTINED',
            quarantine_reason = 'upgrade_review_required_v1'
        WHERE quarantine_state = 'ACTIVE'
        """
    )
    # Existing invalid policy rows make the upgrade fail closed instead of
    # silently selecting an unsafe retention duration or an arbitrary default.
    # The MetaData naming convention expands this to
    # ck_retention_policies_days_bounded in the database.
    op.create_check_constraint(
        "days_bounded",
        "retention_policies",
        "retention_days BETWEEN 1 AND 365",
    )
    op.create_index(
        "uq_retention_policies_single_default",
        "retention_policies",
        ["is_default"],
        unique=True,
        postgresql_where=sa.text("is_default IS TRUE"),
    )


def downgrade() -> None:
    op.drop_index("uq_retention_policies_single_default", table_name="retention_policies")
    # The naming convention expands this to the same name upgrade() created.
    op.drop_constraint(
        "days_bounded",
        "retention_policies",
        type_="check",
    )
    # Restore only untouched rows carrying this migration's exact marker.
    # Rows curated, rejected, or merged after upgrade remain unchanged.
    op.execute(
        """
        UPDATE source_items
        SET quarantine_state = 'ACTIVE',
            quarantine_reason = NULL
        WHERE quarantine_state = 'QUARANTINED'
          AND quarantine_reason = 'upgrade_review_required_v1'
          AND duplicate_of IS NULL
        """
    )
