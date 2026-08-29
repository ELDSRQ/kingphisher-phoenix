"""Publish a safe default privacy notice for every installation.

Revision ID: 0030_default_privacy_notice
Revises: 0029_campaign_canary_gate
Create Date: 2026-08-29
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0030_default_privacy_notice"
down_revision = "0029_campaign_canary_gate"
branch_labels = None
depends_on = None

_DEFAULT_NOTICE_ID = "00000000-0000-4000-8000-000000000030"
_DEFAULT_NOTICE = (
    "Security-awareness simulations collect limited personal data (work mailbox, department, "
    "and interaction events) to deliver and measure training exercises. Data is retained no "
    "longer than 365 days and can be exported, corrected, or deleted on verified request within "
    "45 days; contact your organization's security-awareness administrator to exercise a "
    "data-subject right."
)


def upgrade() -> None:
    # Older development seeds could create more than one current row. Preserve
    # every notice, select one deterministic current version, and then enforce
    # the invariant for all future writes.
    op.execute(
        """
        WITH ranked AS (
            SELECT notice_id,
                   row_number() OVER (
                       ORDER BY version DESC, effective_at DESC, notice_id DESC
                   ) AS position
            FROM privacy_notices
            WHERE is_current IS TRUE
        )
        UPDATE privacy_notices AS notice
        SET is_current = FALSE
        FROM ranked
        WHERE notice.notice_id = ranked.notice_id
          AND ranked.position > 1
        """
    )
    op.create_index(
        "uq_privacy_notices_single_current",
        "privacy_notices",
        ["is_current"],
        unique=True,
        postgresql_where=sa.text("is_current IS TRUE"),
    )
    op.execute(
        sa.text(
            """
            INSERT INTO privacy_notices (
                notice_id, version, notice_text, effective_at, is_current
            )
            SELECT CAST(:notice_id AS UUID), 1, :notice_text, CURRENT_TIMESTAMP, TRUE
            WHERE NOT EXISTS (
                SELECT 1 FROM privacy_notices WHERE is_current IS TRUE
            )
            """
        ).bindparams(notice_id=_DEFAULT_NOTICE_ID, notice_text=_DEFAULT_NOTICE)
    )


def downgrade() -> None:
    # Notice rows are compliance records and remain intact across a rollback.
    op.drop_index("uq_privacy_notices_single_current", table_name="privacy_notices")
