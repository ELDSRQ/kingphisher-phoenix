"""Partial unique index enforcing first-event-wins open/click dedup.

Revision ID: 0009_event_open_click_dedup
Revises: 0008_source_fetch_path
Create Date: 2026-08-26

metric-integrity: open/click dedup was SELECT-then-INSERT, so concurrent
double-clicks or prefetches could create duplicate OPENED/CLICKED rows and
inflate campaign metrics. Adds a partial unique index on
events(token_id, event_type) restricted to OPENED/CLICKED so the first event
wins at the storage layer (other event types are unaffected; rows with a
NULL token_id are ignored by unique indexes). Pre-existing duplicates are
removed first, keeping the lowest event_id per (token_id, event_type).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0009_event_open_click_dedup"
down_revision = "0008_source_fetch_path"
branch_labels = None
depends_on = None

INDEX_NAME = "uq_events_open_click_dedup"
# SQLAlchemy Enum stores member names, and migration 0001 derives the enum
# type from the models, so the labels are uppercase.
WHERE_CLAUSE = "event_type IN ('OPENED', 'CLICKED')"


def _index_exists() -> bool:
    indexes = sa.inspect(op.get_bind()).get_indexes("events")
    return any(index.get("name") == INDEX_NAME for index in indexes)


def upgrade() -> None:
    # Keep the lowest event_id per (token_id, event_type) for open/click rows
    # so the unique index can be created over pre-existing data. uuid has no
    # min() aggregate in Postgres, so the earliest row per group is found with
    # a window function instead (uuid ordering is defined).
    op.execute(
        """
        WITH ranked AS (
            SELECT event_id,
                   ROW_NUMBER() OVER (
                       PARTITION BY token_id, event_type
                       ORDER BY event_id
                   ) AS rn
            FROM events
            WHERE event_type IN ('OPENED', 'CLICKED')
              AND token_id IS NOT NULL
        )
        DELETE FROM events AS dup
        USING ranked
        WHERE dup.event_id = ranked.event_id
          AND ranked.rn > 1
        """
    )
    if not _index_exists():
        op.create_index(
            INDEX_NAME,
            "events",
            ["token_id", "event_type"],
            unique=True,
            postgresql_where=sa.text(WHERE_CLAUSE),
        )


def downgrade() -> None:
    if _index_exists():
        op.drop_index(INDEX_NAME, table_name="events")
