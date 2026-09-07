"""Align training_resources.knowledge_options with the ORM: json -> jsonb.

Migration 0033 created the column as ``sa.JSON()`` (PostgreSQL ``json``) while
``kp_database.models`` declares it as ``JSONB``. The autogenerate drift gate
caught the mismatch the first time it ran against a real database; see
``docs/design/SCHEMA-DRIFT-2026-09-07.md``.

``json`` and ``jsonb`` are different types, not aliases: ``jsonb`` supports GIN
indexing and the containment operators, and — the sharp edge — PostgreSQL has no
equality operator for ``json``, so any ``WHERE knowledge_options = …`` /
``DISTINCT`` / ``GROUP BY`` over the column fails at runtime rather than at
deploy time. The cast is data-preserving in both directions.

Revision ID: 0037_knowledge_options_jsonb
Revises: 0036_launch_gate_submitted_by
Create Date: 2026-09-07
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0037_knowledge_options_jsonb"
down_revision = "0036_launch_gate_submitted_by"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "training_resources",
        "knowledge_options",
        existing_type=sa.JSON(),
        type_=postgresql.JSONB(astext_type=sa.Text()),
        existing_nullable=True,
        postgresql_using="knowledge_options::jsonb",
    )


def downgrade() -> None:
    op.alter_column(
        "training_resources",
        "knowledge_options",
        existing_type=postgresql.JSONB(astext_type=sa.Text()),
        type_=sa.JSON(),
        existing_nullable=True,
        postgresql_using="knowledge_options::json",
    )
