"""Add an optional campaign-bound knowledge check to training lessons.

Revision ID: 0033_training_knowledge_check
Revises: 0032_source_explicit_curation
Create Date: 2026-08-29
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0033_training_knowledge_check"
down_revision = "0032_source_explicit_curation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # All three columns are nullable and constrained to be all-set or all-NULL
    # so a partial knowledge check (a question with no options, or an answer
    # index pointing nowhere) is impossible. The correct answer is stored only
    # as an index into the options array and is never rendered to recipients.
    op.add_column("training_resources", sa.Column("knowledge_question", sa.Text(), nullable=True))
    op.add_column("training_resources", sa.Column("knowledge_options", sa.JSON(), nullable=True))
    op.add_column("training_resources", sa.Column("knowledge_answer_index", sa.Integer(), nullable=True))
    op.create_check_constraint(
        "knowledge_check_all_or_nothing",
        "training_resources",
        "(knowledge_question IS NULL AND knowledge_options IS NULL AND knowledge_answer_index IS NULL) OR "
        "(knowledge_question IS NOT NULL AND knowledge_options IS NOT NULL AND knowledge_answer_index IS NOT NULL)",
    )
    op.create_check_constraint(
        "knowledge_answer_index_non_negative",
        "training_resources",
        "knowledge_answer_index IS NULL OR knowledge_answer_index >= 0",
    )


def downgrade() -> None:
    op.drop_constraint("knowledge_answer_index_non_negative", "training_resources", type_="check")
    op.drop_constraint("knowledge_check_all_or_nothing", "training_resources", type_="check")
    op.drop_column("training_resources", "knowledge_answer_index")
    op.drop_column("training_resources", "knowledge_options")
    op.drop_column("training_resources", "knowledge_question")
