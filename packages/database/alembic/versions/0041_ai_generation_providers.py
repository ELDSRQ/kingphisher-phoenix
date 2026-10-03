"""Operator bring-your-own generation model providers + encrypted API keys.

Lets the operator save API keys for hosted model providers (OpenAI, Gemini,
Anthropic/Claude, OpenRouter, OpenCode) and choose which provider+model
generates phishing-simulation content, or keep the local model. One row per
provider; the ``api_key`` is stored encrypted at rest via the application
``CipherText`` type (so this column holds the ``kpct.1.<key-id>.<payload>``
envelope, never plaintext). At most one row is ``is_active`` at a time; no active
row means the local model is used (the default).

Revision ID: 0041_ai_generation_providers
Revises: 0040_campaign_send_time_spread
Create Date: 2026-10-03
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0041_ai_generation_providers"
down_revision = "0040_campaign_send_time_spread"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ai_generation_providers",
        sa.Column("provider", sa.String(length=32), primary_key=True),
        # Encrypted at rest (CipherText envelope); nullable because 'local' needs none.
        sa.Column("api_key", sa.Text(), nullable=True),
        sa.Column("model_id", sa.String(length=128), nullable=True),
        sa.Column("base_url", sa.String(length=512), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    # At most one active provider at a time (enforced here so a concurrent
    # selection cannot leave two providers active).
    op.create_index(
        "uq_ai_generation_providers_single_active",
        "ai_generation_providers",
        ["is_active"],
        unique=True,
        postgresql_where=sa.text("is_active"),
    )


def downgrade() -> None:
    op.drop_index("uq_ai_generation_providers_single_active", table_name="ai_generation_providers")
    op.drop_table("ai_generation_providers")
