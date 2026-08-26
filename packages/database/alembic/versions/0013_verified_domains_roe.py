"""Verified target domains and signed Rules-of-Engagement.

Revision ID: 0013_verified_domains_roe
Revises: 0012_campaign_sender_display
Create Date: 2026-08-26

The authorization boundary for delivery: recipients may only sit in domains
the operator proved control of via the DNS TXT challenge (verified_domains),
and a campaign may only be scheduled/delivered under an active operator-signed
Rules-of-Engagement that names those verified domains and an engagement
window. Sending fails closed without a valid RoE.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0013_verified_domains_roe"
down_revision = "0012_campaign_sender_display"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "verified_domains",
        sa.Column("verified_domain_id", UUID(as_uuid=True), primary_key=True),
        sa.Column("domain", sa.String(length=253), nullable=False),
        sa.Column("challenge_token", sa.String(length=64), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verified_by", UUID(as_uuid=True), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("domain", name="uq_verified_domains_domain"),
    )
    op.create_table(
        "rules_of_engagement",
        sa.Column("roe_id", UUID(as_uuid=True), primary_key=True),
        sa.Column("signer", sa.String(length=255), nullable=False),
        sa.Column("authorizing_party", sa.String(length=255), nullable=False),
        sa.Column("terms_text", sa.Text(), nullable=False),
        sa.Column("terms_hash", sa.String(length=64), nullable=False),
        sa.Column("signature", sa.String(length=64), nullable=False),
        sa.Column("signed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("target_domains", JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("created_by", UUID(as_uuid=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", UUID(as_uuid=True), nullable=True),
        sa.Column("revoked_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.add_column(
        "campaigns",
        sa.Column("roe_id", UUID(as_uuid=True), sa.ForeignKey("rules_of_engagement.roe_id"), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("campaigns", "roe_id")
    op.drop_table("rules_of_engagement")
    op.drop_table("verified_domains")
