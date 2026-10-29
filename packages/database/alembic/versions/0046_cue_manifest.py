"""Add the deterministic cue + transformation manifest column (W3-01).

Reconstruction (cloning a real phish into a safe DRAFT, and classifying a threat
report into a campaign pattern) now produces a structured, reviewable, and
deterministic cue manifest: the recognisable social-engineering cues the lure
uses (each with bounded, hashed evidence spans — offsets + SHA-256, never raw
malicious text) plus a receipt for every component the reconstruction removed or
replaced and the policy reason for it. The manifest is versioned by its
ontology and kept isolated from the deliverable content.

Both ``template_versions`` and ``campaign_patterns`` already carry a free-text
``warning_cues`` JSONB list; this adds a sibling ``cue_manifest`` JSONB object
column holding the structured manifest, so the coarse labels and the structured
evidence stay distinct.

Additive only: two nullable-by-default JSONB columns with a ``'{}'::jsonb``
server default, so existing rows backfill to an empty manifest. No existing
object is altered or dropped.

Revision ID: 0046_cue_manifest
Revises: 0045_template_assets
Create Date: 2026-10-28
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0046_cue_manifest"
down_revision = "0045_template_assets"
branch_labels = None
depends_on = None

_TABLES = ("template_versions", "campaign_patterns")


def upgrade() -> None:
    for table in _TABLES:
        op.add_column(
            table,
            sa.Column(
                "cue_manifest",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=sa.text("'{}'::jsonb"),
            ),
        )


def downgrade() -> None:
    for table in _TABLES:
        op.drop_column(table, "cue_manifest")
