"""Add the template_assets store (reusable operator-vetted image assets).

A runtime-managed library of raster images (FLUX-generated banners, brand logos)
that operators upload, review/approve, and apply to DRAFT templates. Applying an
asset inlines its bytes into the template's ``safe_html`` as a ``data:image``
URI — the same raster path the sanitizer and SafetyValidator already permit — so
delivery stays self-contained and nothing new is reachable over the network. The
bytes live in a BYTEA ``content`` column so the library is preserved with the
database. Only an ``APPROVED`` asset may be applied.

Additive only: creates two enum types, one table, its indexes, and the operator
grant. No existing object is altered or dropped.

Revision ID: 0045_template_assets
Revises: 0044_message_replied
Create Date: 2026-10-16
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0045_template_assets"
down_revision = "0044_message_replied"
branch_labels = None
depends_on = None

# SQLAlchemy's default Enum persists Python enum MEMBER NAMES (uppercase), the
# convention every other enum in this schema follows (see 0039). The Postgres
# type labels must therefore be uppercase, or inserts fail on real Postgres.
_ASSET_KIND = postgresql.ENUM(
    "BANNER",
    "LOGO",
    "DECORATIVE",
    name="asset_kind",
    create_type=False,
)
_ASSET_APPROVAL_STATE = postgresql.ENUM(
    "DRAFT",
    "APPROVED",
    "REJECTED",
    "SUPERSEDED",
    name="asset_approval_state",
    create_type=False,
)


def upgrade() -> None:
    _ASSET_KIND.create(op.get_bind(), checkfirst=True)
    _ASSET_APPROVAL_STATE.create(op.get_bind(), checkfirst=True)
    op.create_table(
        "template_assets",
        sa.Column("asset_id", sa.UUID(), nullable=False),
        sa.Column("kind", _ASSET_KIND, nullable=False),
        sa.Column("brand", sa.String(length=64), nullable=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("media_type", sa.String(length=32), nullable=False),
        sa.Column("width", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("height", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("byte_size", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("content", sa.LargeBinary(), nullable=False),
        sa.Column("provenance", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("approval_state", _ASSET_APPROVAL_STATE, nullable=False, server_default="DRAFT"),
        sa.Column("approval_hash", sa.String(length=64), nullable=True),
        sa.Column("requested_by", sa.UUID(), nullable=True),
        sa.Column("approved_by", sa.UUID(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint("byte_size >= 0", name="ck_template_assets_byte_size_nonneg"),
        sa.PrimaryKeyConstraint("asset_id"),
    )
    op.create_index("ix_template_assets_kind_state", "template_assets", ["kind", "approval_state"])
    op.create_index("ix_template_assets_brand", "template_assets", ["brand"])
    op.create_index("ix_template_assets_sha256", "template_assets", ["sha256"])
    # Least-privilege: only the operator workload manages the asset library.
    # Mirrors the shared grant matrix in kp_database.grants; a missing role is a
    # no-op so non-managed/dev setups are unaffected.
    op.execute("REVOKE ALL ON template_assets FROM PUBLIC")
    op.execute(
        """
        DO $grant$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kp_operator') THEN
                GRANT SELECT, INSERT, UPDATE ON template_assets TO kp_operator;
            END IF;
        END
        $grant$;
        """
    )


def downgrade() -> None:
    op.drop_index("ix_template_assets_sha256", table_name="template_assets")
    op.drop_index("ix_template_assets_brand", table_name="template_assets")
    op.drop_index("ix_template_assets_kind_state", table_name="template_assets")
    op.drop_table("template_assets")
    _ASSET_APPROVAL_STATE.drop(op.get_bind(), checkfirst=True)
    _ASSET_KIND.drop(op.get_bind(), checkfirst=True)
