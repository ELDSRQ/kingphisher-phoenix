"""Add the governed current-threat library (W3-02, Report-04).

A governed current-threat library gives operators useful current threats without
uncontrolled scraping or unsafe originals. It adds three additive tables:

* ``source_policies`` — governance policy for one feed/mailbox source: the
  accountable owner, the license its content is used under, the parser that
  interprets it, a trust tier, a freshness SLA (days), and the enabled switch,
  plus success/failure health counters for the operator System view. A disabled
  or stale policy fails closed for ingestion.
* ``threat_artifacts`` — one governed artifact. The hostile ORIGINAL is isolated
  (only its SHA-256 + byte length are kept, never the raw bytes, like W3-01's
  hashed evidence); the row is always ``QUARANTINED`` and never approvable or
  deliverable. What is reviewed/reused is the SAFE preview (produced by the
  shared sanitizer) carrying the deterministic W3-01 cue manifest. Deduplicated
  by ``content_hash``.
* ``threat_bundle_imports`` — replay-protection ledger for verified signed
  offline curated bundles: one row per accepted ``bundle_id``.

Additive only: three new tables and three new enum types. No existing object is
altered or dropped. SQLAlchemy persists enums by member NAME in this schema (see
migration 0039), so the Postgres enum labels are uppercase.

Revision ID: 0047_threat_library
Revises: 0046_cue_manifest
Create Date: 2026-10-28
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0047_threat_library"
down_revision = "0046_cue_manifest"
branch_labels = None
depends_on = None

_SOURCE_TRUST = postgresql.ENUM(
    "UNTRUSTED",
    "COMMUNITY",
    "PARTNER",
    "CURATED",
    name="source_trust",
    create_type=False,
)
_ARTIFACT_ORIGIN = postgresql.ENUM(
    "FEED",
    "MAILBOX",
    "BUNDLE",
    name="artifact_origin",
    create_type=False,
)
_ARTIFACT_REVIEW_STATE = postgresql.ENUM(
    "PENDING",
    "SAFE_REVIEWED",
    "REJECTED",
    name="artifact_review_state",
    create_type=False,
)
# Reused, not created here: quarantine_state already exists (source_items).
_QUARANTINE_STATE = postgresql.ENUM(
    "ACTIVE",
    "QUARANTINED",
    "REJECTED",
    name="quarantine_state",
    create_type=False,
)


def _grant(table: str) -> None:
    """Least-privilege grant mirroring kp_database.grants; no-op without the role."""
    op.execute(f"REVOKE ALL ON {table} FROM PUBLIC")
    op.execute(
        f"""
        DO $grant$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kp_operator') THEN
                GRANT SELECT, INSERT, UPDATE ON {table} TO kp_operator;
            END IF;
        END
        $grant$;
        """
    )


def upgrade() -> None:
    _SOURCE_TRUST.create(op.get_bind(), checkfirst=True)
    _ARTIFACT_ORIGIN.create(op.get_bind(), checkfirst=True)
    _ARTIFACT_REVIEW_STATE.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "source_policies",
        sa.Column("source_policy_id", sa.UUID(), nullable=False),
        sa.Column("source_key", sa.String(length=64), nullable=False),
        sa.Column("owner", sa.String(length=255), nullable=False),
        sa.Column("license", sa.String(length=255), nullable=False),
        sa.Column("parser", sa.String(length=128), nullable=False),
        sa.Column("trust", _SOURCE_TRUST, nullable=False, server_default="UNTRUSTED"),
        sa.Column("freshness", sa.Integer(), nullable=False, server_default="7"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_failure_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.CheckConstraint("freshness >= 1 AND freshness <= 3650", name="ck_source_policies_freshness_bounds"),
        sa.CheckConstraint("consecutive_failures >= 0", name="ck_source_policies_failures_nonneg"),
        sa.PrimaryKeyConstraint("source_policy_id", name="pk_source_policies"),
        sa.UniqueConstraint("source_key", name="uq_source_policies_source_key"),
    )
    _grant("source_policies")

    op.create_table(
        "threat_artifacts",
        sa.Column("threat_artifact_id", sa.UUID(), nullable=False),
        sa.Column("source_policy_id", sa.UUID(), nullable=True),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("origin", _ARTIFACT_ORIGIN, nullable=False),
        sa.Column("quarantine_state", _QUARANTINE_STATE, nullable=False, server_default="QUARANTINED"),
        sa.Column("original_sha256", sa.String(length=64), nullable=False),
        sa.Column("original_bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("safe_preview_html", sa.Text(), nullable=False),
        sa.Column("safe_preview_text", sa.Text(), nullable=False),
        sa.Column("cue_manifest", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("provenance", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("review_state", _ARTIFACT_REVIEW_STATE, nullable=False, server_default="PENDING"),
        sa.Column("reviewer", sa.String(length=255), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("original_bytes >= 0", name="ck_threat_artifacts_bytes_nonneg"),
        sa.CheckConstraint("quarantine_state = 'QUARANTINED'", name="ck_threat_artifacts_original_quarantined"),
        sa.ForeignKeyConstraint(
            ["source_policy_id"],
            ["source_policies.source_policy_id"],
            name="fk_threat_artifacts_source_policy_id_source_policies",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("threat_artifact_id", name="pk_threat_artifacts"),
        sa.UniqueConstraint("content_hash", name="uq_threat_artifacts_content_hash"),
    )
    op.create_index("ix_threat_artifacts_review", "threat_artifacts", ["review_state", "first_seen_at"])
    op.create_index("ix_threat_artifacts_policy", "threat_artifacts", ["source_policy_id"])
    _grant("threat_artifacts")

    op.create_table(
        "threat_bundle_imports",
        sa.Column("threat_bundle_import_id", sa.UUID(), nullable=False),
        sa.Column("bundle_id", sa.String(length=255), nullable=False),
        sa.Column("checksum", sa.String(length=64), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("imported_by", sa.String(length=255), nullable=False),
        sa.Column("artifact_count", sa.Integer(), nullable=False, server_default="0"),
        sa.PrimaryKeyConstraint("threat_bundle_import_id", name="pk_threat_bundle_imports"),
        sa.UniqueConstraint("bundle_id", name="uq_threat_bundle_imports_bundle_id"),
    )
    _grant("threat_bundle_imports")


def downgrade() -> None:
    op.drop_table("threat_bundle_imports")
    op.drop_index("ix_threat_artifacts_policy", table_name="threat_artifacts")
    op.drop_index("ix_threat_artifacts_review", table_name="threat_artifacts")
    op.drop_table("threat_artifacts")
    op.drop_table("source_policies")
    _ARTIFACT_REVIEW_STATE.drop(op.get_bind(), checkfirst=True)
    _ARTIFACT_ORIGIN.drop(op.get_bind(), checkfirst=True)
    _SOURCE_TRUST.drop(op.get_bind(), checkfirst=True)
