"""ccpa retention, deletion, and dsr schema

Revision ID: 0005_ccpa_retention
Revises: 0004_recipient_hash_salt
Create Date: 2026-08-03

WS-6 / CRIT-07, CRIT-08: add the retention policy table and wire real FKs,
soft-delete on recipients (with a partial unique index so a deleted mailbox can
be re-imported), a 45-day SLA deadline on privacy requests, a privacy notice
table, and ON DELETE CASCADE on the child rows that currently block deletion.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0005_ccpa_retention"
down_revision = "0004_recipient_hash_salt"
branch_labels = None
depends_on = None

# (table, child_column, referent_table, referent_column)
_CASCADE_FKS: list[tuple[str, str, str, str]] = [
    ("campaign_approvals", "campaign_id", "campaigns", "campaign_id"),
    ("recipient_assignments", "campaign_id", "campaigns", "campaign_id"),
    ("recipient_assignments", "recipient_id", "recipients", "recipient_id"),
    ("tracking_tokens", "campaign_id", "campaigns", "campaign_id"),
    ("recipient_exclusions", "recipient_id", "recipients", "recipient_id"),
    ("source_terms", "source_id", "sources", "source_id"),
    ("source_items", "source_id", "sources", "source_id"),
    ("training_assignments", "resource_id", "training_resources", "training_resource_id"),
]


def _has_table(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def _has_column(table: str, column: str) -> bool:
    return column in {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def _has_constraint(table: str, name: str) -> bool:
    return any(c["name"] == name for c in sa.inspect(op.get_bind()).get_unique_constraints(table))


def _has_fk_to(table: str, ref_table: str, column: str) -> bool:
    return any(
        fk["referred_table"] == ref_table and column in fk["constrained_columns"]
        for fk in sa.inspect(op.get_bind()).get_foreign_keys(table)
    )


def _has_index(table: str, name: str) -> bool:
    return any(i["name"] == name for i in sa.inspect(op.get_bind()).get_indexes(table))


def _recreate_fk_cascade(table: str, ref_table: str, column: str, ref_column: str) -> None:
    """Rewire a child FK to ON DELETE CASCADE, matching it by columns/referent
    rather than by name (create_all-generated names vary across versions)."""
    for fk in sa.inspect(op.get_bind()).get_foreign_keys(table):
        if fk["referred_table"] != ref_table or column not in fk["constrained_columns"]:
            continue
        if fk.get("options", {}).get("ondelete") == "CASCADE":
            return
        if fk["name"] is None:
            return
        op.drop_constraint(fk["name"], table, type_="foreignkey")
        op.create_foreign_key(fk["name"], table, ref_table, [column], [ref_column], ondelete="CASCADE")
        return


def upgrade() -> None:
    if not _has_table("retention_policies"):
        op.create_table(
            "retention_policies",
            sa.Column("retention_policy_id", sa.Uuid(), nullable=False),
            sa.Column("name", sa.String(length=128), nullable=False),
            sa.Column("data_category", sa.String(length=64), nullable=False),
            sa.Column("retention_days", sa.Integer(), nullable=False),
            sa.Column("is_default", sa.Boolean(), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.PrimaryKeyConstraint("retention_policy_id"),
        )
    if not _has_table("privacy_notices"):
        op.create_table(
            "privacy_notices",
            sa.Column("notice_id", sa.Uuid(), nullable=False),
            sa.Column("version", sa.Integer(), nullable=False),
            sa.Column("notice_text", sa.Text(), nullable=False),
            sa.Column("effective_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("is_current", sa.Boolean(), nullable=False),
            sa.PrimaryKeyConstraint("notice_id"),
        )

    if not _has_fk_to("campaigns", "retention_policies", "retention_policy_id"):
        op.create_foreign_key(
            "campaigns_retention_policy_id_fkey",
            "campaigns",
            "retention_policies",
            ["retention_policy_id"],
            ["retention_policy_id"],
        )
    if not _has_fk_to("retention_actions", "retention_policies", "retention_policy_id"):
        op.create_foreign_key(
            "retention_actions_retention_policy_id_fkey",
            "retention_actions",
            "retention_policies",
            ["retention_policy_id"],
            ["retention_policy_id"],
        )

    if not _has_column("recipients", "deleted_at"):
        op.add_column("recipients", sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True))
    if _has_constraint("recipients", "recipients_mailbox_sha256_key"):
        op.drop_constraint("recipients_mailbox_sha256_key", "recipients", type_="unique")
    if not _has_index("recipients", "uq_recipients_mailbox_sha256_active"):
        op.create_index(
            "uq_recipients_mailbox_sha256_active",
            "recipients",
            ["mailbox_sha256"],
            unique=True,
            postgresql_where=sa.text("deleted_at IS NULL"),
        )

    if not _has_column("privacy_requests", "sla_deadline"):
        op.add_column("privacy_requests", sa.Column("sla_deadline", sa.DateTime(timezone=True), nullable=True))
        op.execute(
            "UPDATE privacy_requests SET sla_deadline = opened_at + INTERVAL '45 days' WHERE sla_deadline IS NULL"
        )
        op.alter_column("privacy_requests", "sla_deadline", nullable=False)

    for table, column, ref_table, ref_column in _CASCADE_FKS:
        _recreate_fk_cascade(table, ref_table, column, ref_column)


def downgrade() -> None:
    for table, column, ref_table, ref_column in reversed(_CASCADE_FKS):
        for fk in sa.inspect(op.get_bind()).get_foreign_keys(table):
            if fk["referred_table"] != ref_table or column not in fk["constrained_columns"]:
                continue
            if fk.get("options", {}).get("ondelete") == "CASCADE" and fk["name"] is not None:
                op.drop_constraint(fk["name"], table, type_="foreignkey")
                op.create_foreign_key(fk["name"], table, ref_table, [column], [ref_column])

    if _has_fk_to("retention_actions", "retention_policies", "retention_policy_id"):
        for fk in sa.inspect(op.get_bind()).get_foreign_keys("retention_actions"):
            if fk["referred_table"] == "retention_policies" and fk["name"] is not None:
                op.drop_constraint(fk["name"], "retention_actions", type_="foreignkey")
    if _has_fk_to("campaigns", "retention_policies", "retention_policy_id"):
        for fk in sa.inspect(op.get_bind()).get_foreign_keys("campaigns"):
            if fk["referred_table"] == "retention_policies" and fk["name"] is not None:
                op.drop_constraint(fk["name"], "campaigns", type_="foreignkey")
    if _has_index("recipients", "uq_recipients_mailbox_sha256_active"):
        op.drop_index("uq_recipients_mailbox_sha256_active", table_name="recipients")
    if not _has_constraint("recipients", "recipients_mailbox_sha256_key"):
        op.create_unique_constraint("recipients_mailbox_sha256_key", "recipients", ["mailbox_sha256"])
    if _has_column("recipients", "deleted_at"):
        op.drop_column("recipients", "deleted_at")
    if _has_column("privacy_requests", "sla_deadline"):
        op.drop_column("privacy_requests", "sla_deadline")
    if _has_table("privacy_notices"):
        op.drop_table("privacy_notices")
    if _has_table("retention_policies"):
        op.drop_table("retention_policies")
