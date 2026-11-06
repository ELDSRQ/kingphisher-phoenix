"""Explicit tenant-wide preservation holds (W5-04 / KP-AUD-025).

Revision ID: 0053_retention_holds
Revises: 0052_adaptive_programs
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0053_retention_holds"
down_revision = "0052_adaptive_programs"
branch_labels = None
depends_on = None

PURGE_TABLES = (
    "recipients",
    "recipient_assignments",
    "tracking_tokens",
    "events",
    "training_assignments",
    "recipient_exclusions",
    "audience_group_members",
    "reported_mail_receipts",
    "reply_mail_receipts",
    "awareness_ledger_entries",
    "microsoft365_integration_states",
)


def upgrade() -> None:
    op.create_table(
        "retention_holds",
        sa.Column("retention_hold_id", sa.UUID(), primary_key=True),
        sa.Column("scope", sa.String(64), nullable=False),
        sa.Column("reference", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("released_by", sa.String(255), nullable=True),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("release_reason", sa.Text(), nullable=True),
        sa.CheckConstraint("scope = 'single_tenant_database'", name=op.f("ck_retention_holds_tenant_scope")),
        sa.CheckConstraint(
            "(released_at IS NULL AND released_by IS NULL AND release_reason IS NULL) OR "
            "(released_at IS NOT NULL AND released_by IS NOT NULL AND release_reason IS NOT NULL "
            "AND released_at >= created_at)",
            name=op.f("ck_retention_holds_release_complete"),
        ),
    )
    op.create_index(
        "ix_retention_holds_active", "retention_holds", ["created_at"], postgresql_where=sa.text("released_at IS NULL")
    )
    # Guard legacy processes and direct DML as well as the current helpers.
    # Definer rights expose only a boolean hold decision to runtime roles;
    # reasons remain encrypted, the search path is fixed, and the table is
    # schema-qualified. Function/trigger ownership stays with the migrator.
    op.execute("""CREATE FUNCTION public.kp_guard_retention_hold() RETURNS trigger
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
        BEGIN
            IF current_setting('transaction_isolation') <> 'read committed' THEN
                RAISE EXCEPTION 'preservation checks require READ COMMITTED' USING ERRCODE = '55000';
            END IF;
            PERFORM pg_advisory_xact_lock_shared(1263551025);
            IF EXISTS (SELECT 1 FROM public.retention_holds WHERE released_at IS NULL) THEN
                RAISE EXCEPTION 'active retention hold prevents irreversible deletion' USING ERRCODE = '55000';
            END IF;
            IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
            IF TG_OP = 'UPDATE' THEN RETURN NEW; END IF;
            RETURN NULL;
        END $$""")
    op.execute("REVOKE ALL ON FUNCTION public.kp_guard_retention_hold() FROM PUBLIC")
    for table in PURGE_TABLES:
        # Both names are migration constants; no runtime identifiers are interpolated.
        op.execute(
            f"CREATE TRIGGER kp_preserve_delete BEFORE DELETE ON public.{table} "
            "FOR EACH ROW EXECUTE FUNCTION public.kp_guard_retention_hold()"
        )
        op.execute(
            f"CREATE TRIGGER kp_preserve_truncate BEFORE TRUNCATE ON public.{table} "
            "FOR EACH STATEMENT EXECUTE FUNCTION public.kp_guard_retention_hold()"
        )
    op.execute("""CREATE TRIGGER kp_preserve_erasure BEFORE UPDATE ON public.recipients
        FOR EACH ROW WHEN (NEW.deleted_at IS NOT NULL AND OLD.deleted_at IS DISTINCT FROM NEW.deleted_at)
        EXECUTE FUNCTION public.kp_guard_retention_hold()""")
    op.execute("""CREATE TRIGGER kp_preserve_directory_preview BEFORE UPDATE ON public.microsoft365_integration_states
        FOR EACH ROW WHEN (OLD.pending_payload IS NOT NULL AND NEW.pending_payload IS NULL)
        EXECUTE FUNCTION public.kp_guard_retention_hold()""")
    # The migration role can be the only existing role during a fresh install.
    # The authoritative grants matrix also applies these after roles are made.
    op.execute("""DO $$ BEGIN
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kp_operator') THEN
            GRANT SELECT, INSERT, UPDATE ON retention_holds TO kp_operator;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kp_worker_retention') THEN
            GRANT SELECT ON retention_holds TO kp_worker_retention;
        END IF;
    END $$""")


def downgrade() -> None:
    # Releasing holds retains history; do not let a schema rollback erase it.
    raise RuntimeError("retention-hold history is preservation-required; downgrade is not supported")
