"""DB-enforced audit ownership separation

Revision ID: 0010_audit_ownership_separation
Revises: 0009_event_open_click_dedup
Create Date: 2026-08-26

CRIT-06 residual: the application role (`kingphisher`) created and therefore
owned `audit_events` and `audit_chain_head`, so app/audit separation was a
convention (dedicated audit_writer DSN) rather than database-enforced — any
session on the app role could INSERT/UPDATE/DELETE/TRUNCATE audit rows. This
migration transfers ownership of both audit tables to the INSERT-only
`audit_writer` role and revokes all DML on them from the application role.
Tampering with the audit chain now requires the audit credentials themselves.

Behavior and guards:
- Idempotent: ALTER TABLE ... OWNER TO and REVOKE are no-ops when already
  applied, so re-running `alembic upgrade head` is safe.
- Roles may not exist yet in a bare dev database (audit_writer is created by
  infrastructure/containers/postgres-init/001-roles.sh or
  scripts/azure_migrate.py, which run before migrations in the standard
  bootstrap). Every statement is skipped with a NOTICE when the role or table
  is missing instead of failing the upgrade.
- If the migration runs as a role that may not take ownership (not superuser
  and not a member of audit_writer), the transfer is skipped with a NOTICE
  rather than aborting; production migration runners have admin rights.
- The disposable dev compose stack creates `kingphisher` as the bootstrap
  superuser, so the REVOKE cannot restrict it there (superusers bypass
  privilege checks); the ownership transfer plus revokes bite in deployed
  environments where the app role is unprivileged.
- Fresh installs are covered atomically: alembic applies the upgrade run in a
  single transaction, so the audit tables are never observably owned by the
  application role.
- Future migrations that ALTER these tables must run as a role that owns them
  (or a superuser); ownership now belongs to audit_writer.
"""

from __future__ import annotations

from alembic import op

revision = "0010_audit_ownership_separation"
down_revision = "0009_event_open_click_dedup"
branch_labels = None
depends_on = None

APP_ROLE = "kingphisher"
AUDIT_ROLE = "audit_writer"
AUDIT_TABLES = ("audit_events", "audit_chain_head")

# Guarded, idempotent DO blocks over the constant role/table names above
# (never user input; the SQL is fully literal so it is lint-checkable).
# Each statement skips with a NOTICE when the role or table is missing (bare
# dev databases) and when the runner lacks the rights to apply it, so
# `alembic upgrade head` never aborts on dev or CI databases.
_TRANSFER_OWNERSHIP_SQL = """
DO $$
DECLARE
    target text;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_writer') THEN
        RAISE NOTICE 'role audit_writer does not exist, skipping audit ownership transfer';
        RETURN;
    END IF;
    FOREACH target IN ARRAY ARRAY['audit_events', 'audit_chain_head'] LOOP
        IF to_regclass(format('public.%I', target)) IS NULL THEN
            RAISE NOTICE 'table % does not exist, skipping ownership transfer', target;
            CONTINUE;
        END IF;
        BEGIN
            EXECUTE format('ALTER TABLE public.%I OWNER TO audit_writer', target);
        EXCEPTION
            WHEN insufficient_privilege OR undefined_object THEN
                RAISE NOTICE 'not allowed to transfer ownership of %, %', target, SQLERRM;
        END;
    END LOOP;
END
$$
"""

_REVOKE_APP_DML_SQL = """
DO $$
DECLARE
    target text;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kingphisher') THEN
        RAISE NOTICE 'role kingphisher does not exist, skipping audit DML revoke';
        RETURN;
    END IF;
    FOREACH target IN ARRAY ARRAY['audit_events', 'audit_chain_head'] LOOP
        IF to_regclass(format('public.%I', target)) IS NULL THEN
            RAISE NOTICE 'table % does not exist, skipping DML revoke', target;
            CONTINUE;
        END IF;
        BEGIN
            EXECUTE format(
                'REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.%I FROM kingphisher',
                target
            );
        EXCEPTION
            WHEN insufficient_privilege OR undefined_object THEN
                RAISE NOTICE 'cannot revoke DML on %, %', target, SQLERRM;
        END;
    END LOOP;
END
$$
"""

_RESTORE_APP_OWNERSHIP_SQL = """
DO $$
DECLARE
    target text;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kingphisher') THEN
        RAISE NOTICE 'role kingphisher does not exist, skipping audit ownership restore';
        RETURN;
    END IF;
    FOREACH target IN ARRAY ARRAY['audit_events', 'audit_chain_head'] LOOP
        IF to_regclass(format('public.%I', target)) IS NULL THEN
            RAISE NOTICE 'table % does not exist, skipping ownership restore', target;
            CONTINUE;
        END IF;
        BEGIN
            EXECUTE format('ALTER TABLE public.%I OWNER TO kingphisher', target);
        EXCEPTION
            WHEN insufficient_privilege OR undefined_object THEN
                RAISE NOTICE 'not allowed to restore ownership of %, %', target, SQLERRM;
        END;
    END LOOP;
END
$$
"""


def upgrade() -> None:
    # Ownership first: REVOKE cannot remove an owner's implicit privileges,
    # so the app role keeps DML until the tables belong to audit_writer.
    op.execute(_TRANSFER_OWNERSHIP_SQL)
    # Belt and suspenders: drop any explicitly granted DML held by the
    # application role (e.g. re-granted by tooling) on the audit tables.
    op.execute(_REVOKE_APP_DML_SQL)


def downgrade() -> None:
    # Restore the pre-0010 dev state: application ownership. The explicit
    # SELECT/INSERT grants for audit_writer from migrations 0001/0002 remain.
    op.execute(_RESTORE_APP_OWNERSHIP_SQL)
