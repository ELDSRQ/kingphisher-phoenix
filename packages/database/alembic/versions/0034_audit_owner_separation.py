"""DB-enforced audit ownership separation for local/non-Azure installs

Revision ID: 0034_audit_owner_separation
Revises: 0033_training_knowledge_check
Create Date: 2026-09-06

AUD-002 (KP-008 structural root, point 4). Migration 0010 transferred the audit
evidence tables (``audit_events``, ``audit_chain_head``) to the *LOGIN* role
``audit_writer`` (and infrastructure/containers/postgres-init/001-roles.sh does
the same on local docker). A table owner keeps every implicit privilege
regardless of REVOKE, so on every non-Azure install ``audit_writer`` — a role
services actually log in as — could UPDATE / DELETE / TRUNCATE audit rows,
i.e. tamper with the append-only chain. Only scripts/azure_migrate.py re-owned
these to a *NOLOGIN* ``audit_owner`` that no session can assume, so the
enforcement existed on managed deployments but NOT on local/self-hosted ones.

This migration moves that ownership transfer into the Alembic chain so
``alembic upgrade head`` gives every install the same hardened state: the two
audit evidence tables are owned by a NOLOGIN ``audit_owner``; ``audit_writer``
keeps only its EXPLICIT least-privilege grants (SELECT/INSERT on audit_events
from 0001, SELECT/INSERT/UPDATE on audit_chain_head from 0002), losing the
owner-implicit DELETE/TRUNCATE it never should have held.

SCOPE / DESIGN DECISIONS (flagged for reviewer):
- This DRAFT transfers ONLY the two audit EVIDENCE tables — the exact objects
  001-roles.sh / 0010 hand to audit_writer on local installs. It intentionally
  does NOT reassign ``transactional_outbox`` or ``audit_integrity_secret`` or
  the audit/outbox FUNCTIONS: on a local install those are owned by the
  bootstrap/app principal (never audit_writer), so reassigning them here would
  strip the local app role of access and break the outbox. scripts/azure_migrate
  still performs the full transfer of all four objects + functions for managed
  deployments (where the app never logs in as the owner). Whether local should
  reach FULL parity (function-only audit dispatch, audit_writer's residual DML
  revoked, dev owner-fallback disabled) is the open question for review.
- Guarded + idempotent like 0010: every step skips with a NOTICE when the role
  or table is missing (bare dev DB, roles created later) or when the runner
  lacks rights, so ``upgrade head`` never aborts on dev/CI. Re-running converges.
- Reassigning to a NOLOGIN role requires the migration role to be a member of it
  (unless superuser). We self-grant membership defensively; azure_migrate has
  already created audit_owner and granted it to the migration principal before
  ``upgrade`` runs, so this is a no-op there.
- The incoming owner must hold CREATE on the schema for ALTER ... OWNER to
  succeed under a non-superuser admin (Azure), so CREATE is granted to
  audit_owner transiently and revoked again, leaving it no standing schema right.
"""

from __future__ import annotations

from alembic import op

revision = "0034_audit_owner_separation"
down_revision = "0033_training_knowledge_check"
branch_labels = None
depends_on = None

AUDIT_TABLES = ("audit_events", "audit_chain_head")

# 1) Ensure a NOLOGIN audit_owner exists and the migration role can reassign to
#    it. Both steps are best-effort and skip with a NOTICE under insufficient
#    privilege so the upgrade never aborts.
_ENSURE_OWNER_ROLE_SQL = """
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_owner') THEN
        BEGIN
            CREATE ROLE audit_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
                NOINHERIT NOREPLICATION NOBYPASSRLS;
        EXCEPTION
            WHEN insufficient_privilege THEN
                RAISE NOTICE 'cannot create audit_owner, skipping audit ownership separation';
                RETURN;
        END;
    END IF;
    BEGIN
        EXECUTE format('GRANT audit_owner TO %I', current_user);
    EXCEPTION
        WHEN insufficient_privilege OR undefined_object THEN
            RAISE NOTICE 'cannot self-grant audit_owner membership: %', SQLERRM;
    END;
END
$$
"""

# 2) Transfer ownership of the two audit evidence tables to audit_owner, with a
#    transient CREATE grant so the reassignment succeeds under a non-superuser
#    admin. Explicit audit_writer grants (SELECT/INSERT/UPDATE) survive; only the
#    owner-implicit DELETE/TRUNCATE is removed.
_TRANSFER_OWNERSHIP_SQL = """
DO $$
DECLARE
    target text;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_owner') THEN
        RAISE NOTICE 'audit_owner does not exist, skipping audit ownership transfer';
        RETURN;
    END IF;
    BEGIN
        GRANT USAGE, CREATE ON SCHEMA public TO audit_owner;
    EXCEPTION
        WHEN insufficient_privilege THEN
            RAISE NOTICE 'cannot grant transient CREATE to audit_owner: %', SQLERRM;
    END;
    FOREACH target IN ARRAY ARRAY['audit_events', 'audit_chain_head'] LOOP
        IF to_regclass(format('public.%I', target)) IS NULL THEN
            RAISE NOTICE 'table % does not exist, skipping ownership transfer', target;
            CONTINUE;
        END IF;
        BEGIN
            EXECUTE format('ALTER TABLE public.%I OWNER TO audit_owner', target);
        EXCEPTION
            WHEN insufficient_privilege OR undefined_object THEN
                RAISE NOTICE 'not allowed to transfer ownership of %, %', target, SQLERRM;
        END;
    END LOOP;
    BEGIN
        REVOKE CREATE ON SCHEMA public FROM audit_owner;
    EXCEPTION
        WHEN insufficient_privilege THEN
            RAISE NOTICE 'cannot revoke transient CREATE from audit_owner: %', SQLERRM;
    END;
END
$$
"""

# 3) Defense in depth: drop any owner-only destructive DML audit_writer may still
#    hold on the evidence tables. audit_writer's legitimate SELECT/INSERT (and
#    UPDATE on audit_chain_head) are explicit grants and are NOT revoked here.
_REVOKE_AUDIT_WRITER_DESTRUCTIVE_SQL = """
DO $$
DECLARE
    target text;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_writer') THEN
        RAISE NOTICE 'audit_writer does not exist, skipping destructive DML revoke';
        RETURN;
    END IF;
    FOREACH target IN ARRAY ARRAY['audit_events', 'audit_chain_head'] LOOP
        IF to_regclass(format('public.%I', target)) IS NULL THEN
            CONTINUE;
        END IF;
        BEGIN
            EXECUTE format('REVOKE DELETE, TRUNCATE ON public.%I FROM audit_writer', target);
        EXCEPTION
            WHEN insufficient_privilege OR undefined_object THEN
                RAISE NOTICE 'cannot revoke destructive DML on % from audit_writer: %', target, SQLERRM;
        END;
    END LOOP;
END
$$
"""

# Downgrade: best-effort restore of the pre-0034 state (audit_writer ownership).
_RESTORE_AUDIT_WRITER_OWNERSHIP_SQL = """
DO $$
DECLARE
    target text;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_writer') THEN
        RAISE NOTICE 'audit_writer does not exist, skipping ownership restore';
        RETURN;
    END IF;
    FOREACH target IN ARRAY ARRAY['audit_events', 'audit_chain_head'] LOOP
        IF to_regclass(format('public.%I', target)) IS NULL THEN
            CONTINUE;
        END IF;
        BEGIN
            EXECUTE format('ALTER TABLE public.%I OWNER TO audit_writer', target);
        EXCEPTION
            WHEN insufficient_privilege OR undefined_object THEN
                RAISE NOTICE 'not allowed to restore ownership of %, %', target, SQLERRM;
        END;
    END LOOP;
END
$$
"""


def upgrade() -> None:
    op.execute(_ENSURE_OWNER_ROLE_SQL)
    op.execute(_TRANSFER_OWNERSHIP_SQL)
    op.execute(_REVOKE_AUDIT_WRITER_DESTRUCTIVE_SQL)


def downgrade() -> None:
    op.execute(_RESTORE_AUDIT_WRITER_OWNERSHIP_SQL)
