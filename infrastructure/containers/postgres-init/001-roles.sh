#!/bin/sh
# Local dev bootstrap for the Kingphisher-Phoenix stack.
# Use the image's fixed POSIX shell path. Docker Desktop can expose a macOS bind
# mount as executable while denying the `/usr/bin/env` shebang interpreter;
# the PostgreSQL entrypoint must still be able to invoke this initializer.
# Creates the INSERT-only audit role and the test database used by pytest.
# Production grants live in infrastructure/terraform; this is disposable-local only.
# The audit_writer password comes from the container env (AUDIT_WRITER_PASSWORD),
# which docker-compose injects from the project .env (CRIT-06: no hardcoded creds).
set -eu

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_writer') THEN
    CREATE ROLE audit_writer LOGIN PASSWORD '${AUDIT_WRITER_PASSWORD}';
  END IF;
END
\$\$;
-- CRIT-06 separation, consistent with alembic migrations
-- 0010_audit_ownership_separation and 0034_audit_owner_separation (AUD-002):
-- the audit evidence tables are owned by the NOLOGIN audit_owner (a role no
-- session can log in as), NOT the LOGIN audit_writer — an owner keeps implicit
-- UPDATE/DELETE/TRUNCATE regardless of REVOKE, so a LOGIN owner could tamper
-- with the append-only chain. audit_writer retains only its explicit
-- SELECT/INSERT (+UPDATE on audit_chain_head) grants. On first boot the tables
-- do not exist yet (alembic creates them and 0034 transfers ownership), so the
-- guarded block below is a no-op then; it converges an already-migrated
-- database to the same hardened state if this script is ever re-run manually.
-- Skipping via NOTICE, never failing.
GRANT USAGE ON SCHEMA public TO audit_writer;
DO \$\$
DECLARE
  target text;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_writer') THEN
    RAISE NOTICE 'role audit_writer does not exist, skipping audit ownership hardening';
    RETURN;
  END IF;
  -- Ensure the NOLOGIN owner exists so re-runs converge to audit_owner, not
  -- back to the LOGIN audit_writer (which would reintroduce the owner bypass).
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_owner') THEN
    CREATE ROLE audit_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
      NOINHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
  FOREACH target IN ARRAY ARRAY['audit_events', 'audit_chain_head'] LOOP
    IF to_regclass(format('public.%I', target)) IS NULL THEN
      CONTINUE;
    END IF;
    EXECUTE format('ALTER TABLE public.%I OWNER TO audit_owner', target);
    EXECUTE format(
      'REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.%I FROM ${POSTGRES_USER}',
      target
    );
    EXECUTE format('REVOKE DELETE, TRUNCATE ON public.%I FROM audit_writer', target);
  END LOOP;
END
\$\$;

-- Awareness-ledger projection and expiry are a retention-only boundary. This
-- block is intentionally guarded because fresh local initialization runs
-- before Alembic creates the table and managed roles.
DO \$\$
DECLARE
  target text;
BEGIN
  IF to_regclass('public.awareness_ledger_entries') IS NULL THEN
    RETURN;
  END IF;
  REVOKE ALL ON TABLE public.awareness_ledger_entries FROM PUBLIC;
  FOREACH target IN ARRAY ARRAY[
    'worker',
    'kp_operator',
    'kp_tracking',
    'kp_worker_ingestion',
    'kp_worker_delivery',
    'kp_worker_reminder',
    'kp_worker_alert',
    'kp_worker_audit_anchor',
    'kp_worker_generation',
    'kp_worker_directory',
    'kp_worker_mailbox'
  ] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = target) THEN
      EXECUTE format('REVOKE ALL ON TABLE public.awareness_ledger_entries FROM %I', target);
    END IF;
  END LOOP;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kp_worker_retention') THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.awareness_ledger_entries TO kp_worker_retention;
  END IF;
END
\$\$;
EOSQL
