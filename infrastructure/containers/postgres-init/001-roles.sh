#!/usr/bin/env bash
# Local dev bootstrap for the Kingphisher-Phoenix stack.
# Creates the INSERT-only audit role and the test database used by pytest.
# Production grants live in infrastructure/terraform; this is disposable-local only.
# The audit_writer password comes from the container env (AUDIT_WRITER_PASSWORD),
# which docker-compose injects from the project .env (CRIT-06: no hardcoded creds).
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_writer') THEN
    CREATE ROLE audit_writer LOGIN PASSWORD '${AUDIT_WRITER_PASSWORD}';
  END IF;
END
\$\$;
-- CRIT-06 separation, consistent with alembic migration
-- 0010_audit_ownership_separation: the audit role owns the audit tables and
-- the application role holds no DML on them. On first boot the tables do not
-- exist yet (alembic creates them and migration 0010 transfers ownership in
-- the same transaction), so the guarded block below is a no-op then; it
-- converges an already-migrated database to the same hardened state if this
-- script is ever re-run manually. Skipping via NOTICE, never failing.
GRANT USAGE ON SCHEMA public TO audit_writer;
DO \$\$
DECLARE
  target text;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_writer') THEN
    RAISE NOTICE 'role audit_writer does not exist, skipping audit ownership hardening';
    RETURN;
  END IF;
  FOREACH target IN ARRAY ARRAY['audit_events', 'audit_chain_head'] LOOP
    IF to_regclass(format('public.%I', target)) IS NULL THEN
      CONTINUE;
    END IF;
    EXECUTE format('ALTER TABLE public.%I OWNER TO audit_writer', target);
    EXECUTE format(
      'REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.%I FROM ${POSTGRES_USER}',
      target
    );
  END LOOP;
END
\$\$;
EOSQL
