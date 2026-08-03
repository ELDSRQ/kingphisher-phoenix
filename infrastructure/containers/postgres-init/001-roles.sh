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
EOSQL
