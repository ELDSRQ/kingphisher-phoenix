#!/usr/bin/env bash
# Production-safe operational gate for a disposable, provisioned local stack.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

if [[ ! -f .env ]]; then
  echo "FAIL: .env is required; run scripts/bootstrap_env.sh first" >&2
  exit 1
fi

# Load dotenv values as data, not shell source. Values such as OIDC scopes
# legitimately contain spaces, and a configuration file must never execute
# shell syntax during a readiness check.
while IFS='=' read -r variable_name variable_value; do
  [[ "$variable_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
  export "$variable_name=$variable_value"
done < .env

for command_name in uv docker curl node; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "FAIL: required command not found: $command_name" >&2
    exit 1
  }
done

required_variables=(
  POSTGRES_PASSWORD REDIS_PASSWORD AUDIT_WRITER_PASSWORD MAILPIT_API_PASSWORD
  DATABASE_URL_TEST KP_CONSOLE_PASSWORD OPERATOR_API_AUDIT_HMAC_KEY
  OPERATOR_API_CIPHERTEXT_KEK OPERATOR_API_CONSOLE_JWT_SECRET
)
for variable_name in "${required_variables[@]}"; do
  [[ -n "${!variable_name:-}" ]] || {
    echo "FAIL: required configuration is empty: $variable_name" >&2
    exit 1
  }
done

production_url="${OPERATOR_API_DATABASE_URL:-${DATABASE_URL:-}}"
if [[ -n "$production_url" && "$DATABASE_URL_TEST" == "$production_url" ]]; then
  echo "FAIL: DATABASE_URL_TEST must not reference the application database" >&2
  exit 1
fi

run() {
  printf '\n==> %s\n' "$1"
  shift
  "$@"
}

run "validate Compose configuration" docker compose config --quiet
run "verify database is at all migration heads" uv run alembic -c packages/database/alembic.ini current --check-heads
run "lint Python and console JavaScript" make lint
run "type-check application" make typecheck
run "run automated tests against the dedicated test database" make test
run "verify append-only audit chain" make verify-audit
run "verify running infrastructure, APIs, workers, and console auth" make verify-install
run "exercise live console/API and distinct-principal campaign lifecycle" env \
  KP_E2E_PASSWORD="$KP_CONSOLE_PASSWORD" KP_E2E_LIFECYCLE=1 uv run pytest -q tests/e2e

printf '\nOperational readiness gate passed. Lifecycle evidence remains in the local database.\n'
