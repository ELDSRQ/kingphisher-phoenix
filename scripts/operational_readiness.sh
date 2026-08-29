#!/usr/bin/env bash
# Production-safe operational gate for a preservation-required local stack.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

readiness_env_file="${KP_READINESS_ENV_FILE:-.env}"
if [[ ! -f "$readiness_env_file" ]]; then
  echo "FAIL: $readiness_env_file is required; run scripts/bootstrap_env.sh first" >&2
  exit 1
fi

# Load dotenv values as data, not shell source. Values such as OIDC scopes
# legitimately contain spaces, and a configuration file must never execute
# shell syntax during a readiness check.
while IFS='=' read -r variable_name variable_value; do
  [[ "$variable_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
  case "$variable_name" in
    APP_ENV|LOG_LEVEL|POSTGRES_PASSWORD|REDIS_PASSWORD|AUDIT_WRITER_PASSWORD|DATABASE_URL|DATABASE_URL_TEST|AUDIT_DATABASE_URL|AUDIT_DATABASE_URL_TEST|REDIS_URL|MAILPIT_URL|MAILPIT_API_PASSWORD|TRACKING_TOKEN_HMAC_KEY|TRAINING_TOKEN_HMAC_KEY|OPERATOR_API_*|TRACKING_API_*|KP_WORKER_*|KP_ALLOWED_RECIPIENT_DOMAINS|KP_ROE_SIGNING_KEY|KP_SENDING_DOMAINS|KP_BRAND_ALLOWLIST|KP_CONSOLE_PASSWORD|AZURE_GRAPH_*|MOCK_*)
      export "$variable_name=$variable_value"
      ;;
    *)
      # Dotenv is application configuration, not authority to alter command
      # lookup, shell/Python startup, test selection, Docker routing, or the
      # readiness harness itself. Unknown keys are deliberately ignored.
      continue
      ;;
  esac
done < "$readiness_env_file"

# Local bootstrap rotates the audit-writer password but older env files do not
# contain its test-database DSN. Build the local-only test URL in memory and
# export it without printing credentials. An explicit value still wins.
if [[ -z "${AUDIT_DATABASE_URL_TEST:-}" ]]; then
  AUDIT_DATABASE_URL_TEST="postgresql+psycopg://audit_writer:${AUDIT_WRITER_PASSWORD:-}@localhost:5432/kingphisher_test"
  export AUDIT_DATABASE_URL_TEST
fi

for command_name in uv docker curl node df awk grep make python3 env; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "FAIL: required command not found: $command_name" >&2
    exit 1
  }
done

required_variables=(
  POSTGRES_PASSWORD REDIS_PASSWORD AUDIT_WRITER_PASSWORD MAILPIT_API_PASSWORD
  DATABASE_URL_TEST AUDIT_DATABASE_URL_TEST REDIS_URL
  KP_CONSOLE_PASSWORD OPERATOR_API_AUDIT_HMAC_KEY
  OPERATOR_API_CIPHERTEXT_KEK OPERATOR_API_CONSOLE_JWT_SECRET
)
for variable_name in "${required_variables[@]}"; do
  [[ -n "${!variable_name:-}" ]] || {
    echo "FAIL: required configuration is empty: $variable_name" >&2
    exit 1
  }
done

# Integration tests must never use the application's queue database. Reserve
# database 14 for queue work emitted by PostgreSQL/API tests and database 15
# for the Redis contract itself. Python preserves escaped credentials while
# replacing only the logical database path.
derive_redis_test_url() {
  REDIS_URL_INPUT="$REDIS_URL" REDIS_DATABASE_NUMBER="$1" python3 - <<'PY'
import os
from urllib.parse import urlsplit, urlunsplit

parsed = urlsplit(os.environ["REDIS_URL_INPUT"])
if parsed.scheme not in {"redis", "rediss"} or not parsed.hostname:
    raise SystemExit(2)
if parsed.fragment:
    raise SystemExit(2)
database_number = os.environ["REDIS_DATABASE_NUMBER"]
if database_number not in {"14", "15"}:
    raise SystemExit(2)
print(urlunsplit((parsed.scheme, parsed.netloc, f"/{database_number}", parsed.query, "")))
PY
}
if ! REDIS_URL_POSTGRES_TEST="$(derive_redis_test_url 14)" \
  || ! REDIS_URL_TEST="$(derive_redis_test_url 15)"; then
  echo "FAIL: REDIS_URL must be a valid redis:// or rediss:// URL" >&2
  exit 1
fi

production_url="${OPERATOR_API_DATABASE_URL:-${DATABASE_URL:-}}"
if [[ -n "$production_url" && "$DATABASE_URL_TEST" == "$production_url" ]]; then
  echo "FAIL: DATABASE_URL_TEST must not reference the application database" >&2
  exit 1
fi

minimum_free_kib="${KP_READINESS_MIN_FREE_KIB:-2097152}"
if ! [[ "$minimum_free_kib" =~ ^[1-9][0-9]*$ ]]; then
  echo "FAIL: KP_READINESS_MIN_FREE_KIB must be a positive integer" >&2
  exit 1
fi
if ! available_kib="$(df -Pk "$PROJECT_ROOT" | awk 'NR == 2 {print $4}')"; then
  echo "FAIL: could not determine free disk space for $PROJECT_ROOT" >&2
  exit 1
fi
if ! [[ "$available_kib" =~ ^[0-9]+$ ]]; then
  echo "FAIL: could not determine free disk space for $PROJECT_ROOT" >&2
  exit 1
fi
if (( available_kib < minimum_free_kib )); then
  echo "FAIL: operational readiness requires at least ${minimum_free_kib} KiB free; only ${available_kib} KiB is available" >&2
  echo "Free disk space without pruning or restarting shared Docker resources, then rerun make operational-readiness." >&2
  exit 1
fi

# shellcheck source=scripts/bootstrap_env.sh
source "$PROJECT_ROOT/scripts/bootstrap_env.sh"
bootstrap_docker_host || true

docker_timeout_seconds="${KP_READINESS_DOCKER_TIMEOUT_SECONDS:-10}"
if ! [[ "$docker_timeout_seconds" =~ ^[1-9][0-9]*$ ]]; then
  echo "FAIL: KP_READINESS_DOCKER_TIMEOUT_SECONDS must be a positive integer" >&2
  exit 1
fi
gate_timeout_seconds="${KP_READINESS_GATE_TIMEOUT_SECONDS:-3600}"
if ! [[ "$gate_timeout_seconds" =~ ^[1-9][0-9]*$ ]] \
  || (( gate_timeout_seconds < 60 || gate_timeout_seconds > 7200 )); then
  echo "FAIL: KP_READINESS_GATE_TIMEOUT_SECONDS must be an integer from 60 through 7200" >&2
  exit 1
fi
if ! bounded "$docker_timeout_seconds" docker info >/dev/null 2>&1; then
  echo "FAIL: Docker engine did not respond within ${docker_timeout_seconds}s" >&2
  echo "Start Docker Desktop (or the Docker service); this gate never restarts or prunes Docker." >&2
  exit 1
fi
if ! bounded "$docker_timeout_seconds" docker compose config --quiet >/dev/null 2>&1; then
  echo "FAIL: Docker Compose configuration is invalid or did not respond within ${docker_timeout_seconds}s" >&2
  echo "Run 'docker compose config' for details, correct the configuration, and retry." >&2
  exit 1
fi

require_healthy_service() {
  local service="$1" output
  if ! output="$(bounded "$docker_timeout_seconds" docker compose ps "$service" 2>&1)"; then
    echo "FAIL: could not inspect required service '$service' within ${docker_timeout_seconds}s" >&2
    exit 1
  fi
  if (( ${#output} > 65536 )); then
    echo "FAIL: service inspection returned unexpectedly large output" >&2
    exit 1
  fi
  if ! grep -Fqi "(healthy)" <<< "$output"; then
    echo "FAIL: required service '$service' is not healthy" >&2
    echo "Start the local stack with scripts/run_console.sh, then retry." >&2
    exit 1
  fi
}

require_running_service() {
  local service="$1" container_id
  if ! container_id="$(bounded "$docker_timeout_seconds" docker compose ps --status running --quiet "$service" 2>&1)"; then
    echo "FAIL: could not inspect required service '$service' within ${docker_timeout_seconds}s" >&2
    exit 1
  fi
  if [[ -z "$container_id" ]]; then
    echo "FAIL: required service '$service' is not running" >&2
    echo "Start the local stack with scripts/run_console.sh, then retry." >&2
    exit 1
  fi
}

for service in postgres redis mailpit; do
  require_healthy_service "$service"
done
for service in otel-collector mock-idp mock-graph mock-ai; do
  require_running_service "$service"
done

run() {
  printf '\n==> %s\n' "$1"
  shift
  python3 - "$gate_timeout_seconds" "$@" <<'PYGATE'
import subprocess
import sys

try:
    result = subprocess.run(sys.argv[2:], timeout=int(sys.argv[1]), check=False)
except subprocess.TimeoutExpired:
    print("FAIL: readiness gate exceeded its bounded execution window", file=sys.stderr)
    raise SystemExit(124) from None
raise SystemExit(result.returncode)
PYGATE
}

# The readiness environment intentionally contains live service endpoints and
# provider configuration. Hermetic tests must not consume any of it: Pydantic
# settings read process variables even when an individual test disables its
# dotenv file. Keep only process/toolchain values needed to execute the pinned
# local test suite. Integration and E2E gates below receive their live values
# separately.
hermetic_environment=(env -i "PATH=$PATH" "KP_DISABLE_DOTENV=1")
for variable_name in HOME TMPDIR LANG LC_ALL LC_CTYPE TZ USER LOGNAME UV_CACHE_DIR UV_PYTHON UV_PYTHON_DOWNLOADS; do
  variable_value="${!variable_name-}"
  if [[ -n "$variable_value" ]]; then
    hermetic_environment+=("$variable_name=$variable_value")
  fi
done

run "verify database is at all migration heads" uv run alembic -c packages/database/alembic.ini current --check-heads
run "lint Python and console JavaScript" make lint
run "type-check application" make typecheck
run "run hermetic tests without skipped checks" "${hermetic_environment[@]}" make test
# The dotenv reader exported the dedicated URLs above. Pass them to Make
# through the inherited environment; never echo connection strings or secrets.
run "run PostgreSQL integration tests against the dedicated test database without skipped checks" env \
  DATABASE_URL_TEST="$DATABASE_URL_TEST" AUDIT_DATABASE_URL_TEST="$AUDIT_DATABASE_URL_TEST" \
  REDIS_URL_POSTGRES_TEST="$REDIS_URL_POSTGRES_TEST" make test-postgres
run "run Redis integration tests against dedicated queue database 15 without skipped checks" env \
  REDIS_URL_TEST="$REDIS_URL_TEST" make test-redis
run "verify append-only audit chain" make verify-audit
run "verify running infrastructure, APIs, workers, and console auth" make verify-install
run "exercise live console/API and single-administrator campaign lifecycle without skipped checks" env \
  KP_E2E_PASSWORD="$KP_CONSOLE_PASSWORD" KP_E2E_LIFECYCLE=1 make test-e2e

printf '\nOperational readiness gate passed. Lifecycle evidence remains in the local database.\n'
