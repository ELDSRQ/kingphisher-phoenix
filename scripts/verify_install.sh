#!/usr/bin/env bash
# shellcheck disable=SC2329 # check() deliberately invokes named callback functions.
# Kingphisher-Phoenix local install verification.
#
# Health-checks the infrastructure, APIs, console authentication boundary,
# local supervisor children, and append-only audit chain. Azure uses the
# managed multi-role worker; scripts/supervisor.py intentionally keeps the
# local roles separate for development observability.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# shellcheck source=scripts/bootstrap_env.sh
source "$PROJECT_ROOT/scripts/bootstrap_env.sh"

step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m    ok:\033[0m %s\n' "$*"; }
bad()  { printf '\033[1;31m    FAIL:\033[0m %s\n' "$*"; }

for command_name in docker curl uv; do
  command -v "$command_name" >/dev/null 2>&1 || {
    bad "required command not found: $command_name"
    exit 1
  }
done

bootstrap_docker_host || true
docker_timeout_seconds="${KP_READINESS_DOCKER_TIMEOUT_SECONDS:-10}"
if ! [[ "$docker_timeout_seconds" =~ ^[1-9][0-9]*$ ]]; then
  bad "KP_READINESS_DOCKER_TIMEOUT_SECONDS must be a positive integer"
  exit 1
fi
if ! bounded "$docker_timeout_seconds" docker info >/dev/null 2>&1; then
  bad "Docker engine did not respond within ${docker_timeout_seconds}s"
  echo "    Start Docker Desktop (or the Docker service), then run make verify-install again." >&2
  exit 1
fi

FAIL=0
check() {
  local label="$1"
  shift
  if "$@"; then ok "$label"; else bad "$label"; FAIL=1; fi
}

compose_output() {
  bounded "$docker_timeout_seconds" docker compose "$@"
}

compose_healthy() {
  compose_output ps "$1" 2>/dev/null | grep -qi "healthy"
}

compose_running() {
  [[ -n "$(compose_output ps --status running --quiet "$1" 2>/dev/null)" ]]
}

url_ok() {
  curl --connect-timeout 2 --max-time 5 -fsS "$1" >/dev/null
}

session_enforces_auth() {
  [[ "$(curl --connect-timeout 2 --max-time 5 -sS -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" -d "{}" \
    http://127.0.0.1:8000/api/v1/console/session)" == "422" ]]
}

step "docker infrastructure"
check "postgres healthy" compose_healthy postgres
check "redis healthy" compose_healthy redis
check "mailpit healthy" compose_healthy mailpit
check "otel-collector running" compose_running otel-collector
check "mock-idp running" compose_running mock-idp
check "mock-graph running" compose_running mock-graph
check "mock-ai running" compose_running mock-ai

step "application services"
check "operator-api :8000 /readyz" url_ok http://127.0.0.1:8000/readyz
check "tracking-api :8001 /readyz" url_ok http://127.0.0.1:8001/readyz
check "console SPA reachable" url_ok http://127.0.0.1:8000/console/
check "console session enforces auth" session_enforces_auth

# Keep these names synchronized with scripts/supervisor.py. The regression
# contract fails if the launcher's child map and this verifier drift apart.
local_supervisor_api_children=(
  operator-api
  tracking-api
)
local_supervisor_worker_children=(
  worker-ingestion
  worker-generation
  worker-delivery
  worker-retention
  worker-mailbox
  worker-reminder
  worker-alert
  worker-directory
)

pid_is_live() {
  local pidfile="$1" pid
  [[ -f "$pidfile" ]] || return 1
  IFS= read -r pid < "$pidfile" || [[ -n "$pid" ]] || return 1
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
  kill -0 "$pid" 2>/dev/null
}

step "local supervisor children"
for name in "${local_supervisor_api_children[@]}" "${local_supervisor_worker_children[@]}"; do
  pidfile="data/run/$name.pid"
  if pid_is_live "$pidfile"; then
    # Legacy supervisor versions omitted the final newline.  `read` still
    # populates the PID in that case, so do not let its EOF status abort this
    # verifier under `set -e`.
    IFS= read -r pid < "$pidfile" || [[ -n "$pid" ]]
    ok "$name (pid $pid)"
  else
    bad "$name (pidfile $pidfile missing, invalid, or stale)"
    FAIL=1
  fi
done

step "audit chain integrity"
if bounded 30 uv run --frozen --no-sync python scripts/verify_audit.py; then
  ok "audit chain"
else
  bad "audit chain verification failed or exceeded 30s"
  FAIL=1
fi

step "verification result"
if [[ "$FAIL" -eq 0 ]]; then
  echo "  All checks passed."
  exit 0
fi
echo "  Some checks failed. Start the stack with scripts/run_console.sh and inspect data/logs/*.log." >&2
exit 1
