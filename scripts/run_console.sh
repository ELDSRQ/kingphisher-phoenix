#!/usr/bin/env bash
# Kingphisher-Phoenix one-click launcher.
#
# Starts the whole local stack (infra + operator API + tracking API + workers)
# and opens the browser console. Everything downstream is GUI-driven; there is
# no CLI workflow. If the stack is already running it just opens the console.
#
# Usage:
#   scripts/run_console.sh            # start and keep running (supervisor in foreground)
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

CONSOLE_URL="http://127.0.0.1:8000/console"
ENV_FILE="$PROJECT_ROOT/.env"
RUN_DIR="$PROJECT_ROOT/data/run"
LOG_DIR="$PROJECT_ROOT/data/logs"

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command '$1' not found on PATH" >&2
    echo "install it, then re-run this launcher." >&2
    exit 1
  fi
}

# shellcheck source=scripts/bootstrap_env.sh
source "$PROJECT_ROOT/scripts/bootstrap_env.sh"
DOCKER_TIMEOUT_SECONDS="${KP_LOCAL_DOCKER_TIMEOUT_SECONDS:-15}"

die() {
  echo "error: $*" >&2
  exit 1
}

bounded_seconds_are_valid "$DOCKER_TIMEOUT_SECONDS" 600 \
  || die "KP_LOCAL_DOCKER_TIMEOUT_SECONDS must be a positive integer no greater than 600; no project assets were changed."

require_disk_headroom() {
  local minimum_free_gib minimum_free_kib available_kib
  minimum_free_gib="${KP_LOCAL_MIN_FREE_GIB:-8}"
  if ! [[ "$minimum_free_gib" =~ ^[1-9][0-9]*$ ]] \
    || [ "${#minimum_free_gib}" -gt 6 ] \
    || (( 10#$minimum_free_gib > 1048576 )); then
    die "KP_LOCAL_MIN_FREE_GIB must be a positive whole-GiB integer no greater than 1048576. Set a valid value, then relaunch; no project assets were changed."
  fi
  minimum_free_kib=$((10#$minimum_free_gib * 1024 * 1024))
  if ! available_kib="$(bounded 10 df -Pk "$PROJECT_ROOT" | awk 'NR == 2 { print $4 }')" \
    || ! [[ "$available_kib" =~ ^[0-9]+$ ]]; then
    die "Local disk capacity could not be measured within 10 seconds. Verify filesystem capacity reporting and add capacity if needed, then relaunch; no project assets were changed."
  fi
  if (( available_kib < minimum_free_kib )); then
    die "Local deployment requires at least ${minimum_free_gib} GiB available; only ${available_kib} KiB is available. Add disk capacity outside preserved project assets, then relaunch; no project assets were changed."
  fi
  echo "disk headroom passed (${minimum_free_gib} GiB required; ${available_kib} KiB available)."
}

run_base_image_qualification() {
  local gate_command
  echo "qualifying immutable stateful base images for this Docker platform..."
  if [ -n "$DOCKER_WRAP" ]; then
    printf -v gate_command '%q --timeout-seconds 300' \
      "$PROJECT_ROOT/scripts/operator/base-image-qualification/run.sh"
    bounded 900 sg docker -c "$gate_command" \
      || die "Stateful base-image qualification did not pass within its bounded window. Keep existing containers and named volumes unchanged, review the reported digest/platform/probe failure, then relaunch."
  else
    bounded 900 "$PROJECT_ROOT/scripts/operator/base-image-qualification/run.sh" --timeout-seconds 300 \
      || die "Stateful base-image qualification did not pass within its bounded window. Keep existing containers and named volumes unchanged, review the reported digest/platform/probe failure, then relaunch."
  fi
}

run_deployment_preflight() {
  local gate_command minimum_free_gib phase
  phase="$1"
  case "$phase" in
    prestart|ready) ;;
    *) die "Internal deployment preflight phase is invalid; no project assets were changed." ;;
  esac
  minimum_free_gib="${KP_LOCAL_MIN_FREE_GIB:-8}"
  echo "running read-only deployment preflight (${phase})..."
  if [ -n "$DOCKER_WRAP" ]; then
    printf -v gate_command '%q --root %q --phase %q --minimum-free-gib %q --timeout-seconds 15' \
      "$PROJECT_ROOT/scripts/operator/deployment-preflight/run.sh" "$PROJECT_ROOT" "$phase" "$minimum_free_gib"
    bounded 180 sg docker -c "$gate_command" \
      || die "Read-only deployment preflight (${phase}) did not pass within its bounded window. Preserve existing services and named volumes, follow its safe next action, then relaunch."
  else
    bounded 180 "$PROJECT_ROOT/scripts/operator/deployment-preflight/run.sh" \
      --root "$PROJECT_ROOT" \
      --phase "$phase" \
      --minimum-free-gib "$minimum_free_gib" \
      --timeout-seconds 15 \
      || die "Read-only deployment preflight (${phase}) did not pass within its bounded window. Preserve existing services and named volumes, follow its safe next action, then relaunch."
  fi
}

DOCKER_WRAP=""
dc() {
  if [ -n "$DOCKER_WRAP" ]; then
    # Arguments are fixed service names/options owned by this launcher.
    # shellcheck disable=SC2016
    sg docker -c "docker compose $*"
  else
    docker compose "$@"
  fi
}

compose_service_healthy() {
  local output
  output="$(bounded "$DOCKER_TIMEOUT_SECONDS" dc ps "$1" 2>/dev/null)" || return 1
  printf '%s\n' "$output" | grep -q '(healthy)'
}

start_infra() {
  require docker
  bootstrap_docker_host || true
  if ! bounded "$DOCKER_TIMEOUT_SECONDS" docker info >/dev/null 2>&1; then
    local current_user
    current_user="${USER:-$(id -un)}"
    if command -v sg >/dev/null 2>&1 \
      && id -nG "$current_user" | grep -qw docker \
      && bounded "$DOCKER_TIMEOUT_SECONDS" sg docker -c "docker info" >/dev/null 2>&1; then
      DOCKER_WRAP="sg docker -c"
    else
      die "Docker did not answer within ${DOCKER_TIMEOUT_SECONDS}s. Start Docker/Colima, confirm this user can access it, and relaunch. No containers were restarted or pruned."
    fi
  fi
  bounded "$DOCKER_TIMEOUT_SECONDS" dc version >/dev/null 2>&1 \
    || die "Docker Compose did not answer within ${DOCKER_TIMEOUT_SECONDS}s. Install/enable the Compose plugin, then relaunch."
  bootstrap_env \
    || die "Recovery-sensitive configuration could not be safely bootstrapped. Preserve the existing volumes and restore protected configuration before relaunching."
  run_deployment_preflight prestart
  run_base_image_qualification
  echo "starting infrastructure (postgres, redis, mailpit, mocks)..."
  bounded 120 dc up -d --no-recreate postgres redis mailpit otel-collector mock-graph mock-ai mock-idp \
    || die "Docker Compose could not start local infrastructure within 120s. Inspect Docker diagnostics and relaunch."
  echo "waiting for postgres and redis to be healthy..."
  for _ in $(seq 1 60); do
    if compose_service_healthy postgres && compose_service_healthy redis; then
      break
    fi
    sleep 2
  done
  compose_service_healthy postgres \
    || die "Postgres never became healthy. Inspect 'docker compose logs postgres', correct the error, and relaunch."
  compose_service_healthy redis \
    || die "Redis never became healthy. Inspect 'docker compose logs redis', correct the error, and relaunch."
}

init_db() {
  echo "applying database migrations..."
  uv run --frozen --no-sync alembic -c packages/database/alembic.ini upgrade head \
    || die "database migration failed; the application stack was not started"
  echo "verifying and initializing the local audit integrity root..."
  uv run --frozen --no-sync python scripts/bootstrap_local_audit.py \
    || die "local audit integrity bootstrap failed; the application stack was not started"
  echo "seeding demo dataset (idempotent)..."
  uv run --frozen --no-sync python scripts/seed.py \
    || die "demo seed failed; the application stack was not started"
}

ensure_venv() {
  require uv
  echo "synchronizing the frozen project environment..."
  UV_PYTHON_DOWNLOADS=never uv sync --frozen --all-packages \
    || die "dependency sync failed; uv.lock was not modified"
}

launch_ui() {
  echo "opening console at $CONSOLE_URL"
  if command -v open >/dev/null 2>&1; then
    open "$CONSOLE_URL" || true
  else
    echo "open the console in your browser: $CONSOLE_URL"
  fi
}

mkdir -p "$RUN_DIR" "$LOG_DIR"

# Refuse to double-launch: if the supervisor is already running, just open.
# Check before any gated startup work so a second Finder launch remains fast.
if pidfile_is_live "$RUN_DIR/operator-api.pid"; then
  if command -v curl >/dev/null 2>&1 \
    && curl --max-time 2 -fsS http://127.0.0.1:8000/readyz >/dev/null 2>&1; then
    echo "stack already running and ready; opening console."
    launch_ui
    exit 0
  fi
  die "A live operator PID exists, but console readiness could not be confirmed. Wait for startup or inspect preserved logs; no duplicate supervisor was launched."
fi
require_disk_headroom

ensure_venv
start_infra
init_db
run_deployment_preflight ready

launch_ui
echo "running supervisor; restart the stack from the console or stop this launcher from the host."
exec uv run --frozen --no-sync python scripts/supervisor.py
