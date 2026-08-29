#!/usr/bin/env bash
# Kingphisher-Phoenix one-shot installer.
#
# Checks the local prerequisites and delivers a fully operational local system:
# infrastructure (Postgres, Redis, Mailpit, mocks),
# a seeded database, the operator/tracking APIs and worker services running
# under the supervisor, and (on macOS) the double-clickable
# "Kingphisher Launcher.app". The operator console opens in the browser.
#
# Supported platforms:
#   - macOS (arm64/x86_64): Homebrew, Docker via Colima, uv >= 0.11, Python 3.13
#   - Linux (Debian/Ubuntu): apt, docker.io + compose plugin, uv >= 0.11, Python 3.13
#
# Usage:
#   ./scripts/install.sh            # full install + start
#   ./scripts/install.sh --skip-deps  # re-run provisioning on an existing machine
#   ./scripts/install.sh --check-uv  # verify the uv prerequisite and exit
#
# This script is idempotent: re-running it never breaks a working install.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

CONSOLE_URL="http://127.0.0.1:8000/console"
ENV_FILE="$PROJECT_ROOT/.env"
UV_COMMAND="${KP_UV_COMMAND:-uv}"
UV_MIN_VERSION="0.11.0"

# shellcheck source=scripts/bootstrap_env.sh
source "$PROJECT_ROOT/scripts/bootstrap_env.sh"
DOCKER_TIMEOUT_SECONDS="${KP_LOCAL_DOCKER_TIMEOUT_SECONDS:-15}"
INFRASTRUCTURE_START_TIMEOUT_SECONDS="${KP_LOCAL_INFRASTRUCTURE_START_TIMEOUT_SECONDS:-900}"

SKIP_DEPS=0
UV_CHECK_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --skip-deps) SKIP_DEPS=1 ;;
    --check-uv) UV_CHECK_ONLY=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m    ok:\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m    warn:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

command_exists() { command -v "$1" >/dev/null 2>&1; }

bounded_seconds_are_valid "$DOCKER_TIMEOUT_SECONDS" 600 \
  || die "KP_LOCAL_DOCKER_TIMEOUT_SECONDS must be a positive integer no greater than 600; no project assets were changed."
bounded_seconds_are_valid "$INFRASTRUCTURE_START_TIMEOUT_SECONDS" 3600 \
  || die "KP_LOCAL_INFRASTRUCTURE_START_TIMEOUT_SECONDS must be a positive whole-second integer no greater than 3600; no project assets were changed."

require_disk_headroom() {
  local minimum_free_gib minimum_free_kib available_kib
  minimum_free_gib="${KP_LOCAL_MIN_FREE_GIB:-8}"
  if ! [[ "$minimum_free_gib" =~ ^[1-9][0-9]*$ ]] \
    || [ "${#minimum_free_gib}" -gt 6 ] \
    || (( 10#$minimum_free_gib > 1048576 )); then
    die "KP_LOCAL_MIN_FREE_GIB must be a positive whole-GiB integer no greater than 1048576. Set a valid value, then re-run; no project assets were changed."
  fi
  minimum_free_kib=$((10#$minimum_free_gib * 1024 * 1024))
  if ! available_kib="$(bounded 10 df -Pk "$PROJECT_ROOT" | awk 'NR == 2 { print $4 }')" \
    || ! [[ "$available_kib" =~ ^[0-9]+$ ]]; then
    die "Local disk capacity could not be measured within 10 seconds. Verify filesystem capacity reporting and add capacity if needed, then re-run; no project assets were changed."
  fi
  if (( available_kib < minimum_free_kib )); then
    die "Local deployment requires at least ${minimum_free_gib} GiB available; only ${available_kib} KiB is available. Add disk capacity outside preserved project assets, then re-run; no project assets were changed."
  fi
  ok "disk headroom passed (${minimum_free_gib} GiB required; ${available_kib} KiB available)"
}

detect_os() {
  case "$(uname -s)" in
    Darwin) echo "macos" ;;
    Linux)  echo "linux" ;;
    *) die "unsupported OS: $(uname -s); this installer targets macOS and Linux" ;;
  esac
}
OS="$(detect_os)"
INSTALL_USER="${SUDO_USER:-${USER:-$(id -un)}}"

# --------------------------------------------------------------------------
# 0. Skip the dependency phase for re-runs on a provisioned machine.
# --------------------------------------------------------------------------
if [ "$SKIP_DEPS" -eq 1 ]; then
  step "skipping dependency installation (--skip-deps)"
fi

# --------------------------------------------------------------------------
# 1. Base tooling
# --------------------------------------------------------------------------
if [ "$SKIP_DEPS" -eq 0 ]; then
  step "checking base tooling (git, curl, openssl)"
  for tool in git curl openssl; do
    command_exists "$tool" || die "required command '$tool' not found on PATH"
  done
  ok "git, curl, openssl present"
fi

# --------------------------------------------------------------------------
# 2. uv (Python package + interpreter manager)
# --------------------------------------------------------------------------
require_compatible_uv() {
  local output version major minor

  if ! command_exists "$UV_COMMAND"; then
    die "uv ${UV_MIN_VERSION} or newer is required. Install it with a trusted package manager (macOS: 'brew install uv'; Linux: follow https://docs.astral.sh/uv/getting-started/installation/), then re-run. This installer does not execute downloaded shell scripts."
  fi

  output="$("$UV_COMMAND" --version 2>/dev/null)" \
    || die "uv could not run. Repair or reinstall uv with your trusted package manager, then re-run."
  version="${output#uv }"
  version="${version%% *}"
  if [[ ! "$version" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
    die "uv returned an unrecognized version. Install uv ${UV_MIN_VERSION} or newer with your trusted package manager, then re-run."
  fi
  major="${BASH_REMATCH[1]}"
  minor="${BASH_REMATCH[2]}"
  if (( 10#$major == 0 && 10#$minor < 11 )); then
    die "uv ${version} is too old; uv ${UV_MIN_VERSION} or newer is required. Upgrade it with your trusted package manager, then re-run."
  fi

  printf 'uv %s\n' "$version"
}

require_compatible_uv
ok "compatible uv present"
[ "$UV_CHECK_ONLY" -eq 0 ] || exit 0
require_disk_headroom
bootstrap_docker_host || true

# --------------------------------------------------------------------------
# 3. Docker (CLI + daemon). macOS uses Colima; Linux uses docker.io.
# --------------------------------------------------------------------------
docker_ready() {
  command_exists docker \
    && bounded "$DOCKER_TIMEOUT_SECONDS" docker info >/dev/null 2>&1
}

if [ "$SKIP_DEPS" -eq 0 ] && ! docker_ready; then
  case "$OS" in
    macos)
      step "installing Docker via Homebrew + Colima"
      command_exists brew || die "Homebrew is required on macOS; install it first (https://brew.sh)"
      brew install docker docker-compose colima
      step "starting Colima (first start downloads a VM image; can take a few minutes)"
      bounded 300 colima start --cpu 2 --memory 4 \
        || die "Colima did not start within 5 minutes; open Colima/Docker diagnostics, then re-run with --skip-deps"
      ;;
    linux)
      step "installing Docker via apt (needs sudo)"
      if [ "$(id -u)" -eq 0 ]; then
        SUDO=""
      else
        SUDO="sudo"
      fi
      $SUDO apt-get update
      $SUDO apt-get install -y docker.io docker-compose-plugin
      $SUDO systemctl enable --now docker
      if [ "$(id -u)" -ne 0 ]; then
        $SUDO usermod -aG docker "$INSTALL_USER"
      fi
      ;;
  esac
fi

# If the daemon is reachable only inside the docker group (fresh Linux install),
# wrap docker compose calls so the script still completes without a re-login.
DOCKER_WRAP=""
if ! docker_ready && command_exists sg && id -nG "$INSTALL_USER" | grep -qw docker; then
  DOCKER_WRAP="sg docker -c"
fi
if ! docker_ready; then
  warn "docker is installed but the daemon is not reachable from this shell."
  warn "On Linux after a fresh docker group add, log out/in (or run: newgrp docker),"
  warn "then re-run: ./scripts/install.sh --skip-deps"
  [ -z "$DOCKER_WRAP" ] && die "Docker did not answer within ${DOCKER_TIMEOUT_SECONDS}s; start the daemon and re-run with --skip-deps"
  bounded "$DOCKER_TIMEOUT_SECONDS" sg docker -c "docker info" >/dev/null 2>&1 \
    || die "Docker did not answer through the docker group; log out/in and re-run with --skip-deps"
fi
if [ -n "$DOCKER_WRAP" ]; then
  bounded "$DOCKER_TIMEOUT_SECONDS" sg docker -c "docker version --format 'client {{.Client.Version}}'" \
    || die "Docker stopped responding; check the daemon and re-run with --skip-deps"
else
  bounded "$DOCKER_TIMEOUT_SECONDS" docker version --format 'client {{.Client.Version}}' \
    || die "Docker stopped responding; check the daemon and re-run with --skip-deps"
fi
ok "docker present"

# Validate recovery-sensitive values and inspect for preserved volumes before
# dependency synchronization changes the regenerable Python environment.
_validate_recovery_configuration_before_bootstrap \
  || die "Recovery-sensitive configuration is invalid. Restore protected configuration before re-running."
assert_recovery_credentials_before_bootstrap \
  || die "Recovery-sensitive configuration is incomplete. Preserve existing volumes and restore protected configuration before re-running."

dc() {
  if [ -n "$DOCKER_WRAP" ]; then
    # shellcheck disable=SC2016
    sg docker -c "docker compose $*"
  else
    docker compose "$@"
  fi
}

run_base_image_qualification() {
  local gate_command
  step "qualifying immutable stateful base images for this Docker platform"
  if [ -n "$DOCKER_WRAP" ]; then
    printf -v gate_command '%q --timeout-seconds 300' \
      "$PROJECT_ROOT/scripts/operator/base-image-qualification/run.sh"
    bounded 900 sg docker -c "$gate_command" \
      || die "Stateful base-image qualification did not pass within its bounded window. Keep existing containers and named volumes unchanged, review the reported digest/platform/probe failure, then re-run with --skip-deps."
  else
    bounded 900 "$PROJECT_ROOT/scripts/operator/base-image-qualification/run.sh" --timeout-seconds 300 \
      || die "Stateful base-image qualification did not pass within its bounded window. Keep existing containers and named volumes unchanged, review the reported digest/platform/probe failure, then re-run with --skip-deps."
  fi
  ok "stateful base images qualified"
}

run_deployment_preflight() {
  local gate_command minimum_free_gib phase
  phase="$1"
  case "$phase" in
    prestart|ready) ;;
    *) die "Internal deployment preflight phase is invalid; no project assets were changed." ;;
  esac
  minimum_free_gib="${KP_LOCAL_MIN_FREE_GIB:-8}"
  step "running read-only deployment preflight (${phase})"
  if [ -n "$DOCKER_WRAP" ]; then
    printf -v gate_command '%q --root %q --phase %q --minimum-free-gib %q --timeout-seconds 15' \
      "$PROJECT_ROOT/scripts/operator/deployment-preflight/run.sh" "$PROJECT_ROOT" "$phase" "$minimum_free_gib"
    bounded 180 sg docker -c "$gate_command" \
      || die "Read-only deployment preflight (${phase}) did not pass within its bounded window. Preserve existing services and named volumes, follow its safe next action, then re-run with --skip-deps."
  else
    bounded 180 "$PROJECT_ROOT/scripts/operator/deployment-preflight/run.sh" \
      --root "$PROJECT_ROOT" \
      --phase "$phase" \
      --minimum-free-gib "$minimum_free_gib" \
      --timeout-seconds 15 \
      || die "Read-only deployment preflight (${phase}) did not pass within its bounded window. Preserve existing services and named volumes, follow its safe next action, then re-run with --skip-deps."
  fi
  ok "read-only deployment preflight (${phase}) passed"
}

# --------------------------------------------------------------------------
# 4. Python environment (uv creates the .venv and installs Python 3.13)
# --------------------------------------------------------------------------
step "creating virtualenv and installing dependencies (uv sync)"
bounded 900 "$UV_COMMAND" sync --frozen --all-packages \
  || die "dependency installation failed or exceeded 15 minutes; check network/package access, then re-run"
"$UV_COMMAND" run python --version
ok "project virtualenv ready"

# --------------------------------------------------------------------------
# 5. Local infrastructure
# --------------------------------------------------------------------------
# shellcheck source=scripts/bootstrap_env.sh
source "$PROJECT_ROOT/scripts/bootstrap_env.sh"
bootstrap_env \
  || die "Recovery-sensitive configuration could not be safely bootstrapped. Preserve the existing volumes and restore protected configuration before re-running."
run_deployment_preflight prestart
run_base_image_qualification

step "starting infrastructure (postgres, redis, mailpit, mocks)"
bounded "$INFRASTRUCTURE_START_TIMEOUT_SECONDS" \
  dc up -d --no-recreate postgres redis mailpit otel-collector mock-graph mock-ai mock-idp \
  || die "Docker Compose did not complete local infrastructure startup within ${INFRASTRUCTURE_START_TIMEOUT_SECONDS}s. Existing containers, images, and pull/build progress were preserved; inspect 'docker compose ps', then re-run with --skip-deps. For cold pulls or slow external storage, set KP_LOCAL_INFRASTRUCTURE_START_TIMEOUT_SECONDS to at most 3600."

step "waiting for postgres and redis to become healthy"
compose_service_healthy() {
  local output
  output="$(bounded "$DOCKER_TIMEOUT_SECONDS" dc ps "$1" 2>/dev/null)" || return 1
  printf '%s\n' "$output" | grep -q '(healthy)'
}
for _ in $(seq 1 60); do
  if compose_service_healthy postgres && compose_service_healthy redis; then
    break
  fi
  sleep 2
done
compose_service_healthy postgres \
  || die "Postgres did not become healthy; inspect 'docker compose logs postgres' and re-run"
compose_service_healthy redis \
  || die "Redis did not become healthy; inspect 'docker compose logs redis' and re-run"

# --------------------------------------------------------------------------
# 6. Database migrations + demo seed
# --------------------------------------------------------------------------
step "applying database migrations"
"$UV_COMMAND" run --frozen --no-sync alembic -c packages/database/alembic.ini upgrade head \
  || die "database migration failed; correct the reported error and re-run with --skip-deps"

step "verifying and initializing the local audit integrity root"
"$UV_COMMAND" run --frozen --no-sync python scripts/bootstrap_local_audit.py \
  || die "local audit integrity bootstrap failed; preserve the database and reconcile its integrity key in place from protected recovery material, then re-run"

step "seeding demo dataset (idempotent)"
"$UV_COMMAND" run --frozen --no-sync python scripts/seed.py \
  || die "demo seed failed; correct the reported configuration/database error and re-run with --skip-deps"

run_deployment_preflight ready

# --------------------------------------------------------------------------
# 7. macOS launcher app
# --------------------------------------------------------------------------
if [ "$OS" = macos ]; then
  step "building the double-clickable Kingphisher Launcher.app"
  bash scripts/build_launcher_app.sh
else
  ok "Linux: no .app bundle needed; the console is opened in the browser"
fi

# --------------------------------------------------------------------------
# 8. Bring the stack up and open the console
# --------------------------------------------------------------------------
SUPERVISOR_PID=""
if pidfile_is_live "$PROJECT_ROOT/data/run/operator-api.pid"; then
  step "stack already running"
else
  step "starting operator API, tracking API, and worker services"
  nohup "$UV_COMMAND" run --frozen --no-sync python scripts/supervisor.py \
    >/tmp/kingphisher-install.log 2>&1 &
  SUPERVISOR_PID="$!"
  ok "supervisor started after completed recovery gates (log: /tmp/kingphisher-install.log)"
fi

step "waiting for the operator console"
for _ in $(seq 1 90); do
  if curl --max-time 2 -fsS http://127.0.0.1:8000/readyz >/dev/null 2>&1; then
    break
  fi
  if [ -n "$SUPERVISOR_PID" ] && ! kill -0 "$SUPERVISOR_PID" 2>/dev/null; then
    die "local supervisor exited before the console became ready; see /tmp/kingphisher-install.log"
  fi
  sleep 2
done
curl --max-time 2 -fsS http://127.0.0.1:8000/readyz >/dev/null 2>&1 \
  || die "operator API did not become ready; see /tmp/kingphisher-install.log and data/logs/operator-api.log"
pidfile_is_live "$PROJECT_ROOT/data/run/operator-api.pid" \
  || die "operator readiness answered without a live supervised PID; stop the stray process and re-run with --skip-deps"

if command_exists open; then
  open "$CONSOLE_URL" || warn "console is ready; open $CONSOLE_URL in your browser"
else
  ok "console is ready; open $CONSOLE_URL in your browser"
fi

step "installation complete"
cat <<EOF

  Kingphisher-Phoenix is running.

  Operator console : $CONSOLE_URL
  Console sign-in  : use KP_CONSOLE_PASSWORD from .env. The credential is
                     intentionally not printed to logs.

  What's running
    - Postgres :5432, Redis :6379, Mailpit :1025/:8025, mocks :8443/:8181/:8282
    - operator-api :8000, tracking-api :8001
    - supervised worker services
    - otel-collector :4317/:4318

  Useful commands (from the repo root)
    ./scripts/verify_install.sh   # health check for the running system
    make test                     # test suite
    make verify-audit             # audit-chain integrity

  Restarting is GUI-driven: use Settings > Restart in the console.
  Stop the local launcher from the host when you are finished.
EOF

if [ "$OS" = macos ]; then
  cat <<EOF
  You can also quit the terminal and double-click "Kingphisher Launcher.app"
  (next to the repo) to relaunch the stack later.
EOF
fi
