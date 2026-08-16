#!/usr/bin/env bash
# Kingphisher-Phoenix one-shot installer.
#
# Installs every dependency needed for a fresh clone and delivers a fully
# operational local system: infrastructure (Postgres, Redis, Mailpit, mocks),
# a seeded database, the operator/tracking APIs and all eight workers running
# under the supervisor, and (on macOS) the double-clickable
# "Kingphisher Launcher.app". The operator console opens in the browser.
#
# Supported platforms:
#   - macOS (arm64/x86_64): Homebrew, Docker via Colima, uv, Python 3.13
#   - Linux (Debian/Ubuntu): apt, docker.io + compose plugin, uv, Python 3.13
#
# Usage:
#   ./scripts/install.sh            # full install + start
#   ./scripts/install.sh --skip-deps  # re-run provisioning on an existing machine
#
# This script is idempotent: re-running it never breaks a working install.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

CONSOLE_URL="http://127.0.0.1:8000/console"
ENV_FILE="$PROJECT_ROOT/.env"

# shellcheck source=scripts/bootstrap_env.sh
source "$PROJECT_ROOT/scripts/bootstrap_env.sh"
bootstrap_docker_host || true

SKIP_DEPS=0
for arg in "$@"; do
  case "$arg" in
    --skip-deps) SKIP_DEPS=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m    ok:\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m    warn:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

command_exists() { command -v "$1" >/dev/null 2>&1; }

detect_os() {
  case "$(uname -s)" in
    Darwin) echo "macos" ;;
    Linux)  echo "linux" ;;
    *) die "unsupported OS: $(uname -s); this installer targets macOS and Linux" ;;
  esac
}
OS="$(detect_os)"
ARCH="$(uname -m)"

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
if [ "$SKIP_DEPS" -eq 0 ] && ! command_exists uv; then
  step "installing uv"
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
fi
command_exists uv || export PATH="$HOME/.local/bin:$PATH"
command_exists uv || die "uv was installed but is not on PATH; add $HOME/.local/bin to PATH"
uv --version
ok "uv present"

# --------------------------------------------------------------------------
# 3. Docker (CLI + daemon). macOS uses Colima; Linux uses docker.io.
# --------------------------------------------------------------------------
docker_ready() {
  command_exists docker && docker info >/dev/null 2>&1
}

if [ "$SKIP_DEPS" -eq 0 ] && ! docker_ready; then
  case "$OS" in
    macos)
      step "installing Docker via Homebrew + Colima"
      command_exists brew || die "Homebrew is required on macOS; install it first (https://brew.sh)"
      brew install docker docker-compose colima
      step "starting Colima (first start downloads a VM image; can take a few minutes)"
      colima start --cpu 2 --memory 4
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
        $SUDO usermod -aG docker "$USER"
      fi
      ;;
  esac
fi

# If the daemon is reachable only inside the docker group (fresh Linux install),
# wrap docker compose calls so the script still completes without a re-login.
DOCKER_WRAP=""
if ! docker_ready && command_exists sg && id -nG | grep -qw docker; then
  DOCKER_WRAP="sg docker -c"
fi
if ! docker_ready; then
  warn "docker is installed but the daemon is not reachable from this shell."
  warn "On Linux after a fresh docker group add, log out/in (or run: newgrp docker),"
  warn "then re-run: ./scripts/install.sh --skip-deps"
  [ -z "$DOCKER_WRAP" ] && exit 1
fi
docker version --format 'client {{.Client.Version}}' 2>/dev/null || docker --version
ok "docker present"

dc() {
  if [ -n "$DOCKER_WRAP" ]; then
    # shellcheck disable=SC2016
    sg docker -c "docker compose $*"
  else
    docker compose "$@"
  fi
}

# --------------------------------------------------------------------------
# 4. Python environment (uv creates the .venv and installs Python 3.13)
# --------------------------------------------------------------------------
step "creating virtualenv and installing dependencies (uv sync)"
uv sync --all-packages
uv run python --version
ok "project virtualenv ready"

# --------------------------------------------------------------------------
# 5. Local infrastructure
# --------------------------------------------------------------------------
# shellcheck source=scripts/bootstrap_env.sh
source "$PROJECT_ROOT/scripts/bootstrap_env.sh"
bootstrap_env

step "starting infrastructure (postgres, redis, mailpit, mocks)"
bounded 120 dc up -d postgres redis mailpit otel-collector mock-graph mock-ai mock-idp

step "waiting for postgres and redis to become healthy"
for _ in $(seq 1 60); do
  if dc ps postgres redis 2>/dev/null | grep -q healthy; then
    break
  fi
  sleep 2
done
dc ps postgres redis 2>/dev/null | grep -q healthy || die "postgres/redis did not become healthy in time"

# --------------------------------------------------------------------------
# 6. Database migrations + demo seed
# --------------------------------------------------------------------------
step "applying database migrations"
uv run alembic -c packages/database/alembic.ini upgrade head

step "seeding demo dataset (idempotent)"
uv run python scripts/seed.py || warn "seed skipped (already present or not yet ready)"

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
if [ -f data/run/operator-api.pid ] && kill -0 "$(cat data/run/operator-api.pid)" 2>/dev/null; then
  step "stack already running"
else
  step "starting operator API, tracking API, and the eight workers"
  nohup bash scripts/run_console.sh >/tmp/kingphisher-install.log 2>&1 &
  ok "launcher started (log: /tmp/kingphisher-install.log)"
fi

step "waiting for the operator console"
for _ in $(seq 1 90); do
  if curl -fsS http://127.0.0.1:8000/healthz >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
curl -fsS http://127.0.0.1:8000/healthz >/dev/null 2>&1 || die "operator API did not come up; see /tmp/kingphisher-install.log"

PASSWORD=""
if [ -f "$ENV_FILE" ]; then
  PASSWORD="$(grep -E '^KP_CONSOLE_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)"
fi

step "installation complete"
cat <<EOF

  Kingphisher-Phoenix is running.

  Operator console : $CONSOLE_URL
  Console password : ${PASSWORD:-generated on first login (see .env KP_CONSOLE_PASSWORD)}

  What's running
    - Postgres :5432, Redis :6379, Mailpit :1025/:8025, mocks :8443/:8181/:8282
    - operator-api :8000, tracking-api :8001
    - workers: ingestion, generation, delivery, retention, mailbox, reminder, alert, directory
    - otel-collector :4317/:4318

  Useful commands (from the repo root)
    ./scripts/verify_install.sh   # health check for the running system
    make test                     # test suite
    make verify-audit             # audit-chain integrity

  Stopping/restarting is GUI-only: use Settings > Restart / Stop in the console.
EOF

if [ "$OS" = macos ]; then
  cat <<EOF
  You can also quit the terminal and double-click "Kingphisher Launcher.app"
  (next to the repo) to relaunch the stack later.
EOF
fi
