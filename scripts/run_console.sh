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

bootstrap_env() {
  require docker
  require uv

  if [ ! -f "$ENV_FILE" ]; then
    cp .env.example "$ENV_FILE"
  fi

  # Generate secrets once, preserving any value already present in .env.
  if ! grep -q '^OPERATOR_API_AUDIT_HMAC_KEY=' "$ENV_FILE" || [ -z "$(grep '^OPERATOR_API_AUDIT_HMAC_KEY=' "$ENV_FILE" | cut -d= -f2-)" ]; then
    HMAC_KEY="$(openssl rand -hex 32)"
    grep -q '^OPERATOR_API_AUDIT_HMAC_KEY=' "$ENV_FILE" \
      && sed -i '' "s|^OPERATOR_API_AUDIT_HMAC_KEY=.*|OPERATOR_API_AUDIT_HMAC_KEY=$HMAC_KEY|" "$ENV_FILE" \
      || echo "OPERATOR_API_AUDIT_HMAC_KEY=$HMAC_KEY" >> "$ENV_FILE"
  fi
  if ! grep -q '^OPERATOR_API_CIPHERTEXT_KEK=' "$ENV_FILE" || [ -z "$(grep '^OPERATOR_API_CIPHERTEXT_KEK=' "$ENV_FILE" | cut -d= -f2-)" ]; then
    KEK="$(openssl rand -hex 16)"
    grep -q '^OPERATOR_API_CIPHERTEXT_KEK=' "$ENV_FILE" \
      && sed -i '' "s|^OPERATOR_API_CIPHERTEXT_KEK=.*|OPERATOR_API_CIPHERTEXT_KEK=$KEK|" "$ENV_FILE" \
      || echo "OPERATOR_API_CIPHERTEXT_KEK=$KEK" >> "$ENV_FILE"
  fi
  if ! grep -q '^KP_WORKER_AUDIT_HMAC_KEY=' "$ENV_FILE" || [ -z "$(grep '^KP_WORKER_AUDIT_HMAC_KEY=' "$ENV_FILE" | cut -d= -f2-)" ]; then
    echo "KP_WORKER_AUDIT_HMAC_KEY=$(grep '^OPERATOR_API_AUDIT_HMAC_KEY=' "$ENV_FILE" | cut -d= -f2-)" >> "$ENV_FILE"
  fi
  if ! grep -q '^KP_WORKER_CIPHERTEXT_KEK=' "$ENV_FILE" || [ -z "$(grep '^KP_WORKER_CIPHERTEXT_KEK=' "$ENV_FILE" | cut -d= -f2-)" ]; then
    echo "KP_WORKER_CIPHERTEXT_KEK=$(grep '^OPERATOR_API_CIPHERTEXT_KEK=' "$ENV_FILE" | cut -d= -f2-)" >> "$ENV_FILE"
  fi
  if ! grep -q '^KP_CONSOLE_PASSWORD=' "$ENV_FILE" || [ -z "$(grep '^KP_CONSOLE_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)" ]; then
    PASSWORD="$(openssl rand -base64 12 | tr -d '/+=' )"
    grep -q '^KP_CONSOLE_PASSWORD=' "$ENV_FILE" \
      && sed -i '' "s|^KP_CONSOLE_PASSWORD=.*|KP_CONSOLE_PASSWORD=$PASSWORD|" "$ENV_FILE" \
      || echo "KP_CONSOLE_PASSWORD=$PASSWORD" >> "$ENV_FILE"
  fi
}

start_infra() {
  echo "starting infrastructure (postgres, redis, mailpit, mocks)..."
  docker compose up -d postgres redis mailpit otel-collector mock-graph mock-ai mock-idp
  echo "waiting for postgres and redis to be healthy..."
  for _ in $(seq 1 30); do
    if docker compose ps postgres redis | grep -q healthy; then
      break
    fi
    sleep 1
  done
}

init_db() {
  echo "applying database migrations..."
  uv run alembic -c packages/database/alembic.ini upgrade head
  echo "seeding demo dataset (idempotent)..."
  uv run python scripts/seed.py || echo "seed skipped (already present or infra not ready)"
}

ensure_venv() {
  if [ ! -d ".venv" ]; then
    echo "creating project virtualenv..."
    uv sync --all-packages
  fi
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
rm -f "$RUN_DIR/restart" "$RUN_DIR/stop"

# Refuse to double-launch: if the supervisor is already running, just open.
if [ -f "$RUN_DIR/operator-api.pid" ] && kill -0 "$(cat "$RUN_DIR/operator-api.pid")" 2>/dev/null; then
  echo "stack already running; opening console."
  launch_ui
  exit 0
fi

ensure_venv
bootstrap_env
start_infra
init_db

launch_ui
echo "running supervisor; stop or restart the stack from the console."
exec uv run python scripts/supervisor.py
