#!/usr/bin/env bash
# Shared env bootstrap for Kingphisher-Phoenix launchers.
#
# Sourced by scripts/run_console.sh and scripts/install.sh. Ensures .env exists
# (copied from .env.example) and rotates the local infrastructure credentials
# (Postgres, Redis, audit-writer role) to random values on first bootstrap,
# then rewrites the DSN/REDIS_URL lines to embed them. Never touches a value
# that is already present, so re-runs are idempotent (CRIT-06 / WS-5).

set -euo pipefail

ENV_FILE="${ENV_FILE:-$PROJECT_ROOT/.env}"

ensure_env_file() {
  if [ ! -f "$ENV_FILE" ]; then
    cp .env.example "$ENV_FILE"
  fi
}

_generate_if_absent() {
  local key="$1" value="$2"
  if ! grep -q "^${key}=" "$ENV_FILE" || [ -z "$(grep "^${key}=" "$ENV_FILE" | cut -d= -f2-)" ]; then
    grep -q "^${key}=" "$ENV_FILE" \
      && sed -i '' "s|^${key}=.*|${key}=${value}|" "$ENV_FILE" \
      || echo "${key}=${value}" >> "$ENV_FILE"
  fi
}

_set_line() {
  local key="$1" value="$2"
  grep -q "^${key}=" "$ENV_FILE" \
    && sed -i '' "s|^${key}=.*|${key}=${value}|" "$ENV_FILE" \
    || echo "${key}=${value}" >> "$ENV_FILE"
}

bootstrap_env() {
  ensure_env_file

  # Infrastructure credentials (rotated once, then preserved).
  _generate_if_absent POSTGRES_PASSWORD "$(openssl rand -hex 16)"
  _generate_if_absent REDIS_PASSWORD "$(openssl rand -hex 16)"
  _generate_if_absent AUDIT_WRITER_PASSWORD "$(openssl rand -hex 16)"
  # NOTE: on an existing stack with a pre-rotation postgres_data volume, run
  # `docker compose down -v && docker compose up -d` once so the new passwords
  # take effect (initdb runs only on an empty data dir).

  # Re-embed the passwords into the connection strings so every consumer
  # (alembic, apps, seed/verify scripts) connects with the rotated creds.
  POSTGRES_PASSWORD="$(grep '^POSTGRES_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)"
  REDIS_PASSWORD="$(grep '^REDIS_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)"
  AUDIT_WRITER_PASSWORD="$(grep '^AUDIT_WRITER_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)"

  _set_line DATABASE_URL "postgresql+psycopg://kingphisher:${POSTGRES_PASSWORD}@localhost:5432/kingphisher"
  _set_line DATABASE_URL_TEST "postgresql+psycopg://kingphisher:${POSTGRES_PASSWORD}@localhost:5432/kingphisher_test"
  _set_line AUDIT_DATABASE_URL "postgresql+psycopg://audit_writer:${AUDIT_WRITER_PASSWORD}@localhost:5432/kingphisher"
  _set_line REDIS_URL "redis://:${REDIS_PASSWORD}@localhost:6379/0"

  # The apps read prefixed env names (pydantic-settings env_prefix). Mirror the
  # rotated DSNs into them so the operator/tracking APIs and workers actually
  # connect with the new credentials instead of the compiled-in defaults.
  _set_line OPERATOR_API_DATABASE_URL "postgresql+psycopg://kingphisher:${POSTGRES_PASSWORD}@localhost:5432/kingphisher"
  _set_line OPERATOR_API_AUDIT_DATABASE_URL "postgresql+psycopg://audit_writer:${AUDIT_WRITER_PASSWORD}@localhost:5432/kingphisher"
  _set_line OPERATOR_API_REDIS_URL "redis://:${REDIS_PASSWORD}@localhost:6379/0"
  _set_line KP_WORKER_DATABASE_URL "postgresql+psycopg://kingphisher:${POSTGRES_PASSWORD}@localhost:5432/kingphisher"
  _set_line KP_WORKER_AUDIT_DATABASE_URL "postgresql+psycopg://audit_writer:${AUDIT_WRITER_PASSWORD}@localhost:5432/kingphisher"
  _set_line KP_WORKER_REDIS_URL "redis://:${REDIS_PASSWORD}@localhost:6379/0"
  _set_line TRACKING_API_DATABASE_URL "postgresql+psycopg://kingphisher:${POSTGRES_PASSWORD}@localhost:5432/kingphisher"

  # Keep local authentication and deployment topology explicit. Production
  # operators switch OIDC_MODE and configure their provider values directly.
  _set_line OPERATOR_API_DEPLOYMENT_MODE "single_tenant"
  _generate_if_absent OPERATOR_API_OIDC_MODE "dev"
  _generate_if_absent OPERATOR_API_OIDC_CLIENT_ID "kp-operator-console"
  _generate_if_absent OPERATOR_API_OIDC_REDIRECT_URI "http://localhost:8000/api/v1/console/oidc/callback"
  _generate_if_absent OPERATOR_API_OIDC_SCOPES "openid profile"
  _generate_if_absent KP_WORKER_MAILPIT_SMTP "localhost:1025"
  _generate_if_absent KP_WORKER_MAILPIT_API_URL "http://localhost:8025"

  # Generate secrets once, preserving any value already present in .env.
  # KEK/HMAC must be 256-bit hex (64 chars) — a legacy 128-bit value is
  # rotated, since CipherText/AuditStore now reject it (WS-11 / HIGH-18).
  # NOTE: rotating the KEK invalidates recipient ciphertext written under the
  # old key; combine with a dev-DB recreate (`docker compose down -v`) as with
  # the password rotation above.
  HMAC_KEY="$(grep '^OPERATOR_API_AUDIT_HMAC_KEY=' "$ENV_FILE" | cut -d= -f2-)"
  if [ -z "$HMAC_KEY" ] || ! [[ "$HMAC_KEY" =~ ^[0-9a-fA-F]{64}$ ]]; then
    HMAC_KEY="$(openssl rand -hex 32)"
    _set_line OPERATOR_API_AUDIT_HMAC_KEY "$HMAC_KEY"
  fi
  KEK="$(grep '^OPERATOR_API_CIPHERTEXT_KEK=' "$ENV_FILE" | cut -d= -f2-)"
  if [ -z "$KEK" ] || ! [[ "$KEK" =~ ^[0-9a-fA-F]{64}$ ]]; then
    KEK="$(openssl rand -hex 32)"  # 256-bit KEK (HIGH-18 / WS-11)
    _set_line OPERATOR_API_CIPHERTEXT_KEK "$KEK"
  fi
  if ! grep -q '^KP_WORKER_AUDIT_HMAC_KEY=' "$ENV_FILE" || [ -z "$(grep '^KP_WORKER_AUDIT_HMAC_KEY=' "$ENV_FILE" | cut -d= -f2-)" ]; then
    echo "KP_WORKER_AUDIT_HMAC_KEY=$(grep '^OPERATOR_API_AUDIT_HMAC_KEY=' "$ENV_FILE" | cut -d= -f2-)" >> "$ENV_FILE"
  fi
  if ! grep -q '^KP_WORKER_CIPHERTEXT_KEK=' "$ENV_FILE" || [ -z "$(grep '^KP_WORKER_CIPHERTEXT_KEK=' "$ENV_FILE" | cut -d= -f2-)" ]; then
    echo "KP_WORKER_CIPHERTEXT_KEK=$(grep '^OPERATOR_API_CIPHERTEXT_KEK=' "$ENV_FILE" | cut -d= -f2-)" >> "$ENV_FILE"
  fi
  if ! grep -q '^OPERATOR_API_CONSOLE_JWT_SECRET=' "$ENV_FILE" || [ -z "$(grep '^OPERATOR_API_CONSOLE_JWT_SECRET=' "$ENV_FILE" | cut -d= -f2-)" ]; then
    JWT_SECRET="$(openssl rand -hex 32)"
    _set_line OPERATOR_API_CONSOLE_JWT_SECRET "$JWT_SECRET"
  fi
  _generate_if_absent OPERATOR_API_RECIPIENT_HASH_SALT "$(openssl rand -hex 32)"  # mailbox_sha256 salt (WS-12)
  if ! grep -q '^KP_WORKER_RECIPIENT_HASH_SALT=' "$ENV_FILE" || [ -z "$(grep '^KP_WORKER_RECIPIENT_HASH_SALT=' "$ENV_FILE" | cut -d= -f2-)" ]; then
    _set_line KP_WORKER_RECIPIENT_HASH_SALT "$(grep '^OPERATOR_API_RECIPIENT_HASH_SALT=' "$ENV_FILE" | cut -d= -f2-)"
  fi
  # Rules-of-Engagement signing key: shared by the operator API (signing) and
  # the delivery workers (verification), so a campaign scheduled under a
  # signed RoE is verifiable where it is delivered.
  ROE_KEY="$(openssl rand -hex 32)"
  _generate_if_absent OPERATOR_API_ROE_SIGNING_KEY "$ROE_KEY"
  if ! grep -q '^KP_WORKER_ROE_SIGNING_KEY=' "$ENV_FILE" || [ -z "$(grep '^KP_WORKER_ROE_SIGNING_KEY=' "$ENV_FILE" | cut -d= -f2-)" ]; then
    _set_line KP_WORKER_ROE_SIGNING_KEY "$(grep '^OPERATOR_API_ROE_SIGNING_KEY=' "$ENV_FILE" | cut -d= -f2-)"
  fi
  # DNS-challenge verification key (operator API only): distinct from the RoE
  # key so a leaked challenge token can never forge an authorization.
  _generate_if_absent OPERATOR_API_DOMAIN_VERIFY_KEY "$(openssl rand -hex 32)"
  _generate_if_absent TRACKING_API_CORRECTIONS_SECRET "$(openssl rand -hex 32)"  # corrections bearer secret (WS-9)
  _generate_if_absent MAILPIT_API_PASSWORD "$(openssl rand -base64 18 | tr -d '/+=')"  # Mailpit UI/API auth (WS-16)
  _generate_if_absent KP_WORKER_REPORTED_MAILBOX_BASIC_USERNAME "admin"
  if ! grep -q '^KP_WORKER_REPORTED_MAILBOX_BASIC_PASSWORD=' "$ENV_FILE" || [ -z "$(grep '^KP_WORKER_REPORTED_MAILBOX_BASIC_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)" ]; then
    _set_line KP_WORKER_REPORTED_MAILBOX_BASIC_PASSWORD "$(grep '^MAILPIT_API_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)"
  fi
  if ! grep -q '^KP_CONSOLE_PASSWORD=' "$ENV_FILE" || [ -z "$(grep '^KP_CONSOLE_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)" ]; then
    PASSWORD="$(openssl rand -base64 12 | tr -d '/+=' )"
    grep -q '^KP_CONSOLE_PASSWORD=' "$ENV_FILE" \
      && sed -i '' "s|^KP_CONSOLE_PASSWORD=.*|KP_CONSOLE_PASSWORD=$PASSWORD|" "$ENV_FILE" \
      || echo "KP_CONSOLE_PASSWORD=$PASSWORD" >> "$ENV_FILE"
  fi
}

# Run a command under a hard wall-clock bound (macOS has no `timeout(1)`).
# Docker Desktop's compose client can linger after completing `up -d`
# (recreate done, client never exits); bounding it keeps launchers moving,
# and callers re-verify actual state afterwards with docker compose ps.
bounded() {
  local secs="$1"
  shift
  "$@" &
  local pid=$!
  local i=0
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$i" -ge "$secs" ]; then
      echo "command exceeded ${secs}s bound; continuing: $*" >&2
      kill "$pid" 2>/dev/null
      wait "$pid" 2>/dev/null
      return 124
    fi
    sleep 1
    i=$((i + 1))
  done
  wait "$pid"
  return $?
}

# Workaround for a wedged Docker CLI on macOS (Docker Desktop): after a Desktop
# restart the default engine proxy socket (~/.docker/run/docker.sock) can accept
# connections but never answer, so every `docker` command hangs indefinitely.
# The engine itself is usually fine on docker.raw.sock. This resolver probes the
# live engine sockets directly with curl (bounded, never invokes the hung CLI)
# and exports DOCKER_HOST so launchers/installers avoid the stall.
_boot_socket_probe() {
  [ -S "$1" ] || return 1
  [ "$(curl -s --max-time 2 --unix-socket "$1" http://localhost/_ping 2>/dev/null)" = "OK" ]
}

bootstrap_docker_host() {
  if [ "${DOCKER_HOST:-}" != "" ] && _boot_socket_probe "${DOCKER_HOST#unix://}"; then
    return 0
  fi
  local cand
  for cand in \
    "$HOME/Library/Containers/com.docker.docker/Data/docker.raw.sock" \
    "$HOME/Library/Containers/com.docker.docker/Data/docker-cli.sock" \
    "$HOME/Library/Containers/com.docker.docker/Data/backend.sock"; do
    if _boot_socket_probe "$cand"; then
      export DOCKER_HOST="unix://$cand"
      echo "docker: default CLI socket is not responding; using engine socket $DOCKER_HOST"
      return 0
    fi
  done
  return 1
}
