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
  _generate_if_absent TRACKING_API_CORRECTIONS_SECRET "$(openssl rand -hex 32)"  # corrections bearer secret (WS-9)
  _generate_if_absent MAILPIT_API_PASSWORD "$(openssl rand -base64 18 | tr -d '/+=')"  # Mailpit UI/API auth (WS-16)
  if ! grep -q '^KP_CONSOLE_PASSWORD=' "$ENV_FILE" || [ -z "$(grep '^KP_CONSOLE_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)" ]; then
    PASSWORD="$(openssl rand -base64 12 | tr -d '/+=' )"
    grep -q '^KP_CONSOLE_PASSWORD=' "$ENV_FILE" \
      && sed -i '' "s|^KP_CONSOLE_PASSWORD=.*|KP_CONSOLE_PASSWORD=$PASSWORD|" "$ENV_FILE" \
      || echo "KP_CONSOLE_PASSWORD=$PASSWORD" >> "$ENV_FILE"
  fi
}
