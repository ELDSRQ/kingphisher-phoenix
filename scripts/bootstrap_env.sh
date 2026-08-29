#!/usr/bin/env bash
# Shared env bootstrap for Kingphisher-Phoenix launchers.
#
# Sourced by scripts/run_console.sh and scripts/install.sh. Ensures .env exists
# (copied from .env.example) and generates the local infrastructure credentials
# (Postgres, Redis, audit-writer role) on a proven-clean first bootstrap,
# then rewrites the DSN/REDIS_URL lines to embed them. Never touches a value
# that is already present, so re-runs are idempotent (CRIT-06 / WS-5).

set -euo pipefail

ENV_FILE="${ENV_FILE:-$PROJECT_ROOT/.env}"

_docker_volume_inventory_for_key() {
  local exact_name exact_names labeled_names volume_key="$1"
  case "$volume_key" in
    postgres_data) exact_name="phishing-awareness-platform_postgres_data" ;;
    redis_data) exact_name="phishing-awareness-platform_redis_data" ;;
    *) return 2 ;;
  esac
  if [ -n "${DOCKER_WRAP:-}" ]; then
    labeled_names="$(
      bounded 15 sg docker -c \
        "docker volume ls --filter label=com.docker.compose.volume=${volume_key} --format '{{.Name}}'"
    )" || return 1
    exact_names="$(
      bounded 15 sg docker -c \
        "docker volume ls --filter name=^${exact_name}\$ --format '{{.Name}}'"
    )" || return 1
  else
    labeled_names="$(
      bounded 15 docker volume ls \
        --filter "label=com.docker.compose.volume=${volume_key}" \
        --format '{{.Name}}'
    )" || return 1
    exact_names="$(
      bounded 15 docker volume ls \
        --filter "name=^${exact_name}$" \
        --format '{{.Name}}'
    )" || return 1
  fi
  printf '%s%s' "$labeled_names" "$exact_names"
}

_critical_recovery_keys_missing() {
  local key
  for key in \
    POSTGRES_PASSWORD \
    REDIS_PASSWORD \
    AUDIT_WRITER_PASSWORD \
    OPERATOR_API_AUDIT_HMAC_KEY \
    OPERATOR_API_CIPHERTEXT_KEK \
    OPERATOR_API_CONSOLE_JWT_SECRET \
    OPERATOR_API_RECIPIENT_HASH_SALT \
    OPERATOR_API_ROE_SIGNING_KEY \
    OPERATOR_API_DOMAIN_VERIFY_KEY \
    TRACKING_TOKEN_HMAC_KEY \
    TRAINING_TOKEN_HMAC_KEY \
    MAILPIT_API_PASSWORD \
    KP_WORKER_REPORTED_MAILBOX_BASIC_PASSWORD \
    KP_CONSOLE_PASSWORD; do
    if [ ! -f "$ENV_FILE" ] || [ -z "$(_env_value "$key")" ]; then
      printf '%s\n' "$key"
    fi
  done
}

_validate_recovery_configuration_before_bootstrap() {
  local invalid_keys="" key primary mirror value
  [ -f "$ENV_FILE" ] || return 0

  value="$(_env_value OPERATOR_API_AUDIT_HMAC_KEY)"
  if [ -n "$value" ] && ! [[ "$value" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "error: existing OPERATOR_API_AUDIT_HMAC_KEY is invalid; preserving it because automatic rotation would invalidate audit evidence" >&2
    echo "restore the matching 64-hex key from protected recovery material, then relaunch" >&2
    return 1
  fi
  value="$(_env_value OPERATOR_API_CIPHERTEXT_KEK)"
  if [ -n "$value" ] && ! [[ "$value" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "error: existing OPERATOR_API_CIPHERTEXT_KEK is invalid; preserving it because automatic rotation would make ciphertext unavailable" >&2
    echo "restore the matching 64-hex key from protected recovery material, then relaunch" >&2
    return 1
  fi

  for key in \
    OPERATOR_API_ROE_SIGNING_KEY \
    OPERATOR_API_DOMAIN_VERIFY_KEY \
    TRACKING_TOKEN_HMAC_KEY \
    TRAINING_TOKEN_HMAC_KEY \
    KP_WORKER_AUDIT_HMAC_KEY \
    KP_WORKER_CIPHERTEXT_KEK \
    KP_WORKER_ROE_SIGNING_KEY; do
    value="$(_env_value "$key")"
    if [ -n "$value" ] && ! [[ "$value" =~ ^[0-9a-fA-F]{64}$ ]]; then
      invalid_keys="${invalid_keys}${key}"$'\n'
    fi
  done
  for key in OPERATOR_API_RECIPIENT_HASH_SALT KP_WORKER_RECIPIENT_HASH_SALT; do
    value="$(_env_value "$key")"
    if [ -n "$value" ] \
      && { ! [[ "$value" =~ ^[0-9a-fA-F]+$ ]] \
        || [ "${#value}" -lt 32 ] \
        || [ $(( ${#value} % 2 )) -ne 0 ]; }; then
      invalid_keys="${invalid_keys}${key}"$'\n'
    fi
  done
  value="$(_env_value OPERATOR_API_CONSOLE_JWT_SECRET)"
  if [ -n "$value" ] && [ "${#value}" -lt 32 ]; then
    invalid_keys="${invalid_keys}OPERATOR_API_CONSOLE_JWT_SECRET"$'\n'
  fi

  for primary in \
    OPERATOR_API_AUDIT_HMAC_KEY \
    OPERATOR_API_CIPHERTEXT_KEK \
    OPERATOR_API_RECIPIENT_HASH_SALT \
    OPERATOR_API_ROE_SIGNING_KEY; do
    case "$primary" in
      OPERATOR_API_AUDIT_HMAC_KEY) mirror="KP_WORKER_AUDIT_HMAC_KEY" ;;
      OPERATOR_API_CIPHERTEXT_KEK) mirror="KP_WORKER_CIPHERTEXT_KEK" ;;
      OPERATOR_API_RECIPIENT_HASH_SALT) mirror="KP_WORKER_RECIPIENT_HASH_SALT" ;;
      OPERATOR_API_ROE_SIGNING_KEY) mirror="KP_WORKER_ROE_SIGNING_KEY" ;;
    esac
    if [ -n "$(_env_value "$primary")" ] \
      && [ -n "$(_env_value "$mirror")" ] \
      && [ "$(_env_value "$primary")" != "$(_env_value "$mirror")" ]; then
      invalid_keys="${invalid_keys}${primary}/${mirror} mismatch"$'\n'
    fi
  done

  if [ -n "$invalid_keys" ]; then
    echo "error: existing recovery-sensitive configuration is invalid or internally inconsistent" >&2
    while IFS= read -r key; do
      [ -n "$key" ] && printf 'invalid recovery key: %s\n' "$key" >&2
    done <<< "$invalid_keys"
    echo "restore the matching values from protected recovery material; no configuration or project state was changed" >&2
    return 1
  fi
}

assert_recovery_credentials_before_bootstrap() {
  local missing_key missing_keys postgres_volumes redis_volumes volume_inventory
  missing_keys="$(_critical_recovery_keys_missing)"
  [ -n "$missing_keys" ] || return 0

  command -v docker >/dev/null 2>&1 || {
    echo "error: recovery-sensitive configuration is incomplete and Docker inventory is unavailable; refusing to generate replacement credentials" >&2
    echo "restore .env from protected recovery material or make Docker available for read-only preserved-state inspection" >&2
    return 1
  }
  if ! postgres_volumes="$(_docker_volume_inventory_for_key postgres_data)" \
    || ! redis_volumes="$(_docker_volume_inventory_for_key redis_data)"; then
    echo "error: recovery-sensitive configuration is incomplete and preserved Docker state could not be inspected; refusing to generate replacement credentials" >&2
    echo "restore .env from protected recovery material or restore read-only Docker volume access" >&2
    return 1
  fi
  volume_inventory="${postgres_volumes}${redis_volumes}"
  if [ -n "$volume_inventory" ]; then
    echo "error: preserved PostgreSQL or Redis volumes exist while recovery-sensitive configuration is incomplete" >&2
    echo "restore the missing keys in .env from protected recovery material; no credentials, volumes, or services were changed" >&2
    while IFS= read -r missing_key; do
      [ -n "$missing_key" ] && printf 'missing recovery key: %s\n' "$missing_key" >&2
    done <<< "$missing_keys"
    return 1
  fi
}

ensure_env_file() {
  if [ ! -f "$ENV_FILE" ]; then
    cp "$PROJECT_ROOT/.env.example" "$ENV_FILE"
    chmod 600 "$ENV_FILE"
  fi
}

_env_value() {
  local key="$1"
  awk -v key="$key" '
    index($0, key "=") == 1 {
      print substr($0, length(key) + 2)
      exit
    }
  ' "$ENV_FILE"
}

# Replace a key through a same-directory temporary file.  Unlike `sed -i`,
# this is portable across the BSD tools shipped by macOS and GNU/Linux.  The
# existing file mode is retained by copying it onto the temporary inode before
# rewriting it, then the completed file is atomically renamed into place.
_write_env_line() {
  local key="$1" value="$2" temporary
  case "$key" in
    ''|*[!A-Za-z0-9_]*)
      echo "invalid environment key: $key" >&2
      return 2
      ;;
  esac
  temporary="$(mktemp "${ENV_FILE}.tmp.XXXXXX")"
  if ! cp -p "$ENV_FILE" "$temporary"; then
    rm -f "$temporary"
    return 1
  fi
  if ! awk -v key="$key" -v value="$value" '
    index($0, key "=") == 1 {
      if (!found) {
        print key "=" value
        found = 1
      }
      next
    }
    { print }
    END {
      if (!found) {
        print key "=" value
      }
    }
  ' "$ENV_FILE" > "$temporary"; then
    rm -f "$temporary"
    return 1
  fi
  if ! mv -f "$temporary" "$ENV_FILE"; then
    rm -f "$temporary"
    return 1
  fi
}

_generate_if_absent() {
  local key="$1" value="$2"
  if [ -z "$(_env_value "$key")" ]; then
    _write_env_line "$key" "$value"
  fi
}

_set_line() {
  local key="$1" value="$2"
  _write_env_line "$key" "$value"
}

_env_value_is_literal() {
  local expected="$2" value
  value="$(_env_value "$1")"
  [ "$value" = "$expected" ] \
    || [ "$value" = "'$expected'" ] \
    || [ "$value" = "\"$expected\"" ]
}

_env_value_is_blank() {
  local value
  value="$(_env_value "$1")"
  [ -z "$value" ] || [ "$value" = "''" ] || [ "$value" = '""' ]
}

# Older Compose-hosted local installs saved the Docker DNS name for Mailpit.
# The application processes now run under the host supervisor, where that name
# does not resolve. Migrate only the exact legacy aliases when the rest of the
# saved configuration proves this is the local development Mailpit path. Any
# managed runtime, OIDC deployment, alternate provider, or custom destination
# remains byte-for-byte untouched.
_migrate_legacy_local_mailpit_aliases() {
  _env_value_is_literal OPERATOR_API_DEPLOYMENT_MODE "single_tenant" || return 0
  _env_value_is_literal OPERATOR_API_OIDC_MODE "dev" || return 0

  # Either runtime spelling may remain in a restored file. Fail closed on an
  # unknown or managed value even if the other alias says development.
  if ! _env_value_is_blank KP_WORKER_RUNTIME_MODE \
    && ! _env_value_is_literal KP_WORKER_RUNTIME_MODE "development"; then
    return 0
  fi
  if ! _env_value_is_blank KP_WORKER_DEPLOYMENT_MODE \
    && ! _env_value_is_literal KP_WORKER_DEPLOYMENT_MODE "development"; then
    return 0
  fi

  if { _env_value_is_blank KP_WORKER_EMAIL_PROVIDER \
      || _env_value_is_literal KP_WORKER_EMAIL_PROVIDER "smtp"; } \
    && { _env_value_is_blank KP_WORKER_SMTP_ADDRESS \
      || _env_value_is_literal KP_WORKER_SMTP_ADDRESS "localhost:1025"; } \
    && _env_value_is_literal KP_WORKER_MAILPIT_SMTP "mailpit:1025"; then
    _set_line KP_WORKER_MAILPIT_SMTP "localhost:1025"
  fi
  # A saved preferred localhost value is redundant with the canonical local
  # fallback, but changes the destination key selected by onboarding. Clear
  # only this exact duplicate so the reviewed Mailpit loopback exception is
  # used; custom SMTP destinations remain authoritative.
  if { _env_value_is_blank KP_WORKER_EMAIL_PROVIDER \
      || _env_value_is_literal KP_WORKER_EMAIL_PROVIDER "smtp"; } \
    && _env_value_is_literal KP_WORKER_MAILPIT_SMTP "localhost:1025" \
    && _env_value_is_literal KP_WORKER_SMTP_ADDRESS "localhost:1025"; then
    _set_line KP_WORKER_SMTP_ADDRESS ""
  fi

  if ! _env_value_is_blank KP_WORKER_REPORTED_MAILBOX_PROVIDER \
    && ! _env_value_is_literal KP_WORKER_REPORTED_MAILBOX_PROVIDER "mailpit"; then
    return 0
  fi

  # A preferred custom mailbox URL makes the fallback irrelevant and is
  # operator-owned, so retain both values. Otherwise normalize the exact
  # legacy fallback and clear the exact legacy preferred alias to use it.
  if _env_value_is_literal KP_WORKER_MAILPIT_API_URL "http://mailpit:8025" \
    && { _env_value_is_blank KP_WORKER_REPORTED_MAILBOX_URL \
      || _env_value_is_literal KP_WORKER_REPORTED_MAILBOX_URL "http://mailpit:8025" \
      || _env_value_is_literal KP_WORKER_REPORTED_MAILBOX_URL "http://localhost:8025"; }; then
    _set_line KP_WORKER_MAILPIT_API_URL "http://localhost:8025"
  fi
  if _env_value_is_literal KP_WORKER_REPORTED_MAILBOX_URL "http://mailpit:8025" \
    && { _env_value_is_blank KP_WORKER_MAILPIT_API_URL \
      || _env_value_is_literal KP_WORKER_MAILPIT_API_URL "http://mailpit:8025" \
      || _env_value_is_literal KP_WORKER_MAILPIT_API_URL "http://localhost:8025"; }; then
    _set_line KP_WORKER_REPORTED_MAILBOX_URL ""
  fi
}

bootstrap_env() {
  _validate_recovery_configuration_before_bootstrap
  assert_recovery_credentials_before_bootstrap
  ensure_env_file
  _migrate_legacy_local_mailpit_aliases

  # Infrastructure credentials (rotated once, then preserved).
  _generate_if_absent POSTGRES_PASSWORD "$(openssl rand -hex 16)"
  _generate_if_absent REDIS_PASSWORD "$(openssl rand -hex 16)"
  _generate_if_absent AUDIT_WRITER_PASSWORD "$(openssl rand -hex 16)"
  # Existing values are preservation-required. Never delete/recreate the data
  # volume to make edited credentials take effect: PostgreSQL initialization
  # runs only on an empty directory and doing so would destroy project state.
  # A credential mismatch therefore fails during readiness/migration and must
  # be reconciled in place by an authorized operator with a verified backup.

  # Re-embed the passwords into the connection strings so every consumer
  # (alembic, apps, seed/verify scripts) connects with the rotated creds.
  POSTGRES_PASSWORD="$(_env_value POSTGRES_PASSWORD)"
  REDIS_PASSWORD="$(_env_value REDIS_PASSWORD)"
  AUDIT_WRITER_PASSWORD="$(_env_value AUDIT_WRITER_PASSWORD)"

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
  # KEK/HMAC must be 256-bit hex (64 chars). Generate them only when absent.
  # An existing malformed or legacy value must fail closed: silently replacing
  # it can make recipient ciphertext or the audit chain unverifiable.
  HMAC_KEY="$(_env_value OPERATOR_API_AUDIT_HMAC_KEY)"
  if [ -z "$HMAC_KEY" ]; then
    HMAC_KEY="$(openssl rand -hex 32)"
    _set_line OPERATOR_API_AUDIT_HMAC_KEY "$HMAC_KEY"
  elif ! [[ "$HMAC_KEY" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "error: existing OPERATOR_API_AUDIT_HMAC_KEY is invalid; preserving it because automatic rotation would invalidate audit evidence" >&2
    echo "restore the matching 64-hex key from protected recovery material, then relaunch" >&2
    return 1
  fi
  KEK="$(_env_value OPERATOR_API_CIPHERTEXT_KEK)"
  if [ -z "$KEK" ]; then
    KEK="$(openssl rand -hex 32)"  # 256-bit KEK (HIGH-18 / WS-11)
    _set_line OPERATOR_API_CIPHERTEXT_KEK "$KEK"
  elif ! [[ "$KEK" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "error: existing OPERATOR_API_CIPHERTEXT_KEK is invalid; preserving it because automatic rotation would make ciphertext unavailable" >&2
    echo "restore the matching 64-hex key from protected recovery material, then relaunch" >&2
    return 1
  fi
  if [ -z "$(_env_value KP_WORKER_AUDIT_HMAC_KEY)" ]; then
    _set_line KP_WORKER_AUDIT_HMAC_KEY "$(_env_value OPERATOR_API_AUDIT_HMAC_KEY)"
  fi
  if [ -z "$(_env_value KP_WORKER_CIPHERTEXT_KEK)" ]; then
    _set_line KP_WORKER_CIPHERTEXT_KEK "$(_env_value OPERATOR_API_CIPHERTEXT_KEK)"
  fi
  if [ -z "$(_env_value OPERATOR_API_CONSOLE_JWT_SECRET)" ]; then
    JWT_SECRET="$(openssl rand -hex 32)"
    _set_line OPERATOR_API_CONSOLE_JWT_SECRET "$JWT_SECRET"
  fi
  _generate_if_absent OPERATOR_API_RECIPIENT_HASH_SALT "$(openssl rand -hex 32)"  # mailbox_sha256 salt (WS-12)
  if [ -z "$(_env_value KP_WORKER_RECIPIENT_HASH_SALT)" ]; then
    _set_line KP_WORKER_RECIPIENT_HASH_SALT "$(_env_value OPERATOR_API_RECIPIENT_HASH_SALT)"
  fi
  # Rules-of-Engagement signing key: shared by the operator API (signing) and
  # the delivery workers (verification), so a campaign scheduled under a
  # signed RoE is verifiable where it is delivered.
  ROE_KEY="$(openssl rand -hex 32)"
  _generate_if_absent OPERATOR_API_ROE_SIGNING_KEY "$ROE_KEY"
  if [ -z "$(_env_value KP_WORKER_ROE_SIGNING_KEY)" ]; then
    _set_line KP_WORKER_ROE_SIGNING_KEY "$(_env_value OPERATOR_API_ROE_SIGNING_KEY)"
  fi
  # DNS-challenge verification key (operator API only): distinct from the RoE
  # key so a leaked challenge token can never forge an authorization.
  _generate_if_absent OPERATOR_API_DOMAIN_VERIFY_KEY "$(openssl rand -hex 32)"
  # Tracking and training bearers cross service boundaries, but their keys are
  # deliberately distinct so compromise of one token class cannot forge the
  # other.  The generic names are consumed by operator, tracking, and workers.
  _generate_if_absent TRACKING_TOKEN_HMAC_KEY "$(openssl rand -hex 32)"
  _generate_if_absent TRAINING_TOKEN_HMAC_KEY "$(openssl rand -hex 32)"
  _generate_if_absent MAILPIT_API_PASSWORD "$(openssl rand -base64 18 | tr -d '/+=')"  # Mailpit UI/API auth (WS-16)
  _generate_if_absent KP_WORKER_REPORTED_MAILBOX_BASIC_USERNAME "admin"
  if [ -z "$(_env_value KP_WORKER_REPORTED_MAILBOX_BASIC_PASSWORD)" ]; then
    _set_line KP_WORKER_REPORTED_MAILBOX_BASIC_PASSWORD "$(_env_value MAILPIT_API_PASSWORD)"
  fi
  if [ -z "$(_env_value KP_CONSOLE_PASSWORD)" ]; then
    PASSWORD="$(openssl rand -base64 12 | tr -d '/+=' )"
    _set_line KP_CONSOLE_PASSWORD "$PASSWORD"
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
      echo "command timed out after ${secs}s: $*" >&2
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

bounded_seconds_are_valid() {
  local value="$1" maximum="$2"
  [[ "$value" =~ ^[1-9][0-9]*$ ]] \
    && [ "${#value}" -le 6 ] \
    && (( 10#$value <= 10#$maximum ))
}

# A pidfile is evidence only when it contains one positive integer and that
# process is currently signalable by this user.  Stale, blank, or malformed
# files must never make an installer or launcher report that the stack runs.
pidfile_is_live() {
  local pidfile="$1" pid
  [ -f "$pidfile" ] || return 1
  # `read` returns non-zero at EOF when a legacy PID file has no trailing
  # newline even though it populated the value.  Accept that format so an
  # upgrade cannot mistake a live supervisor for a stale process and launch a
  # duplicate stack.
  IFS= read -r pid < "$pidfile" || [ -n "$pid" ] || return 1
  case "$pid" in
    ''|*[!0-9]*) return 1 ;;
  esac
  [ "$pid" -gt 0 ] 2>/dev/null || return 1
  kill -0 "$pid" 2>/dev/null
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
  # An explicit host is operator authority and must be verified by the caller;
  # never silently redirect it to a different daemon during recovery.
  if [ "${DOCKER_HOST:-}" != "" ]; then
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
