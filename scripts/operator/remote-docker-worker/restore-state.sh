#!/usr/bin/env bash
# Restore a reviewed project snapshot into a clean Docker engine.
#
# This script deliberately supports only a clean target. It never replaces,
# removes, or reuses an existing project container or named volume.

set -euo pipefail

KP_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
KP_POSTGRES_DUMP="$KP_ROOT/migration-checkpoint/postgres.dump"
KP_REDIS_RDB="$KP_ROOT/migration-checkpoint/redis.rdb"
KP_POSTGRES_CONTAINER=phishing-awareness-platform-postgres-1
KP_REDIS_CONTAINER=phishing-awareness-platform-redis-1
KP_POSTGRES_VOLUME=phishing-awareness-platform_postgres_data
KP_REDIS_VOLUME=phishing-awareness-platform_redis_data
KP_POSTGRES_IMAGE='postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777'
KP_REDIS_IMAGE='redis:7-alpine@sha256:e7723ff73d963f5cc6d9c4643ea3d989527a402a319239054e9472a7fb9219a2'
KP_EXTERNAL_ENGINE="$KP_ROOT/scripts/operator/remote-docker-worker/external-engine.sh"
KP_EXPECTED_DOCKER_HOST='unix:///Volumes/DockerExternal/KingPhisher-Phoenix/colima/kingphisher/docker.sock'
KP_EXPECTED_DOCKER_CONFIG='/Volumes/DockerExternal/KingPhisher-Phoenix/docker-client'
KP_PROJECT_NAME=phishing-awareness-platform
KP_APPLY=0

case "${1:-}" in
  '') ;;
  --apply) KP_APPLY=1 ;;
  *) printf 'usage: %s [--apply]\n' "$0" >&2; exit 2 ;;
esac

fail() {
  printf 'RESTORE BLOCKED: %s\n' "$*" >&2
  printf 'Preserve the source archives and any partial project state; do not prune, remove, or recreate volumes.\n' >&2
  exit 1
}

require_external_engine_invocation() {
  [ -x "$KP_EXTERNAL_ENGINE" ] && [ ! -L "$KP_EXTERNAL_ENGINE" ] \
    || fail "the checked-in external-engine helper is absent, non-executable, or symbolic"
  [ "${DOCKER_HOST:-}" = "$KP_EXPECTED_DOCKER_HOST" ] \
    || fail "restore must be launched through external-engine.sh run; ambient Docker is prohibited"
  [ "${DOCKER_CONFIG:-}" = "$KP_EXPECTED_DOCKER_CONFIG" ] \
    || fail "restore Docker client configuration is not bound to the external volume"
  [ "${COMPOSE_PROJECT_NAME:-}" = "$KP_PROJECT_NAME" ] \
    || fail "restore Compose project identity is not exact"
  [ -z "${DOCKER_CONTEXT:-}" ] \
    || fail "DOCKER_CONTEXT must be unset so legacy contexts cannot override the external socket"
  "$KP_EXTERNAL_ENGINE" preflight >/dev/null \
    || fail "the project-isolated external engine did not pass preflight"
  KP_ENGINE_IDENTITY="$(docker info --format '{{.Name}}|{{.Architecture}}|{{.DockerRootDir}}')"
  [ "$KP_ENGINE_IDENTITY" = 'colima-kingphisher|aarch64|/var/lib/docker' ] \
    || fail "restore target is not the exact native external engine: $KP_ENGINE_IDENTITY"
}

cd "$KP_ROOT"
require_external_engine_invocation
[ -s "$KP_POSTGRES_DUMP" ] || fail "PostgreSQL archive is missing or empty"
[ -s "$KP_REDIS_RDB" ] || fail "Redis RDB is missing or empty"
docker compose config >/dev/null || fail "Compose configuration is invalid"

KP_EXISTING_PROJECT_CONTAINERS="$(docker ps -aq \
  --filter "label=com.docker.compose.project=$KP_PROJECT_NAME")"
[ -z "$KP_EXISTING_PROJECT_CONTAINERS" ] \
  || fail "target engine already contains Compose project containers"
KP_EXISTING_PROJECT_VOLUMES="$(docker volume ls -q \
  --filter "label=com.docker.compose.project=$KP_PROJECT_NAME")"
[ -z "$KP_EXISTING_PROJECT_VOLUMES" ] \
  || fail "target engine already contains Compose project volumes"
KP_EXISTING_PROJECT_NETWORKS="$(docker network ls -q \
  --filter "label=com.docker.compose.project=$KP_PROJECT_NAME")"
[ -z "$KP_EXISTING_PROJECT_NETWORKS" ] \
  || fail "target engine already contains Compose project networks"

for KP_NAME in "$KP_POSTGRES_CONTAINER" "$KP_REDIS_CONTAINER"; do
  [ -z "$(docker ps -a --filter "name=^/${KP_NAME}$" -q)" ] \
    || fail "target container already exists: $KP_NAME"
done
for KP_NAME in "$KP_POSTGRES_VOLUME" "$KP_REDIS_VOLUME"; do
  ! docker volume inspect "$KP_NAME" >/dev/null 2>&1 \
    || fail "target volume already exists: $KP_NAME"
done

scripts/operator/deployment-preflight/run.sh \
  --root "$KP_ROOT" \
  --phase prestart \
  --minimum-free-gib "${KP_REMOTE_MIN_FREE_GIB:-100}" \
  --timeout-seconds 15

if [ "$KP_APPLY" -ne 1 ]; then
  printf 'RESTORE PREFLIGHT PASSED: clean target and source archives are present.\n'
  printf 'Re-run with --apply to create only the two fixed project volumes and restore them.\n'
  exit 0
fi

scripts/operator/base-image-qualification/run.sh --timeout-seconds 300

KP_RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
KP_RDB_DIR="$(cd "$(dirname "$KP_REDIS_RDB")" && pwd)"
KP_RDB_NAME="$(basename "$KP_REDIS_RDB")"
KP_VERIFY_DB="kp_restore_verify_${KP_RUN_ID//[^0-9A-Za-z]/_}"
KP_MATERIALIZER="kp-redis-restore-materialize-$KP_RUN_ID"

docker run --rm \
  --name "kp-postgres-archive-check-$KP_RUN_ID" \
  --pull never \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev \
  --entrypoint pg_restore \
  -i "$KP_POSTGRES_IMAGE" --list < "$KP_POSTGRES_DUMP" >/dev/null

docker run --rm \
  --name "kp-redis-rdb-check-$KP_RUN_ID" \
  --pull never \
  --network none \
  --read-only \
  --user 999:999 \
  --volume "$KP_RDB_DIR:/backup:ro" \
  --entrypoint redis-check-rdb \
  "$KP_REDIS_IMAGE" "/backup/$KP_RDB_NAME" >/dev/null

docker compose up -d --no-recreate postgres
for _ in $(seq 1 60); do
  docker exec "$KP_POSTGRES_CONTAINER" pg_isready -U kingphisher -d kingphisher >/dev/null 2>&1 && break
  sleep 2
done
docker exec "$KP_POSTGRES_CONTAINER" pg_isready -U kingphisher -d kingphisher >/dev/null \
  || fail "PostgreSQL did not become ready"

# A host bind mount may be non-executable. The same reviewed initializer remains
# safe to invoke through the image shell.
if ! docker exec "$KP_POSTGRES_CONTAINER" psql -U kingphisher -d kingphisher -Atc \
  "select 1 from pg_roles where rolname = 'audit_writer';" | grep -qx 1; then
  docker exec "$KP_POSTGRES_CONTAINER" /bin/sh /docker-entrypoint-initdb.d/001-roles.sh
fi
docker exec "$KP_POSTGRES_CONTAINER" psql -U kingphisher -d kingphisher -Atc \
  "select 1 from pg_roles where rolname = 'audit_writer';" | grep -qx 1 \
  || fail "required audit_writer role is absent"

docker exec "$KP_POSTGRES_CONTAINER" createdb -U kingphisher "$KP_VERIFY_DB"
docker exec -i "$KP_POSTGRES_CONTAINER" pg_restore \
  -U kingphisher -d "$KP_VERIFY_DB" --exit-on-error --single-transaction < "$KP_POSTGRES_DUMP"
KP_VERIFY_TABLES="$(docker exec "$KP_POSTGRES_CONTAINER" psql -U kingphisher -d "$KP_VERIFY_DB" -Atc \
  "select count(*) from pg_tables where schemaname = 'public';")"
[ "$KP_VERIFY_TABLES" -gt 0 ] || fail "disposable PostgreSQL restore contained no public tables"
docker exec "$KP_POSTGRES_CONTAINER" dropdb -U kingphisher --force "$KP_VERIFY_DB"

KP_TARGET_TABLES="$(docker exec "$KP_POSTGRES_CONTAINER" psql -U kingphisher -d kingphisher -Atc \
  "select count(*) from pg_tables where schemaname = 'public';")"
[ "$KP_TARGET_TABLES" -eq 0 ] || fail "fresh target database is not empty"
docker exec -i "$KP_POSTGRES_CONTAINER" pg_restore \
  -U kingphisher -d kingphisher --exit-on-error --single-transaction < "$KP_POSTGRES_DUMP"

# Create but never start the normal Redis container before materializing AOF.
# Starting with AOF enabled would create an empty AOF that supersedes dump.rdb.
docker compose create redis
docker cp "$KP_REDIS_RDB" "$KP_REDIS_CONTAINER:/data/dump.rdb" >/dev/null
docker run --rm \
  --name "kp-redis-rdb-permissions-$KP_RUN_ID" \
  --pull never \
  --network none \
  --user 0:0 \
  --entrypoint /bin/sh \
  --volume "$KP_REDIS_VOLUME:/data" \
  "$KP_REDIS_IMAGE" -ec \
  'chown -R 999:999 /data; chmod 700 /data; chmod 600 /data/dump.rdb'

KP_REDIS_PASSWORD="$(docker inspect "$KP_REDIS_CONTAINER" --format '{{json .Config.Cmd}}' \
  | python3 -c 'import json,sys; a=json.load(sys.stdin); i=a.index("--requirepass"); print(a[i+1], end="")')"
docker run -d \
  --name "$KP_MATERIALIZER" \
  --pull never \
  --network none \
  --user 999:999 \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 128 \
  --volume "$KP_REDIS_VOLUME:/data" \
  "$KP_REDIS_IMAGE" redis-server \
  --requirepass "$KP_REDIS_PASSWORD" --appendonly no --save '' >/dev/null

for _ in $(seq 1 30); do
  docker exec -e REDISCLI_AUTH="$KP_REDIS_PASSWORD" "$KP_MATERIALIZER" \
    redis-cli --no-auth-warning ping 2>/dev/null | grep -qx PONG && break
  sleep 1
done
docker exec -e REDISCLI_AUTH="$KP_REDIS_PASSWORD" "$KP_MATERIALIZER" \
  redis-cli --no-auth-warning ping | grep -qx PONG || fail "Redis RDB materializer did not become ready"
KP_REDIS_KEYS_BEFORE="$(docker exec -e REDISCLI_AUTH="$KP_REDIS_PASSWORD" "$KP_MATERIALIZER" \
  redis-cli --no-auth-warning -n 0 DBSIZE)"
KP_REDIS_KEYS_15_BEFORE="$(docker exec -e REDISCLI_AUTH="$KP_REDIS_PASSWORD" "$KP_MATERIALIZER" \
  redis-cli --no-auth-warning -n 15 DBSIZE)"

docker exec -e REDISCLI_AUTH="$KP_REDIS_PASSWORD" "$KP_MATERIALIZER" \
  redis-cli --no-auth-warning CONFIG SET appendonly yes >/dev/null
for _ in $(seq 1 60); do
  KP_AOF_STATUS="$(docker exec -e REDISCLI_AUTH="$KP_REDIS_PASSWORD" "$KP_MATERIALIZER" \
    redis-cli --no-auth-warning INFO persistence)"
  if printf '%s\n' "$KP_AOF_STATUS" | grep -q '^aof_enabled:1' \
    && printf '%s\n' "$KP_AOF_STATUS" | grep -q '^aof_rewrite_in_progress:0' \
    && printf '%s\n' "$KP_AOF_STATUS" | grep -q '^aof_last_bgrewrite_status:ok'; then
    break
  fi
  sleep 1
done
KP_AOF_SIZE="$(docker exec -e REDISCLI_AUTH="$KP_REDIS_PASSWORD" "$KP_MATERIALIZER" \
  redis-cli --no-auth-warning INFO persistence \
  | awk -F: '$1 == "aof_current_size" {gsub("\r", "", $2); print $2}')"
[ "${KP_AOF_SIZE:-0}" -gt 0 ] || fail "Redis AOF materialization produced no durable bytes"

docker stop "$KP_MATERIALIZER" >/dev/null
docker rm "$KP_MATERIALIZER" >/dev/null
docker start "$KP_REDIS_CONTAINER" >/dev/null
for _ in $(seq 1 60); do
  [ "$(docker inspect "$KP_REDIS_CONTAINER" --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}')" = healthy ] && break
  sleep 1
done
[ "$(docker inspect "$KP_REDIS_CONTAINER" --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}')" = healthy ] \
  || fail "normal Redis service did not become healthy"
KP_REDIS_KEYS_AFTER="$(docker exec -e REDISCLI_AUTH="$KP_REDIS_PASSWORD" "$KP_REDIS_CONTAINER" \
  redis-cli --no-auth-warning -n 0 DBSIZE)"
KP_REDIS_KEYS_15_AFTER="$(docker exec -e REDISCLI_AUTH="$KP_REDIS_PASSWORD" "$KP_REDIS_CONTAINER" \
  redis-cli --no-auth-warning -n 15 DBSIZE)"
unset KP_REDIS_PASSWORD
[ "$KP_REDIS_KEYS_AFTER" = "$KP_REDIS_KEYS_BEFORE" ] \
  || fail "Redis DB 0 key count changed during RDB-to-AOF materialization"
[ "$KP_REDIS_KEYS_15_AFTER" = "$KP_REDIS_KEYS_15_BEFORE" ] \
  || fail "Redis DB 15 key count changed during RDB-to-AOF materialization"

printf 'RESTORE PASSED: postgres_tables=%s redis_db0=%s->%s redis_db15=%s->%s aof_bytes=%s\n' \
  "$KP_VERIFY_TABLES" \
  "$KP_REDIS_KEYS_BEFORE" "$KP_REDIS_KEYS_AFTER" \
  "$KP_REDIS_KEYS_15_BEFORE" "$KP_REDIS_KEYS_15_AFTER" \
  "$KP_AOF_SIZE"
printf 'Safe next action: run migrations, audit verification, readiness, and full install verification.\n'
