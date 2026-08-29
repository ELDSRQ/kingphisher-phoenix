#!/usr/bin/env bash
# Create a validated encrypted checkpoint of the preserved Docker Desktop copy.
#
# Dry-run is the default.  --apply performs only logical database snapshots and
# additive file creation; it never stops, removes, or recreates containers,
# volumes, images, source files, or unrelated Docker resources.

set -euo pipefail

KP_ROOT="${KP_PROJECT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)}"
KP_PROJECT_NAME=phishing-awareness-platform
KP_POSTGRES_CONTAINER=phishing-awareness-platform-postgres-1
KP_REDIS_CONTAINER=phishing-awareness-platform-redis-1
KP_EXPECTED_CONTEXT=desktop-linux
KP_EXTERNAL_VOLUME="${KP_EXTERNAL_VOLUME:-/Volumes/DockerExternal}"
KP_EXTERNAL_VOLUME_UUID="${KP_EXTERNAL_VOLUME_UUID:-FD7BE277-8CB4-3ADA-8CA2-11F8EBBBADF4}"
KP_SNAPSHOT_ROOT="${KP_SNAPSHOT_ROOT:-$KP_EXTERNAL_VOLUME/KingPhisher-Phoenix/migration-snapshots}"
KP_RECOVERY_KEYCHAIN_SERVICE="${KP_RECOVERY_KEYCHAIN_SERVICE:-com.kingphisher.phishing-awareness-platform.migration-recovery.v1}"
KP_RECOVERY_KEYCHAIN_ACCOUNT="${KP_RECOVERY_KEYCHAIN_ACCOUNT:-phishing-awareness-platform-recovery}"
KP_RECOVERY_IDENTITY_FILE="${KP_RECOVERY_IDENTITY_FILE:-}"
KP_SECURITY_BIN="${KP_SECURITY_BIN:-/usr/bin/security}"
KP_DISKUTIL_BIN="${KP_DISKUTIL_BIN:-/usr/sbin/diskutil}"
KP_AGE_BIN="${KP_AGE_BIN:-$(command -v age || true)}"
KP_AGE_KEYGEN_BIN="${KP_AGE_KEYGEN_BIN:-$(command -v age-keygen || true)}"
KP_APPLY=0
KP_WORK_DIR=''
KP_PARTIAL_DIR=''
KP_UNRELATED_BEFORE=''
KP_UNRELATED_INVENTORY_READY=0
KP_RECIPIENTS=()

fail() {
  printf 'CHECKPOINT BLOCKED: %s\n' "$*" >&2
  printf 'No container, volume, image, source, or unrelated Docker resource was removed or replaced.\n' >&2
  exit 1
}

usage() {
  printf 'usage: %s [--apply] --recipient AGE_RECIPIENT [--recipient AGE_RECIPIENT ...]\n' "$0" >&2
  exit 2
}

unrelated_inventory() {
  docker ps -a --format '{{.ID}}|{{.State}}|{{.Label "com.docker.compose.project"}}' \
    | awk -F'|' -v project="$KP_PROJECT_NAME" '$3 != project {print $1 "|" $2}' \
    | LC_ALL=C sort
}

cleanup() {
  KP_EXIT_STATUS=$?
  trap - EXIT HUP INT TERM
  if [ "$KP_UNRELATED_INVENTORY_READY" -eq 1 ]; then
    if ! KP_UNRELATED_AFTER="$(unrelated_inventory 2>/dev/null)"; then
      printf 'CHECKPOINT BLOCKED: unrelated container state could not be re-inspected\n' >&2
      KP_EXIT_STATUS=1
    elif [ "$KP_UNRELATED_BEFORE" != "$KP_UNRELATED_AFTER" ]; then
      printf 'CHECKPOINT BLOCKED: unrelated container identity or running state changed\n' >&2
      KP_EXIT_STATUS=1
    fi
  fi
  if [ -n "$KP_WORK_DIR" ] && [ -d "$KP_WORK_DIR" ]; then
    /bin/rm -R -- "$KP_WORK_DIR"
  fi
  if [ -n "$KP_PARTIAL_DIR" ] && [ -d "$KP_PARTIAL_DIR" ]; then
    /bin/rm -R -- "$KP_PARTIAL_DIR"
  fi
  exit "$KP_EXIT_STATUS"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

while [ "$#" -gt 0 ]; do
  case "$1" in
    --apply)
      KP_APPLY=1
      shift
      ;;
    --recipient)
      [ "$#" -ge 2 ] || usage
      KP_RECIPIENTS+=("$2")
      shift 2
      ;;
    *) usage ;;
  esac
done
[ "${#KP_RECIPIENTS[@]}" -gt 0 ] || fail "at least one explicit age recipient is required"

command -v docker >/dev/null 2>&1 || fail "Docker CLI is unavailable"
command -v git >/dev/null 2>&1 || fail "Git is unavailable"
[ "$(uname -s)" = Darwin ] || fail "the migration source checkpoint supports macOS only"
[ -x "$KP_SECURITY_BIN" ] || fail "macOS Keychain command is unavailable"
[ -x "$KP_DISKUTIL_BIN" ] || fail "macOS disk identity command is unavailable"
[ -n "$KP_AGE_BIN" ] && [ -x "$KP_AGE_BIN" ] || fail "age is unavailable"
[ -n "$KP_AGE_KEYGEN_BIN" ] && [ -x "$KP_AGE_KEYGEN_BIN" ] || fail "age-keygen is unavailable"
case "$KP_RECOVERY_KEYCHAIN_SERVICE" in
  com.kingphisher.phishing-awareness-platform.migration-recovery.*) ;;
  *) fail "Keychain service is outside the recovery namespace" ;;
esac
[ "$KP_RECOVERY_KEYCHAIN_ACCOUNT" = phishing-awareness-platform-recovery ] \
  || fail "Keychain account is outside the recovery namespace"
for KP_RECIPIENT in "${KP_RECIPIENTS[@]}"; do
  printf '%s\n' "$KP_RECIPIENT" | grep -Eq '^age1[0-9a-z]+$' \
    || fail "a recovery recipient has an invalid format"
done

[ -z "${DOCKER_HOST:-}" ] || fail "DOCKER_HOST must be unset for the preserved Docker Desktop source"
[ -z "${DOCKER_CONTEXT:-}" ] || fail "DOCKER_CONTEXT must be unset for the preserved Docker Desktop source"
[ -z "${DOCKER_CONFIG:-}" ] || fail "DOCKER_CONFIG must be unset for the preserved Docker Desktop source"
KP_CONTEXT="$(docker context show 2>/dev/null)" || fail "Docker context cannot be resolved"
[ "$KP_CONTEXT" = "$KP_EXPECTED_CONTEXT" ] \
  || fail "ambient Docker context must be $KP_EXPECTED_CONTEXT, got $KP_CONTEXT"
docker info >/dev/null 2>&1 || fail "ambient Docker Desktop engine is unreachable"

[ -d "$KP_ROOT" ] || fail "preserved project root is missing"
KP_ROOT="$(cd "$KP_ROOT" && pwd -P)"
[ -f "$KP_ROOT/.env" ] && [ ! -L "$KP_ROOT/.env" ] || fail "the preserved .env is missing or symbolic"
[ -d "$KP_ROOT/.git" ] && [ ! -L "$KP_ROOT/.git" ] || fail "the preserved .git directory is missing or symbolic"
[ -d "$KP_ROOT/data" ] && [ ! -L "$KP_ROOT/data" ] || fail "the preserved data directory is missing or symbolic"
[ -d "$KP_ROOT/data/recovery" ] || fail "the preserved recovery evidence directory is missing"
[ ! -L "$KP_ROOT/artifacts" ] || fail "source artifacts path must not be symbolic"
[ ! -e "$KP_ROOT/migration-checkpoint" ] \
  || fail "source contains the reserved migration-checkpoint path"

KP_MOUNT_POINT="$("$KP_DISKUTIL_BIN" info "$KP_EXTERNAL_VOLUME" \
  | /usr/bin/awk -F: '$1 ~ "^[[:space:]]*Mount Point[[:space:]]*$" {sub(/^[[:space:]]*/, "", $2); print $2}')"
KP_VOLUME_UUID_ACTUAL="$("$KP_DISKUTIL_BIN" info "$KP_EXTERNAL_VOLUME" \
  | /usr/bin/awk -F: '$1 ~ "^[[:space:]]*Volume UUID[[:space:]]*$" {sub(/^[[:space:]]*/, "", $2); print $2}')"
[ "$KP_MOUNT_POINT" = "$KP_EXTERNAL_VOLUME" ] || fail "external migration volume is not mounted at the reviewed path"
[ "$KP_VOLUME_UUID_ACTUAL" = "$KP_EXTERNAL_VOLUME_UUID" ] || fail "external migration volume UUID does not match"
[ -d "$KP_SNAPSHOT_ROOT" ] && [ -w "$KP_SNAPSHOT_ROOT" ] && [ ! -L "$KP_SNAPSHOT_ROOT" ] \
  || fail "snapshot root is absent, unwritable, or symbolic"
case "$(cd "$KP_SNAPSHOT_ROOT" && pwd -P)" in
  "$KP_EXTERNAL_VOLUME"/*) ;;
  *) fail "snapshot root escaped the reviewed external volume" ;;
esac

verify_project_container() {
  KP_CONTAINER_NAME="$1"
  KP_SERVICE_NAME="$2"
  KP_CONTAINER_IDS="$(docker ps -aq --no-trunc \
    --filter "label=com.docker.compose.project=$KP_PROJECT_NAME" \
    --filter "label=com.docker.compose.service=$KP_SERVICE_NAME")"
  [ "$(printf '%s\n' "$KP_CONTAINER_IDS" | awk 'NF {count++} END {print count+0}')" -eq 1 ] \
    || fail "service $KP_SERVICE_NAME does not resolve to exactly one project container"
  KP_EXACT_ID="$(docker inspect --format '{{.Id}}' "$KP_CONTAINER_NAME" 2>/dev/null)" \
    || fail "expected project container is absent: $KP_CONTAINER_NAME"
  [ "$KP_CONTAINER_IDS" = "$KP_EXACT_ID" ] \
    || fail "service $KP_SERVICE_NAME is not bound to the exact reviewed container name"
  [ "$(docker inspect --format '{{.Name}}' "$KP_CONTAINER_NAME")" = "/$KP_CONTAINER_NAME" ] \
    || fail "container name drifted for service $KP_SERVICE_NAME"
  KP_CONTAINER_CONTRACT="$(docker inspect --format \
    '{{index .Config.Labels "com.docker.compose.project"}}|{{index .Config.Labels "com.docker.compose.service"}}|{{.State.Running}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}' \
    "$KP_CONTAINER_NAME")"
  [ "$KP_CONTAINER_CONTRACT" = "$KP_PROJECT_NAME|$KP_SERVICE_NAME|true|healthy" ] \
    || fail "service $KP_SERVICE_NAME is not the exact healthy running project container"
}

verify_project_container "$KP_POSTGRES_CONTAINER" postgres
verify_project_container "$KP_REDIS_CONTAINER" redis
KP_POSTGRES_CONTAINER_ID="$(docker inspect --format '{{.Id}}' "$KP_POSTGRES_CONTAINER")"
KP_REDIS_CONTAINER_ID="$(docker inspect --format '{{.Id}}' "$KP_REDIS_CONTAINER")"
KP_UNRELATED_BEFORE="$(unrelated_inventory)" || fail "could not inventory unrelated containers"
KP_UNRELATED_INVENTORY_READY=1

umask 077
KP_WORK_DIR="$(mktemp -d /private/tmp/kp-checkpoint.XXXXXX)"
[ -d "$KP_WORK_DIR" ] && [ ! -L "$KP_WORK_DIR" ] || fail "could not create checkpoint workspace"
KP_IDENTITY_FILE="$KP_WORK_DIR/recovery-identity.txt"
if [ -n "$KP_RECOVERY_IDENTITY_FILE" ]; then
  case "$KP_RECOVERY_IDENTITY_FILE" in
    /private/tmp/kp-recovery-transfer.*) ;;
    *) fail "explicit recovery identity must use the private transfer namespace" ;;
  esac
  [ -f "$KP_RECOVERY_IDENTITY_FILE" ] && [ ! -L "$KP_RECOVERY_IDENTITY_FILE" ] \
    || fail "explicit recovery identity is absent, non-regular, or symbolic"
  KP_IDENTITY_CONTRACT="$(/usr/bin/stat -f '%u|%Lp' "$KP_RECOVERY_IDENTITY_FILE")"
  [ "$KP_IDENTITY_CONTRACT" = "$(id -u)|600" ] \
    || fail "explicit recovery identity must be owned by the current user with mode 0600"
  /bin/cp -p "$KP_RECOVERY_IDENTITY_FILE" "$KP_IDENTITY_FILE"
else
  "$KP_SECURITY_BIN" find-generic-password \
    -a "$KP_RECOVERY_KEYCHAIN_ACCOUNT" \
    -s "$KP_RECOVERY_KEYCHAIN_SERVICE" \
    -w > "$KP_IDENTITY_FILE" 2>/dev/null \
    || fail "local recovery identity is absent from the named Keychain item"
fi
chmod 600 "$KP_IDENTITY_FILE"
[ "$(wc -l < "$KP_IDENTITY_FILE" | tr -d ' ')" = 1 ] \
  || fail "Keychain recovery identity has an unexpected record count"
grep -Eq '^AGE-SECRET-KEY-1[0-9A-Z]+$' "$KP_IDENTITY_FILE" \
  || fail "Keychain recovery identity has an invalid format"
KP_LOCAL_RECIPIENT="$("$KP_AGE_KEYGEN_BIN" -y "$KP_IDENTITY_FILE" 2>/dev/null)" \
  || fail "Keychain recovery identity cannot derive a recipient"
KP_RECIPIENT_MATCH=0
for KP_RECIPIENT in "${KP_RECIPIENTS[@]}"; do
  if [ "$KP_RECIPIENT" = "$KP_LOCAL_RECIPIENT" ]; then
    KP_RECIPIENT_MATCH=1
  fi
done
[ "$KP_RECIPIENT_MATCH" -eq 1 ] \
  || fail "the local recovery identity does not match any explicit encryption recipient"

if [ "$KP_APPLY" -ne 1 ]; then
  printf 'CHECKPOINT PREFLIGHT PASSED: source containers, external volume, and recovery identity are exact.\n'
  printf 'Re-run with --apply and the same explicit recipient list to publish a snapshot.\n'
  exit 0
fi

KP_SOURCE_PARENT="$(dirname "$KP_ROOT")"
KP_SOURCE_BASENAME="$(basename "$KP_ROOT")"
KP_CHECKPOINT_DIR="$KP_WORK_DIR/$KP_SOURCE_BASENAME/migration-checkpoint"
mkdir -p "$KP_CHECKPOINT_DIR"
chmod 700 "$KP_WORK_DIR/$KP_SOURCE_BASENAME" "$KP_CHECKPOINT_DIR"
KP_POSTGRES_DUMP="$KP_CHECKPOINT_DIR/postgres.dump"
KP_REDIS_RDB="$KP_CHECKPOINT_DIR/redis.rdb"

docker exec "$KP_POSTGRES_CONTAINER" pg_dump \
  -U kingphisher -d kingphisher --format=custom > "$KP_POSTGRES_DUMP"
[ -s "$KP_POSTGRES_DUMP" ] || fail "PostgreSQL logical archive is empty"
docker exec -i "$KP_POSTGRES_CONTAINER" pg_restore --list < "$KP_POSTGRES_DUMP" >/dev/null \
  || fail "PostgreSQL logical archive failed validation"

KP_REDIS_PASSWORD="$(docker inspect "$KP_REDIS_CONTAINER" --format '{{json .Config.Cmd}}' \
  | python3 -c 'import json,sys; a=json.load(sys.stdin); hits=[a[i+1] for i,v in enumerate(a[:-1]) if v == "--requirepass"]; (len(hits) == 1 and hits[0]) or sys.exit(1); print(hits[0], end="")')" \
  || fail "Redis password could not be recovered from the exact container command"
[ -n "$KP_REDIS_PASSWORD" ] || fail "Redis password is empty"
for _ in $(seq 1 60); do
  KP_REDIS_PERSISTENCE="$(docker exec -e REDISCLI_AUTH="$KP_REDIS_PASSWORD" "$KP_REDIS_CONTAINER" \
    redis-cli --no-auth-warning INFO persistence)"
  printf '%s\n' "$KP_REDIS_PERSISTENCE" | grep -q '^rdb_bgsave_in_progress:0' && break
  sleep 1
done
printf '%s\n' "$KP_REDIS_PERSISTENCE" | grep -q '^rdb_bgsave_in_progress:0' \
  || fail "a prior Redis background save did not finish within 60 seconds"
KP_REDIS_LASTSAVE_BEFORE="$(docker exec -e REDISCLI_AUTH="$KP_REDIS_PASSWORD" "$KP_REDIS_CONTAINER" \
  redis-cli --no-auth-warning LASTSAVE)"
printf '%s\n' "$KP_REDIS_LASTSAVE_BEFORE" | grep -Eq '^[0-9]+$' \
  || fail "Redis last-save evidence is malformed"
while [ "$(date -u +%s)" -le "$KP_REDIS_LASTSAVE_BEFORE" ]; do
  sleep 1
done
KP_BGSAVE_RESULT="$(docker exec -e REDISCLI_AUTH="$KP_REDIS_PASSWORD" "$KP_REDIS_CONTAINER" \
  redis-cli --no-auth-warning BGSAVE)"
printf '%s\n' "$KP_BGSAVE_RESULT" | grep -Eq '^Background saving (started|scheduled)$' \
  || fail "Redis did not accept the background save"
for _ in $(seq 1 120); do
  KP_REDIS_PERSISTENCE="$(docker exec -e REDISCLI_AUTH="$KP_REDIS_PASSWORD" "$KP_REDIS_CONTAINER" \
    redis-cli --no-auth-warning INFO persistence)"
  KP_REDIS_LASTSAVE_AFTER="$(docker exec -e REDISCLI_AUTH="$KP_REDIS_PASSWORD" "$KP_REDIS_CONTAINER" \
    redis-cli --no-auth-warning LASTSAVE)"
  if printf '%s\n' "$KP_REDIS_PERSISTENCE" | grep -q '^rdb_bgsave_in_progress:0' \
    && printf '%s\n' "$KP_REDIS_PERSISTENCE" | grep -q '^rdb_last_bgsave_status:ok' \
    && printf '%s\n' "$KP_REDIS_LASTSAVE_AFTER" | grep -Eq '^[0-9]+$' \
    && [ "$KP_REDIS_LASTSAVE_AFTER" -gt "$KP_REDIS_LASTSAVE_BEFORE" ]; then
    break
  fi
  sleep 1
done
if ! printf '%s\n' "$KP_REDIS_PERSISTENCE" | grep -q '^rdb_bgsave_in_progress:0' \
  || ! printf '%s\n' "$KP_REDIS_PERSISTENCE" | grep -q '^rdb_last_bgsave_status:ok' \
  || ! printf '%s\n' "$KP_REDIS_LASTSAVE_AFTER" | grep -Eq '^[0-9]+$' \
  || [ "$KP_REDIS_LASTSAVE_AFTER" -le "$KP_REDIS_LASTSAVE_BEFORE" ]; then
  fail "Redis background save did not complete safely within 120 seconds"
fi
docker exec "$KP_REDIS_CONTAINER" redis-check-rdb /data/dump.rdb >/dev/null \
  || fail "Redis source RDB failed validation"
KP_REDIS_SOURCE_SHA="$(docker exec "$KP_REDIS_CONTAINER" sha256sum /data/dump.rdb | awk '{print $1}')"
docker cp "$KP_REDIS_CONTAINER:/data/dump.rdb" "$KP_REDIS_RDB" >/dev/null
[ -s "$KP_REDIS_RDB" ] || fail "copied Redis RDB is empty"
KP_REDIS_COPY_SHA="$(shasum -a 256 "$KP_REDIS_RDB" | awk '{print $1}')"
[ "$KP_REDIS_SOURCE_SHA" = "$KP_REDIS_COPY_SHA" ] || fail "copied Redis RDB digest does not match source"
unset KP_REDIS_PASSWORD

KP_POSTGRES_SHA="$(shasum -a 256 "$KP_POSTGRES_DUMP" | awk '{print $1}')"
KP_GIT_HEAD="$(git -C "$KP_ROOT" rev-parse --verify HEAD)"
KP_PAYLOAD_METADATA="$KP_CHECKPOINT_DIR/checkpoint-metadata.txt"
{
  printf '%s\n' \
    'schema=kp.remote-migration-checkpoint.v1' \
    "source_root=$KP_ROOT" \
    "source_git_head=$KP_GIT_HEAD" \
    "docker_context=$KP_CONTEXT" \
    "compose_project=$KP_PROJECT_NAME" \
    "postgres_container=$KP_POSTGRES_CONTAINER" \
    "postgres_container_id=$KP_POSTGRES_CONTAINER_ID" \
    "postgres_dump_sha256=$KP_POSTGRES_SHA" \
    "redis_container=$KP_REDIS_CONTAINER" \
    "redis_container_id=$KP_REDIS_CONTAINER_ID" \
    "redis_rdb_sha256=$KP_REDIS_COPY_SHA" \
    "external_volume_uuid=$KP_VOLUME_UUID_ACTUAL" \
    "local_recovery_recipient=$KP_LOCAL_RECIPIENT"
  KP_RECIPIENT_INDEX=0
  for KP_RECIPIENT in "${KP_RECIPIENTS[@]}"; do
    KP_RECIPIENT_INDEX=$((KP_RECIPIENT_INDEX + 1))
    printf 'encryption_recipient_%s=%s\n' "$KP_RECIPIENT_INDEX" "$KP_RECIPIENT"
  done
} > "$KP_PAYLOAD_METADATA"
chmod 600 "$KP_PAYLOAD_METADATA"

KP_RUN_TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
KP_PARTIAL_DIR="$(mktemp -d "$KP_SNAPSHOT_ROOT/.checkpoint-partial.$KP_RUN_TIMESTAMP.XXXXXX")"
[ -d "$KP_PARTIAL_DIR" ] && [ ! -L "$KP_PARTIAL_DIR" ] || fail "could not create partial snapshot directory"
KP_PARTIAL_SUFFIX="${KP_PARTIAL_DIR##*.}"
KP_FINAL_DIR="$KP_SNAPSHOT_ROOT/$KP_RUN_TIMESTAMP-$KP_PARTIAL_SUFFIX"
[ ! -e "$KP_FINAL_DIR" ] && [ ! -L "$KP_FINAL_DIR" ] \
  || fail "unique final snapshot path already exists"
KP_ARCHIVE="$KP_PARTIAL_DIR/kingphisher-project-migration.tar.age"
KP_AGE_ARGS=()
for KP_RECIPIENT in "${KP_RECIPIENTS[@]}"; do
  KP_AGE_ARGS+=(-r "$KP_RECIPIENT")
done

COPYFILE_DISABLE=1 tar -cf - \
  --exclude="$KP_SOURCE_BASENAME/.venv" \
  --exclude="$KP_SOURCE_BASENAME/infrastructure/terraform/.terraform" \
  -C "$KP_SOURCE_PARENT" "$KP_SOURCE_BASENAME" \
  -C "$KP_WORK_DIR" \
  "$KP_SOURCE_BASENAME/migration-checkpoint" \
  | "$KP_AGE_BIN" "${KP_AGE_ARGS[@]}" -o "$KP_ARCHIVE"
[ -s "$KP_ARCHIVE" ] || fail "encrypted checkpoint archive is empty"

KP_ARCHIVE_LIST="$KP_WORK_DIR/archive-members.txt"
"$KP_AGE_BIN" -d -i "$KP_IDENTITY_FILE" "$KP_ARCHIVE" | tar -tf - > "$KP_ARCHIVE_LIST"
for KP_REQUIRED_MEMBER in \
  "$KP_SOURCE_BASENAME/.env" \
  "$KP_SOURCE_BASENAME/.git/" \
  "$KP_SOURCE_BASENAME/data/" \
  "$KP_SOURCE_BASENAME/data/recovery/" \
  "$KP_SOURCE_BASENAME/migration-checkpoint/postgres.dump" \
  "$KP_SOURCE_BASENAME/migration-checkpoint/redis.rdb" \
  "$KP_SOURCE_BASENAME/migration-checkpoint/checkpoint-metadata.txt"; do
  grep -Fqx "$KP_REQUIRED_MEMBER" "$KP_ARCHIVE_LIST" \
    || fail "encrypted checkpoint is missing required member: $KP_REQUIRED_MEMBER"
done
! grep -Eq "^$KP_SOURCE_BASENAME/\.venv(/|$)" "$KP_ARCHIVE_LIST" \
  || fail "encrypted checkpoint unexpectedly contains .venv"
! grep -Eq "^$KP_SOURCE_BASENAME/infrastructure/terraform/\.terraform(/|$)" "$KP_ARCHIVE_LIST" \
  || fail "encrypted checkpoint unexpectedly contains Terraform provider cache"

{
  printf 'created_at=%s\n' "$KP_RUN_TIMESTAMP"
  while IFS= read -r KP_METADATA_LINE; do
    printf '%s\n' "$KP_METADATA_LINE"
  done < "$KP_PAYLOAD_METADATA"
  printf '%s\n' \
    'archive_validation=decrypt-and-full-tar-list-passed' \
    'unrelated_container_state=unchanged'
} > "$KP_PARTIAL_DIR/checkpoint-metadata.txt"
chmod 600 "$KP_PARTIAL_DIR/checkpoint-metadata.txt"
(
  cd "$KP_PARTIAL_DIR"
  shasum -a 256 kingphisher-project-migration.tar.age checkpoint-metadata.txt > manifest.sha256
  shasum -a 256 -c manifest.sha256 >/dev/null
)

verify_project_container "$KP_POSTGRES_CONTAINER" postgres
verify_project_container "$KP_REDIS_CONTAINER" redis
KP_UNRELATED_AFTER="$(unrelated_inventory)" || fail "could not re-inventory unrelated containers"
[ "$KP_UNRELATED_BEFORE" = "$KP_UNRELATED_AFTER" ] \
  || fail "unrelated container identity or running state changed during checkpoint"

KP_PARTIAL_INODE="$(/usr/bin/stat -f %i "$KP_PARTIAL_DIR")" \
  || fail "partial snapshot identity could not be recorded"
/bin/mv -n "$KP_PARTIAL_DIR" "$KP_FINAL_DIR"
[ ! -e "$KP_PARTIAL_DIR" ] \
  && [ -d "$KP_FINAL_DIR" ] \
  && [ ! -L "$KP_FINAL_DIR" ] \
  && [ "$(/usr/bin/stat -f %i "$KP_FINAL_DIR")" = "$KP_PARTIAL_INODE" ] \
  || fail "atomic no-clobber snapshot publication did not complete"
KP_PARTIAL_DIR=''
printf 'CHECKPOINT PASSED: snapshot=%s\n' "$KP_FINAL_DIR"
printf 'archive_sha256=%s\n' "$(shasum -a 256 "$KP_FINAL_DIR/kingphisher-project-migration.tar.age" | awk '{print $1}')"
printf 'recovery_recipient=%s\n' "$KP_LOCAL_RECIPIENT"
