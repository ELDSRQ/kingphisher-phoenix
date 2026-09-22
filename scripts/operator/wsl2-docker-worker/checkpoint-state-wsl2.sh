#!/usr/bin/env bash
# Capture a reviewed project checkpoint from the running WSL2 (linux/amd64)
# stack on .105. This is the missing counterpart to restore-state-wsl2.sh:
# that script could restore a checkpoint, but nothing could CREATE one on the
# current worker — the only creator, remote-docker-worker/checkpoint-state.sh,
# is macOS/Colima/Keychain-bound and fails fast on WSL2. Recovery therefore
# could not be proven end to end (readiness gate D5).
#
# It produces exactly what restore-state-wsl2.sh consumes:
#   migration-checkpoint/globals.sql     cluster roles (pg_dumpall --globals-only)
#   migration-checkpoint/postgres.dump   pg_dump custom format (pg_restore -Fc)
#   migration-checkpoint/redis.rdb       RDB snapshot (redis-check-rdb clean)
#
# globals.sql is not optional. Postgres roles are CLUSTER-level, so a pg_dump of
# one database contains GRANTs to roles it does not define. Restoring that into
# a fresh cluster fails on the first GRANT, and the platform's per-worker
# least-privilege model (kp_operator, kp_worker_*, audit_writer, audit_owner)
# would be lost even if it did not.
#   migration-checkpoint/MANIFEST.txt    sha256 digests, sizes, source identity
#
# READ-ONLY against the running stack. It never stops, restarts, reconfigures or
# prunes a container, volume or image, and it touches only this project's
# resources — .105 is a shared build host that also runs AccessTracker and
# Procurement workloads.
#
# Usage:
#   checkpoint-state-wsl2.sh            capture, verify, write the manifest
#   checkpoint-state-wsl2.sh --verify   verify an existing checkpoint only
set -euo pipefail

KP_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
KP_OUT="$KP_ROOT/migration-checkpoint"
KP_POSTGRES_DUMP="$KP_OUT/postgres.dump"
KP_REDIS_RDB="$KP_OUT/redis.rdb"
KP_GLOBALS_SQL="$KP_OUT/globals.sql"
KP_MANIFEST="$KP_OUT/MANIFEST.txt"
KP_POSTGRES_CONTAINER=phishing-awareness-platform-postgres-1
KP_REDIS_CONTAINER=phishing-awareness-platform-redis-1
KP_DB=kingphisher
KP_DB_USER=kingphisher
KP_MAC_ENGINE_NAME='colima-kingphisher'
KP_RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
KP_VERIFY_ONLY=0

case "${1:-}" in
  '') ;;
  --verify) KP_VERIFY_ONLY=1 ;;
  *) printf 'usage: %s [--verify]\n' "$0" >&2; exit 2 ;;
esac

fail() {
  printf 'CHECKPOINT BLOCKED: %s\n' "$*" >&2
  printf 'The running stack is untouched.\n' >&2
  # Partial artifacts are removed so a retry is not blocked by the
  # refuse-to-overwrite guard, and so a half-written checkpoint can never be
  # mistaken for a verified one. Anything already verified is left alone.
  if [ "${KP_PARTIAL:-0}" = "1" ]; then
    rm -f "$KP_POSTGRES_DUMP" "$KP_REDIS_RDB" "$KP_GLOBALS_SQL"
    printf 'Removed the partial checkpoint in %s.\n' "$KP_OUT" >&2
  fi
  exit 1
}
say(){ printf '==> %s\n' "$*"; }
ok(){  printf '  ok %s\n' "$*"; }

# ------------------------------------------------------------ engine identity
command -v docker >/dev/null 2>&1 || fail "docker is not on PATH"
KP_ENGINE="$(docker info --format '{{.Name}}|{{.OSType}}|{{.Architecture}}' 2>/dev/null)" \
  || fail "cannot reach the Docker engine"
case "$KP_ENGINE" in
  *"$KP_MAC_ENGINE_NAME"*) fail "refusing to run against the retired .140 Colima engine ($KP_ENGINE)";;
esac
case "$KP_ENGINE" in
  *linux*x86_64*|*linux*amd64*) ;;
  *) fail "expected a linux/amd64 engine; found $KP_ENGINE";;
esac
say "engine $KP_ENGINE"

verify_artifacts() {
  local img
  img="$(docker inspect "$KP_POSTGRES_CONTAINER" --format '{{.Config.Image}}' 2>/dev/null || true)"
  [ -s "$KP_POSTGRES_DUMP" ] || fail "missing or empty $KP_POSTGRES_DUMP"
  [ -s "$KP_REDIS_RDB" ] || fail "missing or empty $KP_REDIS_RDB"
  [ -s "$KP_GLOBALS_SQL" ] || fail "missing or empty $KP_GLOBALS_SQL"

  say "verifying the PostgreSQL archive is readable by pg_restore"
  docker run --rm --pull never --network none --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,nodev \
    --entrypoint pg_restore -i "$img" --list < "$KP_POSTGRES_DUMP" >/dev/null \
    || fail "pg_restore --list rejected the archive"
  ok "archive is a valid pg_restore custom-format dump"

  say "verifying the Redis RDB"
  local rimg
  rimg="$(docker inspect "$KP_REDIS_CONTAINER" --format '{{.Config.Image}}' 2>/dev/null || true)"
  # No --user here: docker cp preserves /data/dump.rdb's 0600 builder-owned
  # perms, so uid 999 cannot read it. Widening the artifact to 0644 just to
  # satisfy the check would leak Redis contents on this shared host, so the
  # throwaway container reads it as root instead, still --read-only,
  # --network none and --pull never.
  docker run --rm --pull never --network none --read-only \
    --volume "$KP_OUT:/backup:ro" \
    --entrypoint redis-check-rdb "$rimg" /backup/redis.rdb >/dev/null \
    || fail "redis-check-rdb rejected the snapshot"
  ok "RDB passes redis-check-rdb"
}

if [ "$KP_VERIFY_ONLY" = "1" ]; then
  verify_artifacts
  [ -f "$KP_MANIFEST" ] && { say "manifest"; sed 's/^/     /' "$KP_MANIFEST"; }
  ok "existing checkpoint verified"
  exit 0
fi

# -------------------------------------------------------------- preconditions
for c in "$KP_POSTGRES_CONTAINER" "$KP_REDIS_CONTAINER"; do
  [ "$(docker inspect "$c" --format '{{.State.Running}}' 2>/dev/null || echo false)" = "true" ] \
    || fail "$c is not running; start the stack before taking a checkpoint"
done
ok "postgres and redis are running"

KP_TABLES="$(docker exec "$KP_POSTGRES_CONTAINER" psql -U "$KP_DB_USER" -d "$KP_DB" -Atc \
  "select count(*) from pg_tables where schemaname='public';" 2>/dev/null || echo 0)"
[ "${KP_TABLES:-0}" -gt 0 ] \
  || fail "source database has no public tables; refusing to capture an empty checkpoint"
ok "source database has $KP_TABLES public tables"

KP_PARTIAL=1
mkdir -p "$KP_OUT"
for f in "$KP_POSTGRES_DUMP" "$KP_REDIS_RDB" "$KP_GLOBALS_SQL"; do
  [ -e "$f" ] && fail "$f already exists; move the previous checkpoint aside rather than overwriting it"
done

# ------------------------------------------------------------------- postgres
say "capturing cluster globals (roles and their grants)"
docker exec "$KP_POSTGRES_CONTAINER" pg_dumpall -U "$KP_DB_USER" --globals-only \
  > "$KP_GLOBALS_SQL" || fail "pg_dumpall --globals-only failed"
grep -qE '^CREATE ROLE' "$KP_GLOBALS_SQL" || fail "globals.sql contains no CREATE ROLE statements"
ok "wrote $(grep -c '^CREATE ROLE' "$KP_GLOBALS_SQL") roles"

say "capturing PostgreSQL (custom format)"
docker exec "$KP_POSTGRES_CONTAINER" pg_dump -U "$KP_DB_USER" -d "$KP_DB" --format=custom \
  > "$KP_POSTGRES_DUMP" || fail "pg_dump failed"
ok "wrote $(wc -c < "$KP_POSTGRES_DUMP" | tr -d ' ') bytes"

# ---------------------------------------------------------------------- redis
# BGSAVE, then wait for rdb_bgsave_in_progress to clear. SAVE would block the
# running server; this host is shared, so blocking is not acceptable.
say "capturing Redis (BGSAVE)"
KP_REDIS_PASSWORD="$(docker inspect "$KP_REDIS_CONTAINER" --format '{{json .Config.Cmd}}' \
  | python3 -c 'import json,sys; a=json.load(sys.stdin) or []; print(a[a.index("--requirepass")+1] if "--requirepass" in a else "")')"
redis_cli() {
  if [ -n "$KP_REDIS_PASSWORD" ]; then
    docker exec "$KP_REDIS_CONTAINER" redis-cli -a "$KP_REDIS_PASSWORD" --no-auth-warning "$@"
  else
    docker exec "$KP_REDIS_CONTAINER" redis-cli "$@"
  fi
}
KP_LAST_SAVE="$(redis_cli LASTSAVE | tr -d '\r')"
redis_cli BGSAVE >/dev/null || fail "BGSAVE failed"
for _ in $(seq 1 60); do
  sleep 1
  [ "$(redis_cli LASTSAVE | tr -d '\r')" != "$KP_LAST_SAVE" ] && break
done
[ "$(redis_cli LASTSAVE | tr -d '\r')" != "$KP_LAST_SAVE" ] || fail "BGSAVE did not complete within 60s"
docker cp "$KP_REDIS_CONTAINER:/data/dump.rdb" "$KP_REDIS_RDB" >/dev/null || fail "could not copy dump.rdb"
ok "wrote $(wc -c < "$KP_REDIS_RDB" | tr -d ' ') bytes"

verify_artifacts
KP_PARTIAL=0

# ------------------------------------------------------------------ manifest
{
  echo "checkpoint_run_id    $KP_RUN_ID"
  echo "captured_at_utc      $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "engine               $KP_ENGINE"
  echo "source_public_tables $KP_TABLES"
  echo "postgres_image       $(docker inspect "$KP_POSTGRES_CONTAINER" --format '{{.Config.Image}}')"
  echo "redis_image          $(docker inspect "$KP_REDIS_CONTAINER" --format '{{.Config.Image}}')"
  echo "postgres_dump_sha256 $(sha256sum "$KP_POSTGRES_DUMP" | awk '{print $1}')"
  echo "postgres_dump_bytes  $(wc -c < "$KP_POSTGRES_DUMP" | tr -d ' ')"
  echo "globals_sql_sha256   $(sha256sum "$KP_GLOBALS_SQL" | awk '{print $1}')"
  echo "globals_roles        $(grep -c '^CREATE ROLE' "$KP_GLOBALS_SQL")"
  echo "redis_rdb_sha256     $(sha256sum "$KP_REDIS_RDB" | awk '{print $1}')"
  echo "redis_rdb_bytes      $(wc -c < "$KP_REDIS_RDB" | tr -d ' ')"
} > "$KP_MANIFEST"
say "manifest"; sed 's/^/     /' "$KP_MANIFEST"
ok "checkpoint complete; restore with restore-state-wsl2.sh into a CLEAN engine"
