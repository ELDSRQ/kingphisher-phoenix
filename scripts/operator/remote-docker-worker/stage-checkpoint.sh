#!/usr/bin/env bash
# Validate and stage one encrypted migration checkpoint for the external engine.
#
# Dry-run is the default. --apply publishes only a previously absent
# migration-checkpoint directory. The encrypted archive is never changed.

set -euo pipefail

KP_EXTERNAL_VOLUME="${KP_EXTERNAL_VOLUME:-/Volumes/DockerExternal}"
KP_EXTERNAL_VOLUME_UUID="${KP_EXTERNAL_VOLUME_UUID:-FD7BE277-8CB4-3ADA-8CA2-11F8EBBBADF4}"
KP_EXTERNAL_ROOT="${KP_EXTERNAL_ROOT:-$KP_EXTERNAL_VOLUME/KingPhisher-Phoenix}"
KP_SNAPSHOT_ROOT="${KP_SNAPSHOT_ROOT:-$KP_EXTERNAL_ROOT/migration-snapshots}"
KP_PROJECT_SOURCE="${KP_PROJECT_SOURCE:-$HOME/Projects/kingphisher-phoenix}"
KP_EXTERNAL_ENGINE="${KP_EXTERNAL_ENGINE:-$KP_PROJECT_SOURCE/scripts/operator/remote-docker-worker/external-engine.sh}"
KP_RECOVERY_KEYCHAIN_SERVICE="${KP_RECOVERY_KEYCHAIN_SERVICE:-com.kingphisher.phishing-awareness-platform.migration-recovery.v1}"
KP_RECOVERY_KEYCHAIN_ACCOUNT="${KP_RECOVERY_KEYCHAIN_ACCOUNT:-phishing-awareness-platform-recovery}"
KP_RECOVERY_IDENTITY_FILE="${KP_RECOVERY_IDENTITY_FILE:-}"
KP_SECURITY_BIN="${KP_SECURITY_BIN:-/usr/bin/security}"
KP_DISKUTIL_BIN="${KP_DISKUTIL_BIN:-/usr/sbin/diskutil}"
KP_STAT_BIN="${KP_STAT_BIN:-/usr/bin/stat}"
KP_SHASUM_BIN="${KP_SHASUM_BIN:-/usr/bin/shasum}"
KP_AGE_BIN="${KP_AGE_BIN:-$(command -v age || true)}"
KP_AGE_KEYGEN_BIN="${KP_AGE_KEYGEN_BIN:-$(command -v age-keygen || true)}"
KP_POSTGRES_IMAGE='postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777'
KP_REDIS_IMAGE='redis:7-alpine@sha256:e7723ff73d963f5cc6d9c4643ea3d989527a402a319239054e9472a7fb9219a2'
KP_MAX_ARCHIVE_BYTES=68719476736
KP_APPLY=0
KP_ARCHIVE=''
KP_WORK_DIR=''
KP_PUBLISH_DIR=''

fail() {
  printf 'CHECKPOINT STAGING BLOCKED: %s\n' "$*" >&2
  printf 'The encrypted archive, canonical source, Docker Desktop, and unrelated resources were not changed.\n' >&2
  exit 1
}

usage() {
  printf 'usage: %s [--apply] --archive /exact/path/kingphisher-project-migration.tar.age\n' "$0" >&2
  exit 2
}

cleanup() {
  KP_EXIT_STATUS=$?
  trap - EXIT HUP INT TERM
  if [ -n "$KP_WORK_DIR" ] && [ -d "$KP_WORK_DIR" ]; then
    /bin/rm -R -- "$KP_WORK_DIR"
  fi
  if [ -n "$KP_PUBLISH_DIR" ] && [ -d "$KP_PUBLISH_DIR" ]; then
    /bin/rm -R -- "$KP_PUBLISH_DIR"
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
    --archive)
      [ "$#" -ge 2 ] || usage
      [ -z "$KP_ARCHIVE" ] || usage
      KP_ARCHIVE="$2"
      shift 2
      ;;
    *) usage ;;
  esac
done
[ -n "$KP_ARCHIVE" ] || usage

[ "$(uname -s)" = Darwin ] || fail "checkpoint staging supports the reviewed macOS worker only"
[ -x "$KP_DISKUTIL_BIN" ] || fail "macOS disk identity command is unavailable"
[ -x "$KP_STAT_BIN" ] || fail "file identity command is unavailable"
[ -x "$KP_SHASUM_BIN" ] || fail "SHA-256 command is unavailable"
[ -n "$KP_AGE_BIN" ] && [ -x "$KP_AGE_BIN" ] || fail "age is unavailable"
[ -n "$KP_AGE_KEYGEN_BIN" ] && [ -x "$KP_AGE_KEYGEN_BIN" ] || fail "age-keygen is unavailable"
command -v python3 >/dev/null 2>&1 || fail "Python 3 is unavailable"

KP_MOUNT_POINT="$("$KP_DISKUTIL_BIN" info "$KP_EXTERNAL_VOLUME" \
  | /usr/bin/awk -F: '$1 ~ "^[[:space:]]*Mount Point[[:space:]]*$" {sub(/^[[:space:]]*/, "", $2); print $2}')"
KP_VOLUME_UUID_ACTUAL="$("$KP_DISKUTIL_BIN" info "$KP_EXTERNAL_VOLUME" \
  | /usr/bin/awk -F: '$1 ~ "^[[:space:]]*Volume UUID[[:space:]]*$" {sub(/^[[:space:]]*/, "", $2); print $2}')"
KP_VOLUME_READ_ONLY="$("$KP_DISKUTIL_BIN" info "$KP_EXTERNAL_VOLUME" \
  | /usr/bin/awk -F: '$1 ~ "^[[:space:]]*Volume Read-Only[[:space:]]*$" {sub(/^[[:space:]]*/, "", $2); print $2}')"
[ "$KP_MOUNT_POINT" = "$KP_EXTERNAL_VOLUME" ] \
  || fail "external volume is not mounted at the reviewed path"
[ "$KP_VOLUME_UUID_ACTUAL" = "$KP_EXTERNAL_VOLUME_UUID" ] \
  || fail "external volume UUID does not match"
[ "$KP_VOLUME_READ_ONLY" = No ] || fail "external volume is read-only"

[ -d "$KP_SNAPSHOT_ROOT" ] && [ ! -L "$KP_SNAPSHOT_ROOT" ] \
  || fail "snapshot root is absent or symbolic"
KP_SNAPSHOT_ROOT="$(cd "$KP_SNAPSHOT_ROOT" && pwd -P)"
case "$KP_SNAPSHOT_ROOT" in
  "$KP_EXTERNAL_VOLUME"/KingPhisher-Phoenix/migration-snapshots) ;;
  *) fail "snapshot root is outside the fixed external migration path" ;;
esac

[ -d "$KP_PROJECT_SOURCE" ] && [ ! -L "$KP_PROJECT_SOURCE" ] \
  || fail "canonical project source is absent or symbolic"
KP_PROJECT_SOURCE="$(cd "$KP_PROJECT_SOURCE" && pwd -P)"
[ -d "$KP_PROJECT_SOURCE/.git" ] && [ ! -L "$KP_PROJECT_SOURCE/.git" ] \
  || fail "canonical project source has no regular .git directory"
[ -x "$KP_EXTERNAL_ENGINE" ] && [ ! -L "$KP_EXTERNAL_ENGINE" ] \
  || fail "external engine helper is absent, non-executable, or symbolic"
[ ! -e "$KP_PROJECT_SOURCE/migration-checkpoint" ] \
  && [ ! -L "$KP_PROJECT_SOURCE/migration-checkpoint" ] \
  || fail "canonical migration-checkpoint already exists; it will not be replaced"

case "$KP_ARCHIVE" in
  /*/kingphisher-project-migration.tar.age) ;;
  *) fail "archive must be an absolute path with the fixed archive filename" ;;
esac
[ -f "$KP_ARCHIVE" ] && [ ! -L "$KP_ARCHIVE" ] \
  || fail "archive is absent, non-regular, or symbolic"
KP_ARCHIVE_PARENT_INPUT="$(dirname "$KP_ARCHIVE")"
[ -d "$KP_ARCHIVE_PARENT_INPUT" ] && [ ! -L "$KP_ARCHIVE_PARENT_INPUT" ] \
  || fail "snapshot directory is absent or symbolic"
KP_ARCHIVE_PARENT="$(cd "$KP_ARCHIVE_PARENT_INPUT" && pwd -P)"
case "$KP_ARCHIVE_PARENT" in
  "$KP_SNAPSHOT_ROOT"/*) ;;
  *) fail "archive is outside the reviewed snapshot root" ;;
esac
[ "$(dirname "$KP_ARCHIVE_PARENT")" = "$KP_SNAPSHOT_ROOT" ] \
  || fail "archive must be directly inside one snapshot directory"
KP_ARCHIVE="$KP_ARCHIVE_PARENT/kingphisher-project-migration.tar.age"
KP_OUTER_METADATA="$KP_ARCHIVE_PARENT/checkpoint-metadata.txt"
KP_OUTER_MANIFEST="$KP_ARCHIVE_PARENT/manifest.sha256"
for KP_REQUIRED_OUTER_FILE in "$KP_ARCHIVE" "$KP_OUTER_METADATA" "$KP_OUTER_MANIFEST"; do
  [ -f "$KP_REQUIRED_OUTER_FILE" ] && [ ! -L "$KP_REQUIRED_OUTER_FILE" ] \
    || fail "snapshot outer file is absent, non-regular, or symbolic: $(basename "$KP_REQUIRED_OUTER_FILE")"
done

KP_ARCHIVE_SIZE="$("$KP_STAT_BIN" -f %z "$KP_ARCHIVE")" \
  || fail "archive size cannot be read"
case "$KP_ARCHIVE_SIZE" in ''|*[!0-9]*) fail "archive size is malformed" ;; esac
[ "$KP_ARCHIVE_SIZE" -gt 0 ] && [ "$KP_ARCHIVE_SIZE" -le "$KP_MAX_ARCHIVE_BYTES" ] \
  || fail "archive is empty or exceeds the fixed 64 GiB bound"
[ "$("$KP_STAT_BIN" -f %z "$KP_OUTER_METADATA")" -le 65536 ] \
  || fail "outer checkpoint metadata exceeds 64 KiB"
[ "$("$KP_STAT_BIN" -f %z "$KP_OUTER_MANIFEST")" -le 1024 ] \
  || fail "outer manifest exceeds 1 KiB"

/usr/bin/awk '
  BEGIN { archive = 0; metadata = 0 }
  /^[0-9a-f]{64} [ *]kingphisher-project-migration\.tar\.age$/ { archive++; next }
  /^[0-9a-f]{64} [ *]checkpoint-metadata\.txt$/ { metadata++; next }
  { exit 1 }
  END { exit(archive == 1 && metadata == 1 ? 0 : 1) }
' "$KP_OUTER_MANIFEST" || fail "outer manifest must contain exactly the two fixed SHA-256 entries"
(
  cd "$KP_ARCHIVE_PARENT"
  "$KP_SHASUM_BIN" -a 256 -c manifest.sha256 >/dev/null
) || fail "outer snapshot SHA-256 manifest does not verify"

umask 077
KP_WORK_DIR="$(/usr/bin/mktemp -d /private/tmp/kp-stage-checkpoint.XXXXXX)" \
  || fail "could not create private staging workspace"
[ -d "$KP_WORK_DIR" ] && [ ! -L "$KP_WORK_DIR" ] \
  || fail "private staging workspace is invalid"
chmod 700 "$KP_WORK_DIR"
KP_IDENTITY_COPY="$KP_WORK_DIR/recovery-identity.txt"
if [ -n "$KP_RECOVERY_IDENTITY_FILE" ]; then
  case "$KP_RECOVERY_IDENTITY_FILE" in /*) ;; *) fail "explicit recovery identity path must be absolute" ;; esac
  [ -f "$KP_RECOVERY_IDENTITY_FILE" ] && [ ! -L "$KP_RECOVERY_IDENTITY_FILE" ] \
    || fail "explicit recovery identity is absent, non-regular, or symbolic"
  KP_IDENTITY_CONTRACT="$("$KP_STAT_BIN" -f '%u|%Lp' "$KP_RECOVERY_IDENTITY_FILE")"
  [ "$KP_IDENTITY_CONTRACT" = "$(id -u)|600" ] \
    || fail "explicit recovery identity must be owned by the current user with mode 0600"
  /bin/cp -p "$KP_RECOVERY_IDENTITY_FILE" "$KP_IDENTITY_COPY"
else
  [ -x "$KP_SECURITY_BIN" ] || fail "macOS Keychain command is unavailable"
  case "$KP_RECOVERY_KEYCHAIN_SERVICE" in
    com.kingphisher.phishing-awareness-platform.migration-recovery.*) ;;
    *) fail "Keychain service is outside the recovery namespace" ;;
  esac
  [ "$KP_RECOVERY_KEYCHAIN_ACCOUNT" = phishing-awareness-platform-recovery ] \
    || fail "Keychain account is outside the recovery namespace"
  "$KP_SECURITY_BIN" find-generic-password \
    -a "$KP_RECOVERY_KEYCHAIN_ACCOUNT" \
    -s "$KP_RECOVERY_KEYCHAIN_SERVICE" \
    -w > "$KP_IDENTITY_COPY" 2>/dev/null \
    || fail "recovery identity is unavailable from the named interactive Keychain"
fi
chmod 600 "$KP_IDENTITY_COPY"
KP_IDENTITY_KEY_COUNT="$(grep -Ec '^AGE-SECRET-KEY-1[0-9A-Z]+$' "$KP_IDENTITY_COPY" || true)"
[ "$KP_IDENTITY_KEY_COUNT" = 1 ] \
  || fail "recovery identity has an unexpected record count"
! grep -Evq '^AGE-SECRET-KEY-1[0-9A-Z]+$' "$KP_IDENTITY_COPY" \
  || fail "recovery identity contains unexpected content"
KP_LOCAL_RECIPIENT="$("$KP_AGE_KEYGEN_BIN" -y "$KP_IDENTITY_COPY" 2>/dev/null)" \
  || fail "recovery identity cannot derive a public recipient"
[[ "$KP_LOCAL_RECIPIENT" =~ ^age1[0-9a-z]+$ ]] \
  || fail "derived recovery recipient has an invalid format"

KP_DECRYPTED_TAR="$KP_WORK_DIR/checkpoint.tar"
"$KP_AGE_BIN" -d -i "$KP_IDENTITY_COPY" -o "$KP_DECRYPTED_TAR" "$KP_ARCHIVE" \
  || fail "archive decryption failed"
[ -f "$KP_DECRYPTED_TAR" ] && [ ! -L "$KP_DECRYPTED_TAR" ] \
  || fail "decrypted archive is not a regular file"
KP_DECRYPTED_SIZE="$("$KP_STAT_BIN" -f %z "$KP_DECRYPTED_TAR")"
case "$KP_DECRYPTED_SIZE" in ''|*[!0-9]*) fail "decrypted archive size is malformed" ;; esac
[ "$KP_DECRYPTED_SIZE" -gt 0 ] && [ "$KP_DECRYPTED_SIZE" -le "$KP_MAX_ARCHIVE_BYTES" ] \
  || fail "decrypted archive is empty or exceeds the fixed 64 GiB bound"

KP_EXTRACTED="$KP_WORK_DIR/extracted/migration-checkpoint"
mkdir -p "$KP_EXTRACTED"
chmod 700 "$KP_WORK_DIR/extracted" "$KP_EXTRACTED"
python3 -c '
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile

tar_path, output_text, base, canonical_source, outer_text, volume_uuid, recipient, snapshot_name = sys.argv[1:]
output = Path(output_text)
required_names = {
    f"{base}/migration-checkpoint/postgres.dump": "postgres.dump",
    f"{base}/migration-checkpoint/redis.rdb": "redis.rdb",
    f"{base}/migration-checkpoint/checkpoint-metadata.txt": "checkpoint-metadata.txt",
}
seen = set()
selected = {}
total_size = 0
with tarfile.open(tar_path, mode="r:") as archive:
    members = archive.getmembers()
    if not members or len(members) > 200000:
        raise SystemExit("archive member count is outside the fixed bound")
    for member in members:
        raw = member.name
        normalized = raw[:-1] if raw.endswith("/") else raw
        path = PurePosixPath(normalized)
        if not normalized or raw.startswith("/") or ".." in path.parts or "." in path.parts:
            raise SystemExit("archive contains an unsafe path")
        if str(path) != normalized or not (normalized == base or normalized.startswith(base + "/")):
            raise SystemExit("archive member escaped the canonical source tree")
        if normalized in seen:
            raise SystemExit("archive contains duplicate members")
        seen.add(normalized)
        if not (member.isdir() or member.isreg()):
            raise SystemExit("archive contains links or special files")
        if member.isreg():
            if member.size < 0 or member.size > 34359738368:
                raise SystemExit("archive member exceeds the fixed 32 GiB bound")
            total_size += member.size
            if total_size > 68719476736:
                raise SystemExit("archive payload exceeds the fixed 64 GiB bound")
        checkpoint_prefix = f"{base}/migration-checkpoint/"
        if normalized.startswith(checkpoint_prefix) and normalized not in required_names:
            raise SystemExit(f"reserved migration-checkpoint contains an unexpected member: {normalized}")
        if normalized in required_names:
            if not member.isreg() or member.size <= 0:
                raise SystemExit("required migration-checkpoint member is absent or empty")
            if normalized.endswith("checkpoint-metadata.txt") and member.size > 65536:
                raise SystemExit("internal checkpoint metadata exceeds 64 KiB")
            selected[normalized] = member
    if set(selected) != set(required_names):
        raise SystemExit("archive does not contain the exact required migration-checkpoint files")
    for name, filename in required_names.items():
        source = archive.extractfile(selected[name])
        if source is None:
            raise SystemExit("required archive member cannot be read")
        target = output / filename
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with source, os.fdopen(descriptor, "wb") as destination:
            while True:
                block = source.read(1024 * 1024)
                if not block:
                    break
                destination.write(block)

def parse_metadata(path):
    raw = Path(path).read_bytes()
    if not raw.endswith(b"\n") or b"\x00" in raw:
        raise SystemExit("checkpoint metadata framing is invalid")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise SystemExit("checkpoint metadata is not ASCII") from error
    result = {}
    for line in lines:
        if "=" not in line:
            raise SystemExit("checkpoint metadata line is malformed")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[a-z][a-z0-9_]*", key) or not value or key in result:
            raise SystemExit("checkpoint metadata key is invalid or duplicated")
        if any(ord(character) < 32 or ord(character) > 126 for character in value):
            raise SystemExit("checkpoint metadata value is invalid")
        result[key] = value
    return result

internal = parse_metadata(output / "checkpoint-metadata.txt")
outer = parse_metadata(outer_text)
fixed = {
    "schema", "source_root", "source_git_head", "docker_context", "compose_project",
    "postgres_container", "postgres_container_id", "postgres_dump_sha256",
    "redis_container", "redis_container_id", "redis_rdb_sha256",
    "external_volume_uuid", "local_recovery_recipient",
}
internal_recipient_keys = sorted(
    (key for key in internal if key.startswith("encryption_recipient_")),
    key=lambda item: int(item.removeprefix("encryption_recipient_"))
    if item.removeprefix("encryption_recipient_").isdigit()
    else -1,
)
expected_recipient_keys = [f"encryption_recipient_{index}" for index in range(1, len(internal_recipient_keys) + 1)]
if internal_recipient_keys != expected_recipient_keys or not internal_recipient_keys:
    raise SystemExit("checkpoint encryption recipient set is missing or non-contiguous")
if set(internal) != fixed | set(internal_recipient_keys):
    raise SystemExit("internal checkpoint metadata schema has unexpected fields")
if set(outer) != set(internal) | {"created_at", "archive_validation", "unrelated_container_state"}:
    raise SystemExit("outer checkpoint metadata schema has unexpected fields")
for key, value in internal.items():
    if outer.get(key) != value:
        raise SystemExit("inner and outer checkpoint metadata do not match")
if internal["schema"] != "kp.remote-migration-checkpoint.v1":
    raise SystemExit("checkpoint schema is unsupported")
if internal["source_root"] != canonical_source:
    raise SystemExit("checkpoint source root does not match the canonical project source")
if internal["docker_context"] != "desktop-linux" or internal["compose_project"] != "phishing-awareness-platform":
    raise SystemExit("checkpoint source engine or Compose project is not exact")
if internal["postgres_container"] != "phishing-awareness-platform-postgres-1":
    raise SystemExit("checkpoint PostgreSQL source container is not exact")
if internal["redis_container"] != "phishing-awareness-platform-redis-1":
    raise SystemExit("checkpoint Redis source container is not exact")
if internal["external_volume_uuid"] != volume_uuid:
    raise SystemExit("checkpoint external volume identity does not match")
if outer["archive_validation"] != "decrypt-and-full-tar-list-passed" or outer["unrelated_container_state"] != "unchanged":
    raise SystemExit("checkpoint source validation evidence is incomplete")
if not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z", outer["created_at"]):
    raise SystemExit("checkpoint timestamp is malformed")
if not re.fullmatch(re.escape(outer["created_at"]) + r"-[A-Za-z0-9]{6}", snapshot_name):
    raise SystemExit("checkpoint timestamp does not match its snapshot directory")
if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", internal["source_git_head"]):
    raise SystemExit("checkpoint Git identity is malformed")
for key in ("postgres_container_id", "redis_container_id"):
    if not re.fullmatch(r"[0-9a-f]{64}", internal[key]):
        raise SystemExit("checkpoint container identity is malformed")
for key in ("postgres_dump_sha256", "redis_rdb_sha256"):
    if not re.fullmatch(r"[0-9a-f]{64}", internal[key]):
        raise SystemExit("checkpoint payload digest is malformed")
recipients = [internal[key] for key in internal_recipient_keys]
if len(set(recipients)) != len(recipients) or any(not re.fullmatch(r"age1[0-9a-z]+", item) for item in recipients):
    raise SystemExit("checkpoint encryption recipient set is malformed or duplicated")
if internal["local_recovery_recipient"] != recipient or recipient not in recipients:
    raise SystemExit("recovery identity does not match the checkpoint recipient")
for filename, digest_key in (("postgres.dump", "postgres_dump_sha256"), ("redis.rdb", "redis_rdb_sha256")):
    digest_builder = hashlib.sha256()
    with (output / filename).open("rb") as payload:
        for block in iter(lambda: payload.read(1024 * 1024), b""):
            digest_builder.update(block)
    digest = digest_builder.hexdigest()
    if digest != internal[digest_key]:
        raise SystemExit(f"{filename} digest does not match checkpoint metadata")
' "$KP_DECRYPTED_TAR" "$KP_EXTRACTED" "$(basename "$KP_PROJECT_SOURCE")" \
  "$KP_PROJECT_SOURCE" "$KP_OUTER_METADATA" "$KP_VOLUME_UUID_ACTUAL" \
  "$KP_LOCAL_RECIPIENT" "$(basename "$KP_ARCHIVE_PARENT")" \
  || fail "encrypted archive structure, metadata, or payload validation failed"

(
  cd "$KP_ARCHIVE_PARENT"
  "$KP_SHASUM_BIN" -a 256 -c manifest.sha256 >/dev/null
) || fail "snapshot changed while it was being decrypted and validated"

"$KP_EXTERNAL_ENGINE" preflight >/dev/null \
  || fail "project-isolated external engine preflight failed"
"$KP_EXTERNAL_ENGINE" docker run --rm \
  --name "kp-stage-postgres-check-$$" \
  --pull never \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev \
  --entrypoint pg_restore \
  -i "$KP_POSTGRES_IMAGE" --list < "$KP_EXTRACTED/postgres.dump" >/dev/null \
  || fail "PostgreSQL logical archive failed isolated validation"
"$KP_EXTERNAL_ENGINE" docker run --rm -i \
  --name "kp-stage-redis-check-$$" \
  --pull never \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev \
  --entrypoint /bin/sh \
  "$KP_REDIS_IMAGE" -ec \
  'cat > /tmp/checkpoint.rdb; exec redis-check-rdb /tmp/checkpoint.rdb' \
  < "$KP_EXTRACTED/redis.rdb" >/dev/null \
  || fail "Redis RDB failed isolated validation"

if [ "$KP_APPLY" -ne 1 ]; then
  printf 'CHECKPOINT STAGING PREFLIGHT PASSED: archive=%s\n' "$KP_ARCHIVE"
  printf 'Re-run with --apply and the same exact archive path to publish migration-checkpoint.\n'
  exit 0
fi

[ ! -e "$KP_PROJECT_SOURCE/migration-checkpoint" ] \
  && [ ! -L "$KP_PROJECT_SOURCE/migration-checkpoint" ] \
  || fail "canonical migration-checkpoint appeared during validation; it will not be replaced"
KP_PUBLISH_DIR="$(/usr/bin/mktemp -d "$KP_PROJECT_SOURCE/.migration-checkpoint-stage.XXXXXX")" \
  || fail "could not create same-filesystem publication directory"
[ -d "$KP_PUBLISH_DIR" ] && [ ! -L "$KP_PUBLISH_DIR" ] \
  || fail "same-filesystem publication directory is invalid"
chmod 700 "$KP_PUBLISH_DIR"
for KP_PAYLOAD_FILE in postgres.dump redis.rdb checkpoint-metadata.txt; do
  /bin/cp -p "$KP_EXTRACTED/$KP_PAYLOAD_FILE" "$KP_PUBLISH_DIR/$KP_PAYLOAD_FILE"
  chmod 600 "$KP_PUBLISH_DIR/$KP_PAYLOAD_FILE"
  [ "$("$KP_SHASUM_BIN" -a 256 "$KP_EXTRACTED/$KP_PAYLOAD_FILE" | /usr/bin/awk '{print $1}')" = \
    "$("$KP_SHASUM_BIN" -a 256 "$KP_PUBLISH_DIR/$KP_PAYLOAD_FILE" | /usr/bin/awk '{print $1}')" ] \
    || fail "same-filesystem staged payload digest changed: $KP_PAYLOAD_FILE"
done
[ ! -e "$KP_PROJECT_SOURCE/migration-checkpoint" ] \
  && [ ! -L "$KP_PROJECT_SOURCE/migration-checkpoint" ] \
  || fail "canonical migration-checkpoint appeared before atomic publication"
/bin/mv -n "$KP_PUBLISH_DIR" "$KP_PROJECT_SOURCE/migration-checkpoint"
[ ! -e "$KP_PUBLISH_DIR" ] && [ -d "$KP_PROJECT_SOURCE/migration-checkpoint" ] \
  && [ ! -L "$KP_PROJECT_SOURCE/migration-checkpoint" ] \
  || fail "atomic no-clobber publication did not complete"
KP_PUBLISH_DIR=''
for KP_PAYLOAD_FILE in postgres.dump redis.rdb checkpoint-metadata.txt; do
  [ -f "$KP_PROJECT_SOURCE/migration-checkpoint/$KP_PAYLOAD_FILE" ] \
    && [ ! -L "$KP_PROJECT_SOURCE/migration-checkpoint/$KP_PAYLOAD_FILE" ] \
    || fail "published payload is absent, non-regular, or symbolic: $KP_PAYLOAD_FILE"
  [ "$("$KP_SHASUM_BIN" -a 256 "$KP_EXTRACTED/$KP_PAYLOAD_FILE" | /usr/bin/awk '{print $1}')" = \
    "$("$KP_SHASUM_BIN" -a 256 "$KP_PROJECT_SOURCE/migration-checkpoint/$KP_PAYLOAD_FILE" | /usr/bin/awk '{print $1}')" ] \
    || fail "published payload digest changed: $KP_PAYLOAD_FILE"
done
printf 'CHECKPOINT STAGING PASSED: target=%s\n' "$KP_PROJECT_SOURCE/migration-checkpoint"
printf 'archive_sha256=%s\n' \
  "$("$KP_SHASUM_BIN" -a 256 "$KP_ARCHIVE" | /usr/bin/awk '{print $1}')"
