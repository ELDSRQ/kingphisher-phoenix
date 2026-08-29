from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKER = ROOT / "scripts/operator/remote-docker-worker"
IDENTITY_PATH = WORKER / "recovery-identity.sh"
CHECKPOINT_PATH = WORKER / "checkpoint-state.sh"
IDENTITY = IDENTITY_PATH.read_text(encoding="utf-8")
CHECKPOINT = CHECKPOINT_PATH.read_text(encoding="utf-8")

PRIVATE_IDENTITY = "AGE-SECRET-KEY-1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
PUBLIC_RECIPIENT = "age1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def _identity_environment(tmp_path: Path) -> tuple[dict[str, str], Path]:
    binaries = tmp_path / "bin"
    binaries.mkdir()
    state = tmp_path / "keychain-item"
    _write_executable(binaries / "uname", "#!/bin/sh\nprintf 'Darwin\\n'\n")
    _write_executable(
        binaries / "age-keygen",
        f"""#!/bin/sh
set -eu
if [ "$1" = "-o" ]; then
  printf '%s\\n' '# created: 2026-08-28T00:00:00Z' '# public key: {PUBLIC_RECIPIENT}' '{PRIVATE_IDENTITY}' > "$2"
elif [ "$1" = "-y" ]; then
  [ "$(grep -E '^AGE-SECRET-KEY-1[0-9A-Z]+$' "$2")" = '{PRIVATE_IDENTITY}' ]
  printf '%s\\n' '{PUBLIC_RECIPIENT}'
else
  exit 2
fi
""",
    )
    _write_executable(
        binaries / "security",
        """#!/bin/sh
set -eu
command_name="$1"
shift
password=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -w)
      if [ "$#" -gt 1 ]; then password="$2"; shift 2; else shift; fi
      ;;
    *) shift ;;
  esac
done
case "$command_name" in
  find-generic-password)
    [ -f "$KP_FAKE_KEYCHAIN_STATE" ] || exit 44
    sed -n '1p' "$KP_FAKE_KEYCHAIN_STATE"
    ;;
  add-generic-password)
    [ ! -e "$KP_FAKE_KEYCHAIN_STATE" ] || exit 45
    [ -n "$password" ] || exit 46
    printf '%s\\n' "$password" > "$KP_FAKE_KEYCHAIN_STATE"
    ;;
  *) exit 2 ;;
esac
""",
    )
    environment = os.environ.copy()
    environment.update(
        {
            "PATH": f"{binaries}:{environment['PATH']}",
            "KP_SECURITY_BIN": str(binaries / "security"),
            "KP_AGE_KEYGEN_BIN": str(binaries / "age-keygen"),
            "KP_SECURE_TMP_ROOT": str(tmp_path),
            "KP_FAKE_KEYCHAIN_STATE": str(state),
        }
    )
    return environment, state


def _run_identity(mode: str, environment: dict[str, str], *, check: bool) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        ["/bin/bash", str(IDENTITY_PATH), mode],
        env=environment,
        check=check,
        capture_output=True,
        text=True,
    )


def test_recovery_identity_create_is_idempotent_and_never_prints_private_key(tmp_path: Path) -> None:
    environment, state = _identity_environment(tmp_path)

    created = _run_identity("create", environment, check=True)
    preserved = _run_identity("create", environment, check=True)
    verified = _run_identity("verify", environment, check=True)

    assert state.read_text(encoding="utf-8").strip() == PRIVATE_IDENTITY
    assert "recovery_identity=created" in created.stdout
    assert "recovery_identity=preserved" in preserved.stdout
    assert "recovery_identity=verified" in verified.stdout
    assert all(PUBLIC_RECIPIENT in result.stdout for result in (created, preserved, verified))
    assert all(PRIVATE_IDENTITY not in result.stdout + result.stderr for result in (created, preserved, verified))


def test_recovery_identity_fails_closed_on_expected_recipient_mismatch(tmp_path: Path) -> None:
    environment, state = _identity_environment(tmp_path)
    state.write_text(PRIVATE_IDENTITY + "\n", encoding="utf-8")
    environment["KP_RECOVERY_EXPECTED_RECIPIENT"] = "age1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

    result = _run_identity("verify", environment, check=False)

    assert result.returncode != 0
    assert "does not match KP_RECOVERY_EXPECTED_RECIPIENT" in result.stderr
    assert state.read_text(encoding="utf-8").strip() == PRIVATE_IDENTITY
    assert PRIVATE_IDENTITY not in result.stdout + result.stderr


def test_checkpoint_default_dry_run_checks_exact_state_without_database_mutation(tmp_path: Path) -> None:
    environment, state = _identity_environment(tmp_path)
    state.write_text(PRIVATE_IDENTITY + "\n", encoding="utf-8")
    binaries = Path(environment["KP_SECURITY_BIN"]).parent
    command_log = tmp_path / "docker-commands"
    source = tmp_path / "source"
    (source / ".git").mkdir(parents=True)
    (source / "data/recovery").mkdir(parents=True)
    (source / ".env").write_text("PRESERVED=not-rendered\n", encoding="utf-8")
    external_volume = tmp_path / "DockerExternal"
    snapshot_root = external_volume / "KingPhisher-Phoenix/migration-snapshots"
    snapshot_root.mkdir(parents=True)
    _write_executable(
        binaries / "docker",
        """#!/bin/sh
set -eu
printf '%s\\n' "$*" >> "$KP_FAKE_DOCKER_LOG"
case "$1 ${2:-}" in
  "context show") printf 'desktop-linux\\n' ;;
  "info ") exit 0 ;;
  "ps -a")
    printf '%s\\n' \
      'postgres-container-id|running|phishing-awareness-platform' \
      'redis-container-id|running|phishing-awareness-platform' \
      'unrelated-container-id|running|another-project'
    ;;
  "ps -aq")
    case "$*" in
      *service=postgres*) printf 'postgres-container-id\\n' ;;
      *service=redis*) printf 'redis-container-id\\n' ;;
      *) exit 2 ;;
    esac
    ;;
  "inspect --format")
    case "$*" in
      *phishing-awareness-platform-postgres-1*)
        container='phishing-awareness-platform-postgres-1'; service='postgres'; identifier='postgres-container-id'
        ;;
      *phishing-awareness-platform-redis-1*)
        container='phishing-awareness-platform-redis-1'; service='redis'; identifier='redis-container-id'
        ;;
      *) exit 2 ;;
    esac
    case "$*" in
      *'{{.Id}}'*) printf '%s\\n' "$identifier" ;;
      *'{{.Name}}'*) printf '/%s\\n' "$container" ;;
      *'.State.Running'*) printf 'phishing-awareness-platform|%s|true|healthy\\n' "$service" ;;
      *) exit 2 ;;
    esac
    ;;
  *) exit 2 ;;
esac
""",
    )
    _write_executable(
        binaries / "diskutil",
        """#!/bin/sh
set -eu
printf '   Mount Point: %s\\n' "$KP_FAKE_EXTERNAL_VOLUME"
printf '   Volume UUID: FD7BE277-8CB4-3ADA-8CA2-11F8EBBBADF4\\n'
""",
    )
    _write_executable(binaries / "age", "#!/bin/sh\nexit 99\n")
    _write_executable(binaries / "git", "#!/bin/sh\nexit 99\n")
    environment.update(
        {
            "KP_AGE_BIN": str(binaries / "age"),
            "KP_DISKUTIL_BIN": str(binaries / "diskutil"),
            "KP_EXTERNAL_VOLUME": str(external_volume),
            "KP_FAKE_DOCKER_LOG": str(command_log),
            "KP_FAKE_EXTERNAL_VOLUME": str(external_volume),
            "KP_PROJECT_ROOT": str(source),
            "KP_SNAPSHOT_ROOT": str(snapshot_root),
        }
    )
    environment.pop("DOCKER_CONTEXT", None)
    environment.pop("DOCKER_CONFIG", None)
    environment.pop("DOCKER_HOST", None)

    result = subprocess.run(  # noqa: S603
        ["/bin/bash", str(CHECKPOINT_PATH), "--recipient", PUBLIC_RECIPIENT],
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )

    commands = command_log.read_text(encoding="utf-8")
    assert "CHECKPOINT PREFLIGHT PASSED" in result.stdout
    assert "exec " not in commands
    assert " cp " not in commands
    assert "stop" not in commands
    assert PRIVATE_IDENTITY not in result.stdout + result.stderr
    assert list(snapshot_root.iterdir()) == []


def test_identity_uses_narrow_keychain_item_without_overwrite_or_secret_output() -> None:
    assert "com.kingphisher.phishing-awareness-platform.migration-recovery.v1" in IDENTITY
    assert "phishing-awareness-platform-recovery" in IDENTITY
    assert "find-generic-password" in IDENTITY
    assert "add-generic-password" in IDENTITY
    assert "add-generic-password -U" not in IDENTITY
    assert "printf 'recovery_recipient=%s\\n'" in IDENTITY
    assert "set -x" not in IDENTITY
    assert "rm -rf" not in IDENTITY


def test_checkpoint_is_dry_run_by_default_and_mutations_follow_apply_gate() -> None:
    apply_gate = 'if [ "$KP_APPLY" -ne 1 ]'
    logical_dump = 'docker exec "$KP_POSTGRES_CONTAINER" pg_dump'
    redis_save = "redis-cli --no-auth-warning BGSAVE"
    encrypted_archive = '| "$KP_AGE_BIN" "${KP_AGE_ARGS[@]}" -o "$KP_ARCHIVE"'

    assert "KP_APPLY=0" in CHECKPOINT
    assert "--apply)" in CHECKPOINT
    assert CHECKPOINT.index(apply_gate) < CHECKPOINT.index(logical_dump)
    assert CHECKPOINT.index(apply_gate) < CHECKPOINT.index(redis_save)
    assert CHECKPOINT.index(apply_gate) < CHECKPOINT.index(encrypted_archive)


def test_checkpoint_allows_only_a_private_exactly_scoped_identity_transfer() -> None:
    assert 'KP_RECOVERY_IDENTITY_FILE="${KP_RECOVERY_IDENTITY_FILE:-}"' in CHECKPOINT
    assert "/private/tmp/kp-recovery-transfer.*" in CHECKPOINT
    assert "explicit recovery identity must use the private transfer namespace" in CHECKPOINT
    assert "explicit recovery identity is absent, non-regular, or symbolic" in CHECKPOINT
    assert "$(id -u)|600" in CHECKPOINT
    assert '/bin/cp -p "$KP_RECOVERY_IDENTITY_FILE" "$KP_IDENTITY_FILE"' in CHECKPOINT


def test_checkpoint_pins_exact_healthy_project_database_containers() -> None:
    assert "KP_PROJECT_NAME=phishing-awareness-platform" in CHECKPOINT
    assert "KP_POSTGRES_CONTAINER=phishing-awareness-platform-postgres-1" in CHECKPOINT
    assert "KP_REDIS_CONTAINER=phishing-awareness-platform-redis-1" in CHECKPOINT
    assert "label=com.docker.compose.project=$KP_PROJECT_NAME" in CHECKPOINT
    assert "label=com.docker.compose.service=$KP_SERVICE_NAME" in CHECKPOINT
    assert "$KP_PROJECT_NAME|$KP_SERVICE_NAME|true|healthy" in CHECKPOINT
    assert "KP_EXPECTED_CONTEXT=desktop-linux" in CHECKPOINT
    assert "DOCKER_HOST must be unset" in CHECKPOINT
    assert "DOCKER_CONTEXT must be unset" in CHECKPOINT
    assert "DOCKER_CONFIG must be unset" in CHECKPOINT


def test_checkpoint_validates_both_logical_datastores_before_encryption() -> None:
    postgres_dump = "pg_dump"
    postgres_validate = "pg_restore --list"
    redis_save = "redis-cli --no-auth-warning BGSAVE"
    redis_complete = "rdb_last_bgsave_status:ok"
    redis_lastsave = "redis-cli --no-auth-warning LASTSAVE"
    redis_validate = "redis-check-rdb /data/dump.rdb"
    redis_digest = 'KP_REDIS_SOURCE_SHA="$(docker exec'
    encryption = '| "$KP_AGE_BIN"'

    assert CHECKPOINT.index(postgres_dump) < CHECKPOINT.index(postgres_validate)
    assert CHECKPOINT.index(postgres_validate) < CHECKPOINT.index(encryption)
    assert CHECKPOINT.index(redis_save) < CHECKPOINT.index(redis_complete)
    assert CHECKPOINT.index(redis_lastsave) < CHECKPOINT.index(redis_save)
    assert CHECKPOINT.index(redis_complete) < CHECKPOINT.index(redis_validate)
    assert CHECKPOINT.index(redis_validate) < CHECKPOINT.index(redis_digest)
    assert CHECKPOINT.index(redis_digest) < CHECKPOINT.index(encryption)


def test_checkpoint_streams_full_source_with_only_reviewed_cache_exclusions() -> None:
    assert "COPYFILE_DISABLE=1 tar -cf - \\\n" in CHECKPOINT
    assert '--exclude="$KP_SOURCE_BASENAME/.venv"' in CHECKPOINT
    assert '--exclude="$KP_SOURCE_BASENAME/infrastructure/terraform/.terraform"' in CHECKPOINT
    assert CHECKPOINT.count("--exclude=") == 2
    for required_member in (
        '"$KP_SOURCE_BASENAME/.env"',
        '"$KP_SOURCE_BASENAME/.git/"',
        '"$KP_SOURCE_BASENAME/data/"',
        '"$KP_SOURCE_BASENAME/data/recovery/"',
        '"$KP_SOURCE_BASENAME/migration-checkpoint/postgres.dump"',
        '"$KP_SOURCE_BASENAME/migration-checkpoint/redis.rdb"',
        '"$KP_SOURCE_BASENAME/migration-checkpoint/checkpoint-metadata.txt"',
    ):
        assert required_member in CHECKPOINT
    assert '"$KP_AGE_BIN" -d -i "$KP_IDENTITY_FILE" "$KP_ARCHIVE" | tar -tf -' in CHECKPOINT


def test_reviewed_tar_shape_merges_new_checkpoint_and_excludes_only_caches(tmp_path: Path) -> None:
    source_parent = tmp_path / "source-parent"
    source = source_parent / "source"
    staged = tmp_path / "staged/source/migration-checkpoint"
    for directory in (
        source / ".git",
        source / "data/recovery",
        source / ".venv",
        source / "infrastructure/terraform/.terraform",
        staged,
    ):
        directory.mkdir(parents=True, exist_ok=True)
    (source / ".env").write_text("SECRET=preserved\n", encoding="utf-8")
    (source / ".git/HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (source / "data/recovery/evidence").write_text("preserved\n", encoding="utf-8")
    (source / ".venv/regenerable").write_text("omit\n", encoding="utf-8")
    (source / "infrastructure/terraform/.terraform/provider").write_text("omit\n", encoding="utf-8")
    (staged / "postgres.dump").write_bytes(b"postgres")
    (staged / "redis.rdb").write_bytes(b"redis")
    archive = tmp_path / "checkpoint.tar"

    subprocess.run(  # noqa: S603
        [
            "/usr/bin/tar",
            "-cf",
            str(archive),
            "--exclude=source/.venv",
            "--exclude=source/infrastructure/terraform/.terraform",
            "-C",
            str(source_parent),
            "source",
            "-C",
            str(tmp_path / "staged"),
            "source/migration-checkpoint",
        ],
        check=True,
    )
    listing = subprocess.run(  # noqa: S603
        ["/usr/bin/tar", "-tf", str(archive)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()

    assert "source/.env" in listing
    assert "source/.git/HEAD" in listing
    assert "source/data/recovery/evidence" in listing
    assert "source/migration-checkpoint/postgres.dump" in listing
    assert "source/migration-checkpoint/redis.rdb" in listing
    assert not any(member.startswith("source/.venv/") for member in listing)
    assert not any(member.startswith("source/infrastructure/terraform/.terraform/") for member in listing)


def test_checkpoint_atomically_publishes_hashed_validated_archive() -> None:
    decrypt_validation = '"$KP_AGE_BIN" -d -i "$KP_IDENTITY_FILE" "$KP_ARCHIVE" | tar -tf -'
    hash_manifest = "shasum -a 256 kingphisher-project-migration.tar.age checkpoint-metadata.txt"
    hash_check = "shasum -a 256 -c manifest.sha256"
    publish = '/bin/mv -n "$KP_PARTIAL_DIR" "$KP_FINAL_DIR"'

    assert CHECKPOINT.index(decrypt_validation) < CHECKPOINT.index(hash_manifest)
    assert CHECKPOINT.index(hash_manifest) < CHECKPOINT.index(hash_check)
    assert CHECKPOINT.index(hash_check) < CHECKPOINT.index(publish)
    assert 'mktemp -d "$KP_SNAPSHOT_ROOT/.checkpoint-partial.' in CHECKPOINT
    assert '$(/usr/bin/stat -f %i "$KP_FINAL_DIR")" = "$KP_PARTIAL_INODE"' in CHECKPOINT
    assert "KP_PARTIAL_DIR=''" in CHECKPOINT


def test_checkpoint_records_unrelated_container_state_before_and_after() -> None:
    assert "unrelated_inventory()" in CHECKPOINT
    assert "{{.ID}}|{{.State}}" in CHECKPOINT
    assert CHECKPOINT.index('KP_UNRELATED_BEFORE="$(unrelated_inventory)"') < CHECKPOINT.index(
        'docker exec "$KP_POSTGRES_CONTAINER" pg_dump'
    )
    assert CHECKPOINT.index('KP_UNRELATED_AFTER="$(unrelated_inventory)"') < CHECKPOINT.index(
        '/bin/mv -n "$KP_PARTIAL_DIR" "$KP_FINAL_DIR"'
    )
    assert "unrelated container identity or running state changed" in CHECKPOINT


def test_checkpoint_has_no_container_or_project_cleanup_lane() -> None:
    forbidden = (
        "docker compose down",
        "docker stop",
        "docker rm",
        "docker volume rm",
        "docker image rm",
        "docker system prune",
        "docker builder prune",
        "docker buildx prune",
        "colima delete",
        "git clean",
        "git reset",
        "rm -rf",
    )
    assert not any(command in CHECKPOINT for command in forbidden)
    assert '/bin/rm -R -- "$KP_WORK_DIR"' in CHECKPOINT
    assert '/bin/rm -R -- "$KP_PARTIAL_DIR"' in CHECKPOINT
