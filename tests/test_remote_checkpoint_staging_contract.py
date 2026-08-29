from __future__ import annotations

import hashlib
import io
import os
import subprocess
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGER_PATH = ROOT / "scripts/operator/remote-docker-worker/stage-checkpoint.sh"
STAGER = STAGER_PATH.read_text(encoding="utf-8")

PRIVATE_IDENTITY = "AGE-SECRET-KEY-1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
PUBLIC_RECIPIENT = "age1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
VOLUME_UUID = "FD7BE277-8CB4-3ADA-8CA2-11F8EBBBADF4"
CREATED_AT = "20260828T120000Z"


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def _checkpoint_metadata(source: Path, postgres: bytes, redis: bytes) -> bytes:
    values = (
        "schema=kp.remote-migration-checkpoint.v1",
        f"source_root={source.resolve()}",
        f"source_git_head={'a' * 40}",
        "docker_context=desktop-linux",
        "compose_project=phishing-awareness-platform",
        "postgres_container=phishing-awareness-platform-postgres-1",
        f"postgres_container_id={'b' * 64}",
        f"postgres_dump_sha256={hashlib.sha256(postgres).hexdigest()}",
        "redis_container=phishing-awareness-platform-redis-1",
        f"redis_container_id={'c' * 64}",
        f"redis_rdb_sha256={hashlib.sha256(redis).hexdigest()}",
        f"external_volume_uuid={VOLUME_UUID}",
        f"local_recovery_recipient={PUBLIC_RECIPIENT}",
        f"encryption_recipient_1={PUBLIC_RECIPIENT}",
    )
    return ("\n".join(values) + "\n").encode()


def _add_bytes(archive: tarfile.TarFile, name: str, content: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.mode = 0o600
    info.size = len(content)
    archive.addfile(info, io.BytesIO(content))


def _build_snapshot(
    snapshot_root: Path,
    source: Path,
    *,
    unsafe_member: tarfile.TarInfo | None = None,
) -> Path:
    postgres = b"valid-postgres-custom-archive"
    redis = b"REDIS0011-valid-rdb"
    internal = _checkpoint_metadata(source, postgres, redis)
    snapshot = snapshot_root / f"{CREATED_AT}-ABC123"
    snapshot.mkdir(parents=True)
    archive_path = snapshot / "kingphisher-project-migration.tar.age"
    base = source.name
    with tarfile.open(archive_path, "w") as archive:
        _add_bytes(archive, f"{base}/.env", b"PRESERVED=true\n")
        _add_bytes(archive, f"{base}/.git/HEAD", b"ref: refs/heads/main\n")
        _add_bytes(archive, f"{base}/data/recovery/evidence.txt", b"preserved\n")
        _add_bytes(archive, f"{base}/migration-checkpoint/postgres.dump", postgres)
        _add_bytes(archive, f"{base}/migration-checkpoint/redis.rdb", redis)
        _add_bytes(archive, f"{base}/migration-checkpoint/checkpoint-metadata.txt", internal)
        if unsafe_member is not None:
            archive.addfile(unsafe_member)

    outer = (
        b"created_at="
        + CREATED_AT.encode()
        + b"\n"
        + internal
        + (b"archive_validation=decrypt-and-full-tar-list-passed\nunrelated_container_state=unchanged\n")
    )
    metadata_path = snapshot / "checkpoint-metadata.txt"
    metadata_path.write_bytes(outer)
    manifest = snapshot / "manifest.sha256"
    manifest.write_text(
        f"{hashlib.sha256(archive_path.read_bytes()).hexdigest()}  {archive_path.name}\n"
        f"{hashlib.sha256(outer).hexdigest()}  {metadata_path.name}\n",
        encoding="ascii",
    )
    return archive_path


def _environment(tmp_path: Path) -> tuple[dict[str, str], Path, Path, Path]:
    binaries = tmp_path / "bin"
    binaries.mkdir()
    external = tmp_path / "DockerExternal"
    snapshot_root = external / "KingPhisher-Phoenix/migration-snapshots"
    snapshot_root.mkdir(parents=True)
    source = tmp_path / "kingphisher-phoenix"
    (source / ".git").mkdir(parents=True)
    identity = tmp_path / "recovery-identity.txt"
    identity.write_text(PRIVATE_IDENTITY + "\n", encoding="ascii")
    identity.chmod(0o600)
    command_log = tmp_path / "external-engine.log"

    _write_executable(binaries / "uname", "#!/bin/sh\nprintf 'Darwin\\n'\n")
    _write_executable(
        binaries / "diskutil",
        """#!/bin/sh
set -eu
printf '   Mount Point: %s\n' "$KP_FAKE_EXTERNAL_VOLUME"
printf '   Volume UUID: FD7BE277-8CB4-3ADA-8CA2-11F8EBBBADF4\n'
printf '   Volume Read-Only: No\n'
""",
    )
    _write_executable(
        binaries / "stat",
        """#!/usr/bin/env python3
import os, stat, sys
value = os.stat(sys.argv[3])
if sys.argv[2] == "%z":
    print(value.st_size)
elif sys.argv[2] == "%u|%Lp":
    print(f"{value.st_uid}|{stat.S_IMODE(value.st_mode):o}")
else:
    raise SystemExit(2)
""",
    )
    _write_executable(
        binaries / "age",
        """#!/bin/sh
set -eu
output=''
input=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -d) shift ;;
    -i) shift 2 ;;
    -o) output="$2"; shift 2 ;;
    *) input="$1"; shift ;;
  esac
done
cp "$input" "$output"
""",
    )
    _write_executable(
        binaries / "age-keygen",
        f"#!/bin/sh\n[ \"$1\" = -y ] || exit 2\nprintf '%s\\n' '{PUBLIC_RECIPIENT}'\n",
    )
    external_engine = source / "scripts/operator/remote-docker-worker/external-engine.sh"
    external_engine.parent.mkdir(parents=True)
    _write_executable(
        external_engine,
        """#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$KP_FAKE_EXTERNAL_ENGINE_LOG"
if [ "$1" = preflight ]; then
  exit 0
fi
[ "$1" = docker ] && [ "$2" = run ] || exit 2
cat >/dev/null
""",
    )
    environment = os.environ.copy()
    environment.update(
        {
            "PATH": f"{binaries}:{environment['PATH']}",
            "KP_AGE_BIN": str(binaries / "age"),
            "KP_AGE_KEYGEN_BIN": str(binaries / "age-keygen"),
            "KP_DISKUTIL_BIN": str(binaries / "diskutil"),
            "KP_STAT_BIN": str(binaries / "stat"),
            "KP_EXTERNAL_VOLUME": str(external),
            "KP_SNAPSHOT_ROOT": str(snapshot_root),
            "KP_PROJECT_SOURCE": str(source),
            "KP_EXTERNAL_ENGINE": str(external_engine),
            "KP_RECOVERY_IDENTITY_FILE": str(identity),
            "KP_FAKE_EXTERNAL_VOLUME": str(external),
            "KP_FAKE_EXTERNAL_ENGINE_LOG": str(command_log),
        }
    )
    return environment, snapshot_root, source, command_log


def _run_stager(
    archive: Path,
    environment: dict[str, str],
    *,
    apply: bool,
) -> subprocess.CompletedProcess[str]:
    arguments = ["/bin/bash", str(STAGER_PATH)]
    if apply:
        arguments.append("--apply")
    arguments.extend(("--archive", str(archive)))
    return subprocess.run(  # noqa: S603
        arguments,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


def test_stager_dry_run_validates_without_publishing_plaintext(tmp_path: Path) -> None:
    environment, snapshot_root, source, command_log = _environment(tmp_path)
    archive = _build_snapshot(snapshot_root, source)

    result = _run_stager(archive, environment, apply=False)

    assert result.returncode == 0, result.stderr
    assert "CHECKPOINT STAGING PREFLIGHT PASSED" in result.stdout
    assert not (source / "migration-checkpoint").exists()
    assert archive.exists()
    commands = command_log.read_text(encoding="utf-8")
    assert "preflight" in commands
    assert "pg_restore" in commands
    assert "redis-check-rdb" in commands


def test_stager_apply_publishes_only_the_three_validated_files(tmp_path: Path) -> None:
    environment, snapshot_root, source, _ = _environment(tmp_path)
    archive = _build_snapshot(snapshot_root, source)

    result = _run_stager(archive, environment, apply=True)

    assert result.returncode == 0, result.stderr
    assert "CHECKPOINT STAGING PASSED" in result.stdout
    staged = source / "migration-checkpoint"
    assert {item.name for item in staged.iterdir()} == {
        "postgres.dump",
        "redis.rdb",
        "checkpoint-metadata.txt",
    }
    assert oct(staged.stat().st_mode & 0o777) == "0o700"
    assert all(oct(item.stat().st_mode & 0o777) == "0o600" for item in staged.iterdir())
    assert archive.exists()

    repeated = _run_stager(archive, environment, apply=True)
    assert repeated.returncode != 0
    assert "already exists; it will not be replaced" in repeated.stderr


def test_stager_rejects_links_inside_the_encrypted_tar(tmp_path: Path) -> None:
    environment, snapshot_root, source, _ = _environment(tmp_path)
    link = tarfile.TarInfo(f"{source.name}/unsafe-link")
    link.type = tarfile.SYMTYPE
    link.linkname = "/etc/passwd"
    archive = _build_snapshot(snapshot_root, source, unsafe_member=link)

    result = _run_stager(archive, environment, apply=False)

    assert result.returncode != 0
    assert "structure, metadata, or payload validation failed" in result.stderr
    assert not (source / "migration-checkpoint").exists()
    assert archive.exists()


def test_stager_contract_is_fixed_dry_run_and_fail_closed() -> None:
    apply_gate = 'if [ "$KP_APPLY" -ne 1 ]'
    publish = '/bin/mv -n "$KP_PUBLISH_DIR" "$KP_PROJECT_SOURCE/migration-checkpoint"'

    assert "KP_APPLY=0" in STAGER
    assert "--archive)" in STAGER
    assert "kingphisher-project-migration.tar.age" in STAGER
    assert STAGER.index(apply_gate) < STAGER.index(publish)
    assert "FD7BE277-8CB4-3ADA-8CA2-11F8EBBBADF4" in STAGER
    assert "snapshot root is outside the fixed external migration path" in STAGER
    assert "canonical migration-checkpoint already exists; it will not be replaced" in STAGER


def test_stager_checks_outer_and_encrypted_inner_evidence() -> None:
    assert '"$KP_SHASUM_BIN" -a 256 -c manifest.sha256' in STAGER
    assert '"schema"' in STAGER
    assert "kp.remote-migration-checkpoint.v1" in STAGER
    assert "inner and outer checkpoint metadata do not match" in STAGER
    assert "recovery identity does not match the checkpoint recipient" in STAGER
    assert 'raise SystemExit(f"{filename} digest does not match checkpoint metadata")' in STAGER
    assert "archive contains duplicate members" in STAGER
    assert "archive contains links or special files" in STAGER
    assert "archive contains an unsafe path" in STAGER
    assert "archive member exceeds the fixed 32 GiB bound" in STAGER


def test_stager_uses_only_the_project_isolated_engine_and_pinned_images() -> None:
    assert '"$KP_EXTERNAL_ENGINE" preflight' in STAGER
    assert STAGER.count('"$KP_EXTERNAL_ENGINE" docker run') == 2
    assert "postgres:16-alpine@sha256:57c72fd2" in STAGER
    assert "redis:7-alpine@sha256:e7723ff73d963f5" in STAGER
    assert "--pull never" in STAGER
    assert "--network none" in STAGER
    assert "docker context use" not in STAGER
    assert "docker --context desktop-linux" not in STAGER
    assert "docker compose down" not in STAGER
    assert "docker system prune" not in STAGER
    assert "docker volume rm" not in STAGER
    assert "colima delete" not in STAGER
    assert "rm -rf" not in STAGER


def test_stager_identity_is_exact_and_never_printed() -> None:
    assert '"$(id -u)|600"' in STAGER
    assert "explicit recovery identity is absent, non-regular, or symbolic" in STAGER
    assert "find-generic-password" in STAGER
    assert "com.kingphisher.phishing-awareness-platform.migration-recovery.v1" in STAGER
    assert "phishing-awareness-platform-recovery" in STAGER
    assert "set -x" not in STAGER
    assert PRIVATE_IDENTITY not in STAGER
