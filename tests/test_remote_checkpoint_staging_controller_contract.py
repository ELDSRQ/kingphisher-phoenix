from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKER = ROOT / "scripts/operator/remote-docker-worker"

pytestmark = pytest.mark.macos_only
CONTROLLER_PATH = WORKER / "stage-remote.sh"
STAGER_PATH = WORKER / "stage-checkpoint.sh"
CONTROLLER = CONTROLLER_PATH.read_text(encoding="utf-8")

PRIVATE_IDENTITY = "AGE-SECRET-KEY-1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
PUBLIC_RECIPIENT = "age1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
REMOTE_TARGET = "edierks@192.168.1.140"
REMOTE_STAGER = "/Users/edierks/Projects/kingphisher-phoenix/scripts/operator/remote-docker-worker/stage-checkpoint.sh"
ARCHIVE = (
    "/Volumes/DockerExternal/KingPhisher-Phoenix/migration-snapshots/"
    "20260828T120000Z-ABC123/kingphisher-project-migration.tar.age"
)


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def _controller_environment(tmp_path: Path) -> tuple[dict[str, str], Path, Path, Path, Path]:
    binaries = tmp_path / "bin"
    binaries.mkdir()
    ssh_log = tmp_path / "ssh.log"
    scp_log = tmp_path / "scp.log"
    local_path_log = tmp_path / "local-path.log"
    suffix = hashlib.sha256(str(tmp_path).encode()).hexdigest()[:6]
    remote_identity = Path(f"/private/tmp/kp-recovery-stage-transfer.{suffix}")
    stager_sha = hashlib.sha256(STAGER_PATH.read_bytes()).hexdigest()

    _write_executable(binaries / "uname", "#!/bin/sh\nprintf 'Darwin\\n'\n")
    _write_executable(
        binaries / "security",
        f"""#!/bin/sh
set -eu
[ "$1" = find-generic-password ]
printf '%s\n' '{PRIVATE_IDENTITY}'
""",
    )
    _write_executable(
        binaries / "age-keygen",
        f"""#!/bin/sh
set -eu
[ "$1" = -y ]
printf '%s\n' "$2" > "$KP_FAKE_LOCAL_PATH_LOG"
[ "$(grep -E '^AGE-SECRET-KEY-1[0-9A-Z]+$' "$2")" = '{PRIVATE_IDENTITY}' ]
printf '%s\n' '{PUBLIC_RECIPIENT}'
""",
    )
    _write_executable(
        binaries / "ssh",
        f"""#!/bin/bash
set -eu
printf '%s\n' "$*" >> "$KP_FAKE_SSH_LOG"
expected_stage_call=' /usr/bin/env KP_RECOVERY_IDENTITY_FILE='
expected_stage_call="$expected_stage_call$KP_FAKE_REMOTE_IDENTITY /bin/bash"
expected_stage_call="$expected_stage_call {REMOTE_STAGER} --archive {ARCHIVE}"
case "$*" in
  *" /usr/bin/shasum -a 256 {REMOTE_STAGER}")
    printf '%s  %s\n' "$KP_FAKE_STAGER_SHA" '{REMOTE_STAGER}'
    ;;
  *" /usr/bin/mktemp /private/tmp/kp-recovery-stage-transfer.XXXXXX")
    : > "$KP_FAKE_REMOTE_IDENTITY"
    printf '%s\n' "$KP_FAKE_REMOTE_IDENTITY"
    ;;
  *" /bin/chmod 600 $KP_FAKE_REMOTE_IDENTITY")
    /bin/chmod 600 "$KP_FAKE_REMOTE_IDENTITY"
    ;;
  *" /usr/bin/stat -f %Lp $KP_FAKE_REMOTE_IDENTITY")
    [ -f "$KP_FAKE_REMOTE_IDENTITY" ]
    printf '600\n'
    ;;
  *"$expected_stage_call"*)
    [ "$(grep -E '^AGE-SECRET-KEY-1[0-9A-Z]+$' "$KP_FAKE_REMOTE_IDENTITY")" = '{PRIVATE_IDENTITY}' ]
    if [ "${{KP_FAKE_STAGE_FAIL:-0}}" = 1 ]; then
      printf 'simulated remote staging failure\n' >&2
      exit 74
    fi
    printf 'CHECKPOINT STAGING PREFLIGHT PASSED: simulated exact archive.\n'
    ;;
  *" /bin/rm -f -- $KP_FAKE_REMOTE_IDENTITY")
    /bin/rm -f -- "$KP_FAKE_REMOTE_IDENTITY"
    ;;
  *)
    exit 91
    ;;
esac
""",
    )
    _write_executable(
        binaries / "scp",
        f"""#!/bin/bash
set -eu
printf '%s\n' "$*" >> "$KP_FAKE_SCP_LOG"
previous=''
last=''
for argument in "$@"; do
  previous="$last"
  last="$argument"
done
[ "$last" = "{REMOTE_TARGET}:$KP_FAKE_REMOTE_IDENTITY" ]
/bin/cp "$previous" "$KP_FAKE_REMOTE_IDENTITY"
""",
    )

    environment = os.environ.copy()
    environment.update(
        {
            "PATH": f"{binaries}:{environment['PATH']}",
            "KP_SECURITY_BIN": str(binaries / "security"),
            "KP_AGE_KEYGEN_BIN": str(binaries / "age-keygen"),
            "KP_SSH_BIN": str(binaries / "ssh"),
            "KP_SCP_BIN": str(binaries / "scp"),
            "KP_FAKE_STAGER_SHA": stager_sha,
            "KP_FAKE_LOCAL_PATH_LOG": str(local_path_log),
            "KP_FAKE_REMOTE_IDENTITY": str(remote_identity),
            "KP_FAKE_SSH_LOG": str(ssh_log),
            "KP_FAKE_SCP_LOG": str(scp_log),
        }
    )
    return environment, remote_identity, ssh_log, scp_log, local_path_log


def _run_controller(
    environment: dict[str, str],
    *arguments: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        ["/bin/bash", str(CONTROLLER_PATH), *arguments],
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


def _assert_transfer_files_removed(local_path_log: Path, remote_identity: Path) -> None:
    local_identity = Path(local_path_log.read_text(encoding="utf-8").strip())
    assert str(local_identity).startswith("/private/tmp/kp-recovery-stage-controller.")
    assert not local_identity.exists()
    assert not remote_identity.exists()


def test_controller_staging_dry_run_succeeds_without_leaking_identity(tmp_path: Path) -> None:
    environment, remote_identity, ssh_log, scp_log, local_path_log = _controller_environment(tmp_path)

    result = _run_controller(environment, "--archive", ARCHIVE)

    assert result.returncode == 0, result.stderr
    assert "mode=dry-run" in result.stdout
    assert "CHECKPOINT STAGING PREFLIGHT PASSED" in result.stdout
    assert PRIVATE_IDENTITY not in result.stdout + result.stderr
    assert f"{REMOTE_TARGET}:{remote_identity}" in scp_log.read_text(encoding="utf-8")
    stage_call = next(
        line for line in ssh_log.read_text(encoding="utf-8").splitlines() if "KP_RECOVERY_IDENTITY_FILE=" in line
    )
    assert stage_call.endswith(f"--archive {ARCHIVE}")
    assert "--apply" not in stage_call
    _assert_transfer_files_removed(local_path_log, remote_identity)


def test_controller_passes_apply_only_after_explicit_flag(tmp_path: Path) -> None:
    environment, remote_identity, ssh_log, _, local_path_log = _controller_environment(tmp_path)

    result = _run_controller(environment, "--apply", "--archive", ARCHIVE)

    assert result.returncode == 0, result.stderr
    assert "mode=apply" in result.stdout
    stage_call = next(
        line for line in ssh_log.read_text(encoding="utf-8").splitlines() if "KP_RECOVERY_IDENTITY_FILE=" in line
    )
    assert stage_call.endswith(f"--archive {ARCHIVE} --apply")
    _assert_transfer_files_removed(local_path_log, remote_identity)


def test_controller_cleans_exact_transfer_files_after_remote_failure(tmp_path: Path) -> None:
    environment, remote_identity, ssh_log, _, local_path_log = _controller_environment(tmp_path)
    environment["KP_FAKE_STAGE_FAIL"] = "1"

    result = _run_controller(environment, "--archive", ARCHIVE)

    assert result.returncode == 74
    assert "simulated remote staging failure" in result.stderr
    assert PRIVATE_IDENTITY not in result.stdout + result.stderr
    assert f"/bin/rm -f -- {remote_identity}" in ssh_log.read_text(encoding="utf-8")
    _assert_transfer_files_removed(local_path_log, remote_identity)


def test_controller_blocks_remote_helper_tamper_before_identity_creation_or_transfer(tmp_path: Path) -> None:
    environment, remote_identity, ssh_log, scp_log, local_path_log = _controller_environment(tmp_path)
    environment["KP_FAKE_STAGER_SHA"] = "d" * 64

    result = _run_controller(environment, "--archive", ARCHIVE)

    assert result.returncode != 0
    assert "does not match the checked-in controller copy" in result.stderr
    assert "/usr/bin/mktemp /private/tmp/kp-recovery-stage-transfer.XXXXXX" not in ssh_log.read_text(encoding="utf-8")
    assert not scp_log.exists()
    assert not local_path_log.exists()
    assert not remote_identity.exists()
    assert PRIVATE_IDENTITY not in result.stdout + result.stderr


@pytest.mark.parametrize(
    "archive",
    (
        "migration-snapshots/20260828T120000Z-ABC123/kingphisher-project-migration.tar.age",
        "/Volumes/DockerExternal/KingPhisher-Phoenix/migration-snapshots/../escape/kingphisher-project-migration.tar.age",
        "/Volumes/DockerExternal/KingPhisher-Phoenix/migration-snapshots/20260828T120000Z/kingphisher-project-migration.tar.age",
        "/Volumes/DockerExternal/KingPhisher-Phoenix/migration-snapshots/20260828T120000Z-ABC123/nested/kingphisher-project-migration.tar.age",
    ),
)
def test_controller_rejects_archive_scope_ambiguity_before_remote_access(tmp_path: Path, archive: str) -> None:
    environment, remote_identity, ssh_log, scp_log, local_path_log = _controller_environment(tmp_path)

    result = _run_controller(environment, "--archive", archive)

    assert result.returncode != 0
    assert "outside the fixed current-schema snapshot namespace" in result.stderr
    assert not ssh_log.exists()
    assert not scp_log.exists()
    assert not local_path_log.exists()
    assert not remote_identity.exists()


def test_controller_has_fixed_remote_archive_and_transport_scope() -> None:
    assert "KP_REMOTE_TARGET='edierks@192.168.1.140'" in CONTROLLER
    assert "KP_REMOTE_SOURCE='/Users/edierks/Projects/kingphisher-phoenix'" in CONTROLLER
    assert "KP_REMOTE_SNAPSHOT_ROOT='/Volumes/DockerExternal/KingPhisher-Phoenix/migration-snapshots'" in CONTROLLER
    assert 'KP_REMOTE_TARGET="${' not in CONTROLLER
    assert 'KP_REMOTE_SOURCE="${' not in CONTROLLER
    assert "-o BatchMode=yes" in CONTROLLER
    assert "-o ConnectTimeout=10" in CONTROLLER
    assert "-o StrictHostKeyChecking=yes" in CONTROLLER
    assert "/private/tmp/kp-recovery-stage-controller.XXXXXX" in CONTROLLER
    assert "/private/tmp/kp-recovery-stage-transfer.XXXXXX" in CONTROLLER


def test_controller_hashes_remote_helper_before_identity_or_transfer() -> None:
    hash_check = '[ "$KP_REMOTE_STAGER_SHA" = "$KP_LOCAL_STAGER_SHA" ]'
    identity_create = "/private/tmp/kp-recovery-stage-controller.XXXXXX"
    transfer = '"$KP_SCP_BIN" -q'
    invocation = '"KP_RECOVERY_IDENTITY_FILE=$KP_REMOTE_IDENTITY_FILE"'

    assert CONTROLLER.index(hash_check) < CONTROLLER.index(identity_create)
    assert CONTROLLER.index(identity_create) < CONTROLLER.index(transfer)
    assert CONTROLLER.index(transfer) < CONTROLLER.index(invocation)
    assert "find-generic-password" in CONTROLLER
    assert "com.kingphisher.phishing-awareness-platform.migration-recovery.v1" in CONTROLLER
    assert "phishing-awareness-platform-recovery" in CONTROLLER
    assert 'chmod 600 "$KP_LOCAL_IDENTITY_FILE"' in CONTROLLER
    assert "/usr/bin/stat -f %Lp" in CONTROLLER


def test_controller_has_no_archive_or_docker_mutation_lane() -> None:
    forbidden = (
        "docker ",
        "docker compose down",
        "docker system prune",
        "docker volume rm",
        "colima delete",
        "rm -rf",
        'kingphisher-project-migration.tar.age"',
    )
    assert not any(command in CONTROLLER for command in forbidden)
    assert '"$KP_REMOTE_STAGER"' in CONTROLLER
    assert '"$KP_ARCHIVE"' in CONTROLLER
    assert "set -x" not in CONTROLLER
    assert PRIVATE_IDENTITY not in CONTROLLER
