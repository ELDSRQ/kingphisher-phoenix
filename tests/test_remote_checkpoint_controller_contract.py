from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKER = ROOT / "scripts/operator/remote-docker-worker"
pytestmark = pytest.mark.macos_only
CONTROLLER_PATH = WORKER / "checkpoint-remote.sh"
CHECKPOINT_PATH = WORKER / "checkpoint-state.sh"
CONTROLLER = CONTROLLER_PATH.read_text(encoding="utf-8")

PRIVATE_IDENTITY = "AGE-SECRET-KEY-1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
PUBLIC_RECIPIENT = "age1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
REMOTE_TARGET = "edierks@192.168.1.140"
REMOTE_CHECKPOINT = (
    "/Users/edierks/Projects/kingphisher-phoenix/scripts/operator/remote-docker-worker/checkpoint-state.sh"
)


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def _controller_environment(tmp_path: Path) -> tuple[dict[str, str], Path, Path, Path]:
    binaries = tmp_path / "bin"
    binaries.mkdir()
    ssh_log = tmp_path / "ssh.log"
    scp_log = tmp_path / "scp.log"
    local_path_log = tmp_path / "local-path.log"
    suffix = hashlib.sha256(str(tmp_path).encode()).hexdigest()[:6]
    remote_identity = Path(f"/private/tmp/kp-recovery-transfer.{suffix}")
    checkpoint_sha = hashlib.sha256(CHECKPOINT_PATH.read_bytes()).hexdigest()

    _write_executable(binaries / "uname", "#!/bin/sh\nprintf 'Darwin\\n'\n")
    _write_executable(
        binaries / "security",
        f"""#!/bin/sh
set -eu
[ "$1" = find-generic-password ]
printf '%s\\n' '{PRIVATE_IDENTITY}'
""",
    )
    _write_executable(
        binaries / "age-keygen",
        f"""#!/bin/sh
set -eu
[ "$1" = -y ]
printf '%s\\n' "$2" > "$KP_FAKE_LOCAL_PATH_LOG"
[ "$(grep -E '^AGE-SECRET-KEY-1[0-9A-Z]+$' "$2")" = '{PRIVATE_IDENTITY}' ]
printf '%s\\n' '{PUBLIC_RECIPIENT}'
""",
    )
    _write_executable(
        binaries / "ssh",
        f"""#!/bin/bash
set -eu
printf '%s\\n' "$*" >> "$KP_FAKE_SSH_LOG"
expected_checkpoint_call=' /usr/bin/env KP_RECOVERY_IDENTITY_FILE='
expected_checkpoint_call="$expected_checkpoint_call$KP_FAKE_REMOTE_IDENTITY /bin/bash"
expected_checkpoint_call="$expected_checkpoint_call {REMOTE_CHECKPOINT} --recipient {PUBLIC_RECIPIENT}"
case "$*" in
  *" /usr/bin/shasum -a 256 {REMOTE_CHECKPOINT}")
    printf '%s  %s\\n' "$KP_FAKE_CHECKPOINT_SHA" '{REMOTE_CHECKPOINT}'
    ;;
  *" /usr/bin/mktemp /private/tmp/kp-recovery-transfer.XXXXXX")
    : > "$KP_FAKE_REMOTE_IDENTITY"
    printf '%s\\n' "$KP_FAKE_REMOTE_IDENTITY"
    ;;
  *" /bin/chmod 600 $KP_FAKE_REMOTE_IDENTITY")
    /bin/chmod 600 "$KP_FAKE_REMOTE_IDENTITY"
    ;;
  *" /usr/bin/stat -f %Lp $KP_FAKE_REMOTE_IDENTITY")
    [ -f "$KP_FAKE_REMOTE_IDENTITY" ]
    printf '600\\n'
    ;;
  *"$expected_checkpoint_call"*)
    [ "$(grep -E '^AGE-SECRET-KEY-1[0-9A-Z]+$' "$KP_FAKE_REMOTE_IDENTITY")" = '{PRIVATE_IDENTITY}' ]
    if [ "${{KP_FAKE_CHECKPOINT_FAIL:-0}}" = 1 ]; then
      printf 'simulated remote checkpoint failure\\n' >&2
      exit 73
    fi
    printf 'CHECKPOINT PREFLIGHT PASSED: simulated exact source.\\n'
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
printf '%s\\n' "$*" >> "$KP_FAKE_SCP_LOG"
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
            "KP_FAKE_CHECKPOINT_SHA": checkpoint_sha,
            "KP_FAKE_LOCAL_PATH_LOG": str(local_path_log),
            "KP_FAKE_REMOTE_IDENTITY": str(remote_identity),
            "KP_FAKE_SSH_LOG": str(ssh_log),
            "KP_FAKE_SCP_LOG": str(scp_log),
        }
    )
    return environment, remote_identity, ssh_log, scp_log


def _run_controller(environment: dict[str, str], *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        ["/bin/bash", str(CONTROLLER_PATH), *arguments],
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


def _assert_transfer_files_removed(environment: dict[str, str], remote_identity: Path) -> None:
    local_identity = Path(Path(environment["KP_FAKE_LOCAL_PATH_LOG"]).read_text().strip())
    assert str(local_identity).startswith("/private/tmp/kp-recovery-controller.")
    assert not local_identity.exists()
    assert not remote_identity.exists()


def test_controller_dry_run_succeeds_without_leaking_identity(tmp_path: Path) -> None:
    environment, remote_identity, ssh_log, scp_log = _controller_environment(tmp_path)

    result = _run_controller(environment)

    assert result.returncode == 0, result.stderr
    assert "mode=dry-run" in result.stdout
    assert "CHECKPOINT PREFLIGHT PASSED" in result.stdout
    assert PRIVATE_IDENTITY not in result.stdout + result.stderr
    assert f"{REMOTE_TARGET}:{remote_identity}" in scp_log.read_text()
    checkpoint_call = next(line for line in ssh_log.read_text().splitlines() if "KP_RECOVERY_IDENTITY_FILE=" in line)
    assert "--apply" not in checkpoint_call
    _assert_transfer_files_removed(environment, remote_identity)


def test_controller_passes_through_apply_only_after_explicit_flag(tmp_path: Path) -> None:
    environment, remote_identity, ssh_log, _ = _controller_environment(tmp_path)

    result = _run_controller(environment, "--apply")

    assert result.returncode == 0, result.stderr
    assert "mode=apply" in result.stdout
    checkpoint_call = next(line for line in ssh_log.read_text().splitlines() if "KP_RECOVERY_IDENTITY_FILE=" in line)
    assert checkpoint_call.endswith(f"--recipient {PUBLIC_RECIPIENT} --apply")
    _assert_transfer_files_removed(environment, remote_identity)


def test_controller_cleans_both_exact_transfer_files_after_remote_failure(tmp_path: Path) -> None:
    environment, remote_identity, ssh_log, _ = _controller_environment(tmp_path)
    environment["KP_FAKE_CHECKPOINT_FAIL"] = "1"

    result = _run_controller(environment)

    assert result.returncode == 73
    assert "simulated remote checkpoint failure" in result.stderr
    assert PRIVATE_IDENTITY not in result.stdout + result.stderr
    assert f"/bin/rm -f -- {remote_identity}" in ssh_log.read_text()
    _assert_transfer_files_removed(environment, remote_identity)


def test_controller_blocks_remote_script_hash_mismatch_before_transfer(tmp_path: Path) -> None:
    environment, remote_identity, ssh_log, scp_log = _controller_environment(tmp_path)
    environment["KP_FAKE_CHECKPOINT_SHA"] = "b" * 64

    result = _run_controller(environment)

    assert result.returncode != 0
    assert "does not match the checked-in controller copy" in result.stderr
    assert "/usr/bin/mktemp /private/tmp/kp-recovery-transfer.XXXXXX" not in ssh_log.read_text()
    assert not scp_log.exists()
    assert not remote_identity.exists()
    local_identity = Path(Path(environment["KP_FAKE_LOCAL_PATH_LOG"]).read_text().strip())
    assert not local_identity.exists()
    assert PRIVATE_IDENTITY not in result.stdout + result.stderr


def test_controller_has_fixed_remote_scope_and_bounded_strict_transport() -> None:
    assert "KP_REMOTE_TARGET='edierks@192.168.1.140'" in CONTROLLER
    assert "KP_REMOTE_SOURCE='/Users/edierks/Projects/kingphisher-phoenix'" in CONTROLLER
    assert 'KP_REMOTE_TARGET="${' not in CONTROLLER
    assert 'KP_REMOTE_SOURCE="${' not in CONTROLLER
    assert "-o BatchMode=yes" in CONTROLLER
    assert "-o ConnectTimeout=10" in CONTROLLER
    assert "-o StrictHostKeyChecking=yes" in CONTROLLER
    assert "/private/tmp/kp-recovery-controller.XXXXXX" in CONTROLLER
    assert "/private/tmp/kp-recovery-transfer.XXXXXX" in CONTROLLER


def test_controller_uses_exact_keychain_item_and_hashes_before_transfer() -> None:
    assert "com.kingphisher.phishing-awareness-platform.migration-recovery.v1" in CONTROLLER
    assert "phishing-awareness-platform-recovery" in CONTROLLER
    assert "find-generic-password" in CONTROLLER
    assert 'chmod 600 "$KP_LOCAL_IDENTITY_FILE"' in CONTROLLER
    assert "/usr/bin/stat -f %Lp" in CONTROLLER
    hash_check = '[ "$KP_REMOTE_CHECKPOINT_SHA" = "$KP_LOCAL_CHECKPOINT_SHA" ]'
    transfer = '"$KP_SCP_BIN" -q'
    invoke = '"KP_RECOVERY_IDENTITY_FILE=$KP_REMOTE_IDENTITY_FILE"'
    assert CONTROLLER.index(hash_check) < CONTROLLER.index(transfer)
    assert CONTROLLER.index(transfer) < CONTROLLER.index(invoke)
    assert "set -x" not in CONTROLLER
    assert "docker " not in CONTROLLER
    assert "rm -rf" not in CONTROLLER
    assert "docker compose down" not in CONTROLLER
