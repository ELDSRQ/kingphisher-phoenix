"""Private IO, subprocess diagnostics and the explicit one-phase boundary."""

from __future__ import annotations

import importlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

TOOL = Path(__file__).resolve().parents[1] / "scripts/operator/recovery-qualification"


sys.path.insert(0, str(TOOL))
c = importlib.import_module("common")
assert Path(c.__file__).resolve() == TOOL / "common.py"


@pytest.fixture
def private(tmp_path):
    tmp_path.chmod(0o700)
    return tmp_path.resolve()


def test_exclusive_file_retains_original(private):
    path = private / "identity"
    c.private_bytes(path, b"first")
    with pytest.raises(FileExistsError):
        c.private_bytes(path, b"second")
    assert path.read_bytes() == b"first"
    assert path.stat().st_mode & 0o777 == 0o600


def test_symlink_and_public_file_refused(private):
    path = private / "private"
    c.private_bytes(path, b"private")
    (private / "alias").symlink_to(path)
    with pytest.raises(c.RecoveryError, match="noncanonical"):
        c.private_file(private / "alias")
    path.chmod(0o644)
    with pytest.raises(c.RecoveryError, match="file_not_private"):
        c.private_file(path)


@pytest.mark.parametrize("name", ["../keys", "/keys", "a//b", "a/./b", "a/../b", ".git/config", "a\\b", "a\0b"])
def test_unsafe_archive_name_refused(name):
    with pytest.raises(c.RecoveryError):
        c.relative_name(name)


def test_subprocess_secret_inputs_not_logged(private):
    output = c.command(
        [sys.executable, "-c", "import os,sys; print(os.environ['RECOVERY_INPUT']); print(sys.stdin.read())"],
        timeout=5,
        input_data=b"stdin-secret",
        env={"RECOVERY_INPUT": "environment-secret"},
        evidence=private,
        record=False,
    )
    assert b"stdin-secret" in output and b"environment-secret" in output
    assert list(private.iterdir()) == []


def test_missing_executable_safe_private_diagnostic(private):
    with pytest.raises(c.RecoveryError, match="command_could_not_run"):
        c.command([str(private / "missing")], timeout=2, evidence=private)
    metadata = json.loads(next(private.glob("*.json")).read_text())
    assert metadata["error_type"] == "FileNotFoundError"
    assert metadata["returncode"] is None
    assert "argv" not in metadata and "env" not in metadata


def test_timeout_retains_partial_output(private):
    with pytest.raises(c.RecoveryError, match="command_timed_out"):
        c.command(
            [sys.executable, "-c", "import time;print('partial',flush=True);time.sleep(2)"],
            timeout=0.1,
            evidence=private,
        )
    assert next(private.glob("*.stdout")).read_bytes() == b"partial\n"
    metadata = json.loads(next(private.glob("*.json")).read_text())
    assert metadata["timed_out"] is True


def test_failed_command_does_not_echo_output(private):
    with pytest.raises(c.RecoveryError, match="^command_failed$"):
        c.command(
            [sys.executable, "-c", "import sys;print('private-failure');sys.exit(2)"], timeout=5, evidence=private
        )
    assert next(private.glob("*.stdout")).read_bytes() == b"private-failure\n"


def test_no_inherited_docker_endpoint(monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", "unix:///unrelated.sock")
    monkeypatch.setenv("DOCKER_CONTEXT", "unrelated")
    env = c.clean_environment()
    assert "DOCKER_HOST" not in env and "DOCKER_CONTEXT" not in env


def test_expired_deadline():
    with pytest.raises(c.RecoveryError, match="deadline"):
        c.remaining(time.time() - 1)


@pytest.mark.parametrize("value", [float("inf"), float("-inf"), float("nan"), "Infinity", True, None])
def test_nonfinite_or_nonnumeric_deadline_rejected(value):
    with pytest.raises(c.RecoveryError, match="operation_deadline_invalid"):
        c.remaining(value)


def test_work_budget_cannot_exceed_forty_five_minutes():
    with pytest.raises(c.RecoveryError, match="operation_work_budget_exceeded"):
        c.remaining(time.time() + 2702)


@pytest.mark.parametrize("reserve", [float("inf"), float("nan"), -1, True])
def test_invalid_reserve_rejected(reserve):
    with pytest.raises(c.RecoveryError, match="operation_deadline_invalid"):
        c.remaining(time.time() + 10, reserve=reserve)


def test_protected_purpose_fingerprints_exclude_paths():
    result = c.purpose_fingerprints(
        {"AUDIT_SIGNING_KEY": "secret", "KEY_PATH": "/private/file", "DATABASE_URL": "private"}
    )
    assert set(result) == {"AUDIT_SIGNING_KEY"}
    assert "secret" not in json.dumps(result)


def test_ciphertext_kek_and_previous_kek_are_protected_purposes():
    result = c.purpose_fingerprints({"CIPHERTEXT_KEK": "current", "CIPHERTEXT_KEK_PREVIOUS": "previous"})
    assert set(result) == {"CIPHERTEXT_KEK", "CIPHERTEXT_KEK_PREVIOUS"}
    assert all(len(value) == 64 for value in result.values())


def test_default_phase_plan_has_no_operation(tmp_path):
    request = tmp_path / "request.json"
    request.write_text(
        json.dumps(
            {"schema": "kp.offhost-recovery.phase-request.v1", "scope": "synthetic-qualification", "phase": "upload"}
        )
    )
    request.chmod(0o600)
    result = subprocess.run(  # noqa: S603 - fixed local dispatcher, no execution switch or network operation
        [sys.executable, str(TOOL / "run.py"), str(request.resolve())],
        capture_output=True,
        timeout=5,
        check=False,
        env=os.environ.copy(),
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"plan": True, "phase": "upload", "scope": "synthetic-qualification"}


def test_execute_requires_tools_and_private_receipt(tmp_path):
    request = tmp_path / "request.json"
    request.write_text(
        json.dumps(
            {"schema": "kp.offhost-recovery.phase-request.v1", "scope": "synthetic-qualification", "phase": "upload"}
        )
    )
    request.chmod(0o600)
    result = subprocess.run(  # noqa: S603 - fixed local dispatcher is rejected before any module operation
        [sys.executable, str(TOOL / "run.py"), str(request.resolve()), "--execute-after-review"],
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 1
    assert json.loads(result.stderr)["error"] == "exclusive_private_receipt_required"
