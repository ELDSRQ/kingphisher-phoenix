"""Fail-closed transaction tests for GUI-managed local configuration."""

from __future__ import annotations

import os
import stat
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from dotenv import dotenv_values
from dotenv import set_key as dotenv_set_key
from fastapi import HTTPException, Request
from kp_authorization.rbac import Principal, Role
from kp_operator_api import console


def _values(path: Path) -> dict[str, str]:
    return {key: value for key, value in dotenv_values(path).items() if value is not None}


def _recovery_copies(path: Path) -> list[Path]:
    return sorted(path.parent.glob(f"{path.name}.recovery.*.bak"))


class _Audit:
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    def record(self, **event: object) -> None:
        self.events.append(event)


def test_atomic_update_preserves_safe_mode_and_retains_private_recovery(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    original = b"KP_CONSOLE_PASSWORD='original-secret'\nOPERATOR_API_LOG_LEVEL='INFO'\n"
    path.write_bytes(original)
    path.chmod(0o640)
    prior_recovery = path.parent / ".env.recovery.prior.bak"
    prior_recovery.write_bytes(b"older recovery evidence")
    prior_recovery.chmod(0o600)

    changed = console._atomic_update_env(
        path,
        {
            "OPERATOR_API_LOG_LEVEL": "WARNING",
            "OPERATOR_API_TRAINING_DOMAINS": "training.example",
        },
        validate_candidate=console._validate_config_candidate,
    )

    assert changed == ["OPERATOR_API_LOG_LEVEL", "OPERATOR_API_TRAINING_DOMAINS"]
    assert _values(path)["OPERATOR_API_LOG_LEVEL"] == "WARNING"
    assert _values(path)["OPERATOR_API_TRAINING_DOMAINS"] == "training.example"
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
    copies = _recovery_copies(path)
    assert len(copies) == 2
    assert prior_recovery.read_bytes() == b"older recovery evidence"
    current_recovery = next(copy for copy in copies if copy != prior_recovery)
    assert current_recovery.read_bytes() == original
    assert stat.S_IMODE(current_recovery.stat().st_mode) == 0o600


def test_invalid_field_is_rejected_before_any_staging_write(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / ".env"
    original = b"OPERATOR_API_LOG_LEVEL='INFO'\n"
    path.write_bytes(original)

    def unexpected_stage(*_args: object, **_kwargs: object) -> tuple[int, str]:
        pytest.fail("invalid input must be rejected before a staging file is created")

    monkeypatch.setattr("kp_operator_api.console.tempfile.mkstemp", unexpected_stage)
    with pytest.raises(HTTPException, match="single-line"):
        console._atomic_update_env(path, {"OPERATOR_API_LOG_LEVEL": "INFO\nSECRET=value"})

    assert path.read_bytes() == original
    assert _recovery_copies(path) == []


def test_set_failure_never_partially_replaces_or_discloses_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / ".env"
    original = b"OPERATOR_API_LOG_LEVEL='INFO'\nKP_WORKER_SMTP_PASSWORD='old-secret'\n"
    path.write_bytes(original)
    calls = 0
    new_secret = "new-secret-that-must-not-leak"

    def fail_second_set(dotenv_path: str, key: str, value: str) -> tuple[bool | None, str, str]:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError(f"synthetic failure while setting {value}")
        return dotenv_set_key(dotenv_path, key, value)

    monkeypatch.setattr("kp_operator_api.console.set_key", fail_second_set)
    with pytest.raises(console._AtomicEnvUpdateError) as raised:
        console._atomic_update_env(
            path,
            {
                "OPERATOR_API_LOG_LEVEL": "ERROR",
                "KP_WORKER_SMTP_PASSWORD": new_secret,
            },
        )

    assert path.read_bytes() == original
    assert new_secret not in str(raised.value)
    assert _values(path)["OPERATOR_API_LOG_LEVEL"] == "INFO"
    assert _values(path)["KP_WORKER_SMTP_PASSWORD"] == "old-secret"


def test_replace_failure_leaves_original_and_retains_recovery(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / ".env"
    original = b"OPERATOR_API_LOG_LEVEL='INFO'\n"
    path.write_bytes(original)
    secret = "replacement-error-secret"

    def fail_replace(_source: os.PathLike[str] | str, _target: os.PathLike[str] | str) -> None:
        raise OSError(secret)

    monkeypatch.setattr("kp_operator_api.console._replace_env_file", fail_replace)
    with pytest.raises(console._AtomicEnvUpdateError) as raised:
        console._atomic_update_env(path, {"OPERATOR_API_LOG_LEVEL": "ERROR"})

    assert path.read_bytes() == original
    assert secret not in str(raised.value)
    copies = _recovery_copies(path)
    assert len(copies) == 1
    assert copies[0].read_bytes() == original
    assert stat.S_IMODE(copies[0].stat().st_mode) == 0o600


def test_failed_config_commit_emits_no_changed_key_audit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / ".env"
    original = b"OPERATOR_API_LOG_LEVEL='INFO'\n"
    path.write_bytes(original)
    audit = _Audit()
    request = cast(
        Request,
        SimpleNamespace(
            app=SimpleNamespace(
                state=SimpleNamespace(
                    settings=SimpleNamespace(config_is_managed=False, env_file=str(path)),
                    audit_store=audit,
                )
            )
        ),
    )
    principal = Principal(subject_id="11111111-1111-4111-8111-111111111111", roles={Role.ADMINISTRATOR})

    def fail_replace(_source: os.PathLike[str] | str, _target: os.PathLike[str] | str) -> None:
        raise OSError("synthetic replace failure")

    monkeypatch.setattr("kp_operator_api.console._replace_env_file", fail_replace)
    with pytest.raises(HTTPException, match="original configuration is unchanged"):
        console.put_config(
            console.ConfigPatch(values={"OPERATOR_API_LOG_LEVEL": "ERROR"}),
            request,
            principal,
        )

    assert path.read_bytes() == original
    assert audit.events == []


def test_post_replace_sync_failure_rolls_back_without_removing_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / ".env"
    original = b"OPERATOR_API_LOG_LEVEL='INFO'\n"
    path.write_bytes(original)
    real_fsync = os.fsync
    calls = 0

    def fail_post_replace_once(descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 4:
            raise OSError("synthetic post-replace directory fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr("kp_operator_api.console.os.fsync", fail_post_replace_once)
    with pytest.raises(console._AtomicEnvUpdateError, match="original configuration is unchanged"):
        console._atomic_update_env(path, {"OPERATOR_API_LOG_LEVEL": "ERROR"})

    assert path.read_bytes() == original
    copies = _recovery_copies(path)
    assert len(copies) == 1
    assert copies[0].read_bytes() == original


def test_repeated_post_replace_sync_failures_still_restore_logical_contents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / ".env"
    original = b"OPERATOR_API_LOG_LEVEL='INFO'\n"
    path.write_bytes(original)
    real_fsync = os.fsync
    calls = 0

    def fail_from_post_replace(descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls >= 4:
            raise OSError("filesystem will not sync")
        real_fsync(descriptor)

    monkeypatch.setattr("kp_operator_api.console.os.fsync", fail_from_post_replace)
    with pytest.raises(console._AtomicEnvUpdateError, match="original configuration is unchanged"):
        console._atomic_update_env(path, {"OPERATOR_API_LOG_LEVEL": "ERROR"})

    assert path.read_bytes() == original
    assert len(_recovery_copies(path)) == 1


def test_concurrent_updates_serialize_without_lost_fields(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / ".env"
    path.write_text("OPERATOR_API_LOG_LEVEL='INFO'\n", encoding="utf-8")
    updates = {
        "OPERATOR_API_HOST": "127.0.0.2",
        "OPERATOR_API_PORT": "9100",
        "TRACKING_API_HOST": "127.0.0.3",
        "TRACKING_API_PORT": "9101",
        "KP_WORKER_POLL_SECONDS": "7",
        "KP_WORKER_MAILBOX_POLL_LIMIT": "42",
        "KP_WORKER_REMINDER_BATCH_SIZE": "13",
        "KP_WORKER_GRAPH_MAX_PAGES": "11",
    }

    def slow_set(dotenv_path: str, key: str, value: str) -> tuple[bool | None, str, str]:
        result = dotenv_set_key(dotenv_path, key, value)
        time.sleep(0.01)
        return result

    monkeypatch.setattr("kp_operator_api.console.set_key", slow_set)
    with ThreadPoolExecutor(max_workers=len(updates)) as executor:
        results = list(
            executor.map(
                lambda item: console._atomic_update_env(path, {item[0]: item[1]}),
                updates.items(),
            )
        )

    assert all(len(result) == 1 for result in results)
    final = _values(path)
    assert all(final[key] == value for key, value in updates.items())
    assert len(_recovery_copies(path)) == len(updates)


def test_blank_secret_keeps_current_value_in_complete_candidate(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text(
        "KP_WORKER_SMTP_PASSWORD='keep-me'\nOPERATOR_API_LOG_LEVEL='INFO'\n",
        encoding="utf-8",
    )
    observed: dict[str, str] = {}

    def validate(candidate: dict[str, str]) -> None:
        observed.update(candidate)

    changed = console._atomic_update_env(
        path,
        {"KP_WORKER_SMTP_PASSWORD": "", "OPERATOR_API_LOG_LEVEL": "DEBUG"},
        validate_candidate=validate,
    )

    assert changed == ["OPERATOR_API_LOG_LEVEL"]
    assert observed["KP_WORKER_SMTP_PASSWORD"] == "keep-me"
    assert _values(path)["KP_WORKER_SMTP_PASSWORD"] == "keep-me"
