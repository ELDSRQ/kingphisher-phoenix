"""Scheduled audit-chain verification (CRIT-06): fired at startup and on the
interval, failures surface loudly (CRITICAL + status), verification errors
never crash the loop, the task is cancellable for graceful shutdown, and
/healthz exposes aggregate state without changing its HTTP 200 contract."""

from __future__ import annotations

import asyncio
import contextlib
import json
import threading
import time
import traceback
from typing import Any

import kp_operator_api.main as main_module
import pytest
from fastapi.testclient import TestClient
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.main import AuditVerificationScheduler, create_app
from kp_telemetry.logging import configure_logging, get_logger
from pydantic import ValidationError

KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"


def _settings() -> OperatorApiSettings:
    return OperatorApiSettings(
        audit_hmac_key=HMAC,
        ciphertext_kek=KEK,
        console_jwt_secret=CONSOLE_JWT,
        console_static_dir="/nonexistent-console-dir",
    )


class _FakeAuditStore:
    def __init__(self, problems: list[str] | None = None, *, delay: float = 0.0) -> None:
        self.problems = problems or []
        self.calls = 0
        self.delay = delay

    def verify(self) -> list[str]:
        self.calls += 1
        if self.delay:
            time.sleep(self.delay)
        return list(self.problems)


class _FlakyAuditStore:
    """Raises on the first verification, then succeeds (recovery path)."""

    def __init__(self) -> None:
        self.calls = 0

    def verify(self) -> list[str]:
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("audit database unreachable")
        return []


class _TransientSnapshotAuditStore:
    """Reports one inconsistent read while a concurrent append completes."""

    def __init__(self) -> None:
        self.calls = 0

    def verify(self) -> list[str]:
        self.calls += 1
        return ["transient head mismatch"] if self.calls == 1 else []


class _BlockingAuditStore:
    def __init__(self) -> None:
        self.started = threading.Event()
        self.release = threading.Event()
        self.finished = threading.Event()

    def verify(self) -> list[str]:
        self.started.set()
        self.release.wait(timeout=5)
        self.finished.set()
        return []


class AuditBackendSecretFailure(RuntimeError):
    pass


class _SecretBearingAuditStore:
    def verify(self) -> list[str]:
        raise AuditBackendSecretFailure(
            "password=must-not-log postgresql://audit:secret@db/audit request=/private?token=secret"
        )


class _RecordingLogger:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict[str, Any]]] = []

    def critical(self, event: str, **kwargs: Any) -> None:
        self.events.append(("critical", event, kwargs))

    def info(self, event: str, **kwargs: Any) -> None:
        self.events.append(("info", event, kwargs))


def _drive(scheduler: AuditVerificationScheduler, until: Any, timeout: float = 5.0) -> None:
    """Run the scheduler until `until()` holds, then cancel it like shutdown."""

    async def run() -> None:
        task = asyncio.create_task(scheduler.run())
        deadline = time.monotonic() + timeout
        while not until() and time.monotonic() < deadline:
            await asyncio.sleep(0.005)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    asyncio.run(run())


def test_scheduler_verifies_at_startup_then_periodically() -> None:
    store = _FakeAuditStore()
    logger = _RecordingLogger()
    scheduler = AuditVerificationScheduler(store, interval_seconds=0.01, logger=logger)

    _drive(scheduler, lambda: store.calls >= 3)

    assert store.calls >= 3
    assert scheduler.status == "ok"
    assert scheduler.problem_count == 0
    assert ("info", "audit_chain_verified", {"detail": "audit chain intact"}) in logger.events


def test_scheduler_failure_surfaces_bounded_critical_log_and_status(
    capsys: pytest.CaptureFixture[str],
) -> None:
    problems = [
        "hash mismatch at 2026-08-26 00:00:00+00:00 recipient@example.com:campaign.create",
        "audit head references chain-hash-deadbeef but chain ends elsewhere",
    ]
    store = _FakeAuditStore(problems=problems)
    logger = _RecordingLogger()
    scheduler = AuditVerificationScheduler(store, interval_seconds=0.01, logger=logger)

    # Two full failing passes: the loop survived and kept verifying.
    _drive(scheduler, lambda: store.calls >= 2 and scheduler.status == "failing")

    assert scheduler.status == "failing"
    assert scheduler.problem_count == 2
    assert not hasattr(scheduler, "problems")
    critical = [e for e in logger.events if e[0] == "critical"]
    assert critical
    level, event, fields = critical[0]
    assert level == "critical"
    assert event == "audit_chain_verification_failed"
    assert fields == {"status": "failing", "problem_count": 2}
    assert all(problem not in repr(logger.events) for problem in problems)
    assert "recipient@example.com" not in repr(logger.events)
    assert "chain-hash-deadbeef" not in repr(logger.events)

    configure_logging()
    json_scheduler = AuditVerificationScheduler(
        store,
        interval_seconds=60,
        logger=get_logger("kp.audit.verify.failure.test"),
    )
    asyncio.run(json_scheduler.verify_once())

    output = capsys.readouterr().out
    record = json.loads(output.splitlines()[-1])
    assert record["event"] == "audit_chain_verification_failed"
    assert record["status"] == "failing"
    assert record["problem_count"] == 2
    assert "recipient@example.com" not in output
    assert "chain-hash-deadbeef" not in output


def test_scheduler_error_does_not_crash_loop_and_recovers() -> None:
    store = _FlakyAuditStore()
    logger = _RecordingLogger()
    scheduler = AuditVerificationScheduler(store, interval_seconds=0.01, logger=logger)

    _drive(scheduler, lambda: scheduler.status == "ok")

    assert scheduler.status == "ok"  # recovered on the second pass
    assert store.calls >= 2
    assert any(e[0] == "critical" and e[1] == "audit_chain_verification_error" for e in logger.events)


def test_scheduler_confirms_a_bad_snapshot_before_failing_readiness() -> None:
    store = _TransientSnapshotAuditStore()
    logger = _RecordingLogger()
    scheduler = AuditVerificationScheduler(store, interval_seconds=60, logger=logger)

    asyncio.run(scheduler.verify_once())

    assert store.calls == 2
    assert scheduler.status == "ok"
    assert scheduler.problem_count == 0
    assert not any(event == "audit_chain_verification_failed" for _level, event, _fields in logger.events)


def test_scheduler_error_log_is_bounded_for_recording_and_json_renderers(
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret = "password=must-not-log"
    logger = _RecordingLogger()
    scheduler = AuditVerificationScheduler(_SecretBearingAuditStore(), interval_seconds=60, logger=logger)

    asyncio.run(scheduler.verify_once())

    assert scheduler.status == "error"
    assert logger.events == [
        (
            "critical",
            "audit_chain_verification_error",
            {"exception_type": "AuditBackendSecretFailure"},
        )
    ]
    assert secret not in repr(logger.events)

    configure_logging()
    json_scheduler = AuditVerificationScheduler(
        _SecretBearingAuditStore(), interval_seconds=60, logger=get_logger("kp.audit.verify.test")
    )
    asyncio.run(json_scheduler.verify_once())

    output = capsys.readouterr().out
    record = json.loads(output.splitlines()[-1])
    assert record["event"] == "audit_chain_verification_error"
    assert record["exception_type"] == "AuditBackendSecretFailure"
    assert secret not in output
    assert "postgresql://" not in output
    assert "/private" not in output
    assert "Traceback" not in output
    assert "exception" not in record


def test_scheduler_is_cancellable_during_sleep_and_during_verify() -> None:
    # Cancel while idle between passes.
    scheduler = AuditVerificationScheduler(_FakeAuditStore(), interval_seconds=60.0)

    async def cancel_idle() -> None:
        task = asyncio.create_task(scheduler.run())
        await asyncio.sleep(0.05)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    asyncio.run(cancel_idle())

    # Cancel while a verification is in flight (to_thread). Cancellation must
    # surface as CancelledError only — never a verification error — and the
    # abandoned pass still counts as exactly one attempt.
    store = _FakeAuditStore(delay=0.5)
    scheduler_inflight = AuditVerificationScheduler(store, interval_seconds=60.0)

    async def cancel_inflight() -> None:
        task = asyncio.create_task(scheduler_inflight.run())
        await asyncio.sleep(0.02)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    asyncio.run(cancel_inflight())
    assert store.calls == 1


def test_shutdown_joins_inflight_thread_before_return_and_repeated_cancellation_is_safe() -> None:
    store = _BlockingAuditStore()
    scheduler = AuditVerificationScheduler(store, interval_seconds=60.0)

    async def exercise() -> None:
        run_task = asyncio.create_task(scheduler.run())
        while not store.started.is_set():
            await asyncio.sleep(0.005)

        started = time.monotonic()
        run_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await run_task
        assert time.monotonic() - started < 0.25

        shutdown_task = asyncio.create_task(scheduler.shutdown())
        await asyncio.sleep(0.02)
        assert not shutdown_task.done()

        # Even cancellation of shutdown cannot let engine disposal race the
        # checked-out blocking operation. It is propagated only after join.
        shutdown_task.cancel()
        await asyncio.sleep(0.02)
        assert not shutdown_task.done()
        store.release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(shutdown_task, timeout=1)

        assert store.finished.is_set()
        await scheduler.shutdown()  # idempotent after a cancelled caller

    try:
        asyncio.run(exercise())
    finally:
        store.release.set()


def test_interval_is_env_tunable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPERATOR_API_AUDIT_VERIFY_INTERVAL_SECONDS", "90")
    assert main_module._audit_verify_interval_seconds() == 90
    monkeypatch.delenv("OPERATOR_API_AUDIT_VERIFY_INTERVAL_SECONDS", raising=False)
    assert main_module._audit_verify_interval_seconds() == 6 * 60 * 60
    # Misconfiguration fails loudly at startup, consistent with other settings.
    monkeypatch.setenv("OPERATOR_API_AUDIT_VERIFY_INTERVAL_SECONDS", "not-a-number")
    with pytest.raises(ValidationError):
        main_module._audit_verify_interval_seconds()


@pytest.mark.parametrize(
    ("settings_type", "values"),
    [
        (main_module._AuditVerificationSettings, {"audit_verify_interval_seconds": "SECRET_INTERVAL"}),
        (main_module._RateLimitSettings, {"rate_limit_backend": "SECRET_BACKEND"}),
    ],
)
def test_internal_settings_errors_hide_input_in_tracebacks(settings_type: type[Any], values: dict[str, str]) -> None:
    secret = next(iter(values.values()))

    with pytest.raises(ValidationError) as caught:
        settings_type(_env_file=None, **values)

    rendered = f"{caught.value!s}\n{caught.value!r}\n{''.join(traceback.format_exception(caught.value))}"
    assert secret not in rendered
    assert "input_value=" not in rendered


def _client_with_audit_store(monkeypatch: pytest.MonkeyPatch, store: _FakeAuditStore) -> TestClient:
    monkeypatch.setattr(main_module, "AuditStore", lambda engine, key: store)
    return TestClient(create_app(_settings()))


def _poll_healthz(client: TestClient, expected_status: str, timeout: float = 5.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    body: dict[str, Any] = {}
    while time.monotonic() < deadline:
        body = client.get("/healthz").json()
        if body.get("status") == expected_status:
            return body
        time.sleep(0.01)
    return body


def test_healthz_exposes_failed_verification(monkeypatch: pytest.MonkeyPatch) -> None:
    sensitive_problem = "hash mismatch 2026-08-26 actor@example.com:campaign.create chain-hash-deadbeef"
    store = _FakeAuditStore(problems=[sensitive_problem])
    with _client_with_audit_store(monkeypatch, store) as client:
        resp = client.get("/healthz")
        assert resp.status_code == 200  # contract kept; payload carries the signal
        body = _poll_healthz(client, "degraded")
        assert body == {"status": "degraded", "audit_verification": "failing"}
        assert sensitive_problem not in resp.text
        assert "actor@example.com" not in resp.text
        assert "chain-hash-deadbeef" not in resp.text


def test_healthz_exposes_verification_error(monkeypatch: pytest.MonkeyPatch) -> None:
    class _BrokenAuditStore(_FakeAuditStore):
        def verify(self) -> list[str]:
            self.calls += 1
            raise RuntimeError("audit store unreachable")

    with _client_with_audit_store(monkeypatch, _BrokenAuditStore()) as client:
        body = _poll_healthz(client, "degraded")
        assert body == {"status": "degraded", "audit_verification": "error"}


def test_healthz_ok_when_chain_verifies(monkeypatch: pytest.MonkeyPatch) -> None:
    with _client_with_audit_store(monkeypatch, _FakeAuditStore()) as client:
        body = _poll_healthz(client, "ok")
        assert body == {"status": "ok"}
