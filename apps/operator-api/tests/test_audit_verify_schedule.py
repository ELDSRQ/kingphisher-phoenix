"""Scheduled audit-chain verification (CRIT-06): fired at startup and on the
interval, failures surface loudly (CRITICAL + status), verification errors
never crash the loop, the task is cancellable for graceful shutdown, and
/healthz exposes the state without changing its HTTP 200 contract."""

from __future__ import annotations

import asyncio
import contextlib
import time
from typing import Any

import kp_operator_api.main as main_module
import pytest
from fastapi.testclient import TestClient
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.main import AuditVerificationScheduler, create_app
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
    assert scheduler.problems == []
    assert ("info", "audit_chain_verified", {"detail": "audit chain intact"}) in logger.events


def test_scheduler_failure_surfaces_critical_log_and_status() -> None:
    problems = [
        "hash mismatch at 2026-08-26 00:00:00+00:00 api:campaign.create",
        "audit head signature verification failed",
    ]
    store = _FakeAuditStore(problems=problems)
    logger = _RecordingLogger()
    scheduler = AuditVerificationScheduler(store, interval_seconds=0.01, logger=logger)

    # Two full failing passes: the loop survived and kept verifying.
    _drive(scheduler, lambda: store.calls >= 2 and scheduler.status == "failing")

    assert scheduler.status == "failing"
    assert scheduler.problems == problems
    critical = [e for e in logger.events if e[0] == "critical"]
    assert critical
    level, event, fields = critical[0]
    assert level == "critical"
    assert event == "audit_chain_verification_failed"
    assert fields["problems"] == problems
    assert fields["problem_count"] == 2
    assert "tampering" in fields["detail"]


def test_scheduler_error_does_not_crash_loop_and_recovers() -> None:
    store = _FlakyAuditStore()
    logger = _RecordingLogger()
    scheduler = AuditVerificationScheduler(store, interval_seconds=0.01, logger=logger)

    _drive(scheduler, lambda: scheduler.status == "ok")

    assert scheduler.status == "ok"  # recovered on the second pass
    assert store.calls >= 2
    assert any(e[0] == "critical" and e[1] == "audit_chain_verification_error" for e in logger.events)


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


def test_interval_is_env_tunable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPERATOR_API_AUDIT_VERIFY_INTERVAL_SECONDS", "90")
    assert main_module._audit_verify_interval_seconds() == 90
    monkeypatch.delenv("OPERATOR_API_AUDIT_VERIFY_INTERVAL_SECONDS", raising=False)
    assert main_module._audit_verify_interval_seconds() == 6 * 60 * 60
    # Misconfiguration fails loudly at startup, consistent with other settings.
    monkeypatch.setenv("OPERATOR_API_AUDIT_VERIFY_INTERVAL_SECONDS", "not-a-number")
    with pytest.raises(ValidationError):
        main_module._audit_verify_interval_seconds()


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
    store = _FakeAuditStore(problems=["hash mismatch at 2026-08-26 00:00:00+00:00 api:campaign.create"])
    with _client_with_audit_store(monkeypatch, store) as client:
        resp = client.get("/healthz")
        assert resp.status_code == 200  # contract kept; payload carries the signal
        body = _poll_healthz(client, "degraded")
        assert body["status"] == "degraded"
        assert body["audit_verification"] == "failing"
        assert "hash mismatch" in body["detail"]


def test_healthz_exposes_verification_error(monkeypatch: pytest.MonkeyPatch) -> None:
    class _BrokenAuditStore(_FakeAuditStore):
        def verify(self) -> list[str]:
            self.calls += 1
            raise RuntimeError("audit store unreachable")

    with _client_with_audit_store(monkeypatch, _BrokenAuditStore()) as client:
        body = _poll_healthz(client, "degraded")
        assert body["status"] == "degraded"
        assert body["audit_verification"] == "error"


def test_healthz_ok_when_chain_verifies(monkeypatch: pytest.MonkeyPatch) -> None:
    with _client_with_audit_store(monkeypatch, _FakeAuditStore()) as client:
        body = _poll_healthz(client, "ok")
        assert body == {"status": "ok"}
