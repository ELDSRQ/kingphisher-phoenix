from __future__ import annotations

import logging
import uuid
from contextlib import nullcontext
from datetime import UTC, datetime
from typing import Any

import pytest
from kp_database.outbox import OutboxDispatcher, dispatch_after_commit
from sqlalchemy import create_engine
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.orm import Session


class SecretDispatchFailure(RuntimeError):
    pass


class SecretSqlstateFailure(RuntimeError):
    sqlstate = "42883"


class _Result:
    def __init__(self, row: dict[str, Any] | None = None) -> None:
        self._row = row

    def mappings(self) -> _Result:
        return self

    def one_or_none(self) -> dict[str, Any] | None:
        return self._row


class _Connection:
    def __init__(
        self,
        row: dict[str, Any],
        *,
        fail_claim_function: bool = False,
        fail_complete_function: bool = False,
    ) -> None:
        self._row = row
        self._fail_claim_function = fail_claim_function
        self._fail_complete_function = fail_complete_function
        self.executions: list[tuple[str, object | None]] = []
        self.durable_state: dict[str, Any] = {
            "status": "pending",
            "attempts": 0,
            "last_error": None,
            "retry_delay_seconds": None,
        }

    def execute(self, statement: object, parameters: object | None = None) -> _Result:
        sql = str(statement)
        self.executions.append((sql, parameters))
        if "kp_claim_queue_outbox" in sql:
            if self._fail_claim_function:
                raise ProgrammingError(sql, parameters, RuntimeError("function unavailable"))
            return _Result(self._row)
        if "UPDATE transactional_outbox SET status = 'dispatching'" in sql:
            self.durable_state["status"] = "dispatching"
            self.durable_state["attempts"] += 1
            return _Result(self._row)
        if "UPDATE transactional_outbox SET status = 'failed'" in sql:
            assert isinstance(parameters, dict)
            self.durable_state.update(
                status="failed",
                last_error=parameters["error"],
                retry_delay_seconds=30,
            )
        if "kp_complete_outbox" in sql and self._fail_complete_function:
            raise ProgrammingError(
                "SELECT secret_statement",
                {"password": "secret-parameter"},
                SecretSqlstateFailure("password=secret-error"),
            )
        return _Result()


class _Engine:
    def __init__(
        self,
        row: dict[str, Any],
        *,
        fail_claim_function: bool = False,
        fail_complete_function: bool = False,
    ) -> None:
        self._connection = _Connection(
            row,
            fail_claim_function=fail_claim_function,
            fail_complete_function=fail_complete_function,
        )

    def begin(self) -> nullcontext[_Connection]:
        return nullcontext(self._connection)


class _FailingQueue:
    def __init__(self) -> None:
        self.publish_calls = 0

    def publish(self, *_args: object, **_kwargs: object) -> None:
        self.publish_calls += 1
        raise SecretDispatchFailure("password=queue-secret token=opaque-secret https://provider.invalid/private")


class _SuccessfulQueue:
    def publish(self, *_args: object, **_kwargs: object) -> None:
        return None


def test_post_commit_callback_logs_only_bounded_failure_metadata(caplog: Any) -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    try:
        with Session(engine) as session:
            dispatch_after_commit(
                session,
                lambda: (_ for _ in ()).throw(
                    SecretDispatchFailure("password=callback-secret postgresql://user:secret@db/private")
                ),
            )
            with caplog.at_level(logging.ERROR, logger="kp_database.outbox"):
                session.commit()
    finally:
        engine.dispose()

    assert "post_commit_outbox_dispatch_failed" in caplog.text
    assert "reason_code=callback_failed" in caplog.text
    assert "sqlstate_class=unknown" in caplog.text
    assert "exception_type=SecretDispatchFailure" in caplog.text
    assert "callback-secret" not in caplog.text
    assert "postgresql://" not in caplog.text
    assert "Traceback" not in caplog.text


def test_post_commit_callback_logs_only_sqlstate_class_for_database_failure(caplog: Any) -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    failure = ProgrammingError(
        "SELECT secret_statement",
        {"password": "secret-parameter"},
        SecretSqlstateFailure("password=secret-error"),
    )
    try:
        with Session(engine) as session:
            dispatch_after_commit(session, lambda: (_ for _ in ()).throw(failure))
            with caplog.at_level(logging.ERROR, logger="kp_database.outbox"):
                session.commit()
    finally:
        engine.dispose()

    assert "reason_code=callback_failed" in caplog.text
    assert "sqlstate_class=42" in caplog.text
    assert "exception_type=ProgrammingError" in caplog.text
    for secret in ("secret_statement", "secret-parameter", "secret-error"):
        assert secret not in caplog.text


def test_queue_dispatch_logs_reference_and_type_without_exception_detail(caplog: Any) -> None:
    outbox_id = uuid.UUID("11111111-1111-4111-8111-111111111111")
    engine = _Engine(
        {
            "outbox_id": outbox_id,
            "topic": "deliver",
            "payload": {"credential": "must-not-be-logged"},
            "idempotency_key": "queue:test",
            "available_at": datetime(2026, 8, 27, tzinfo=UTC),
        }
    )
    queue = _FailingQueue()
    dispatcher = OutboxDispatcher(  # type: ignore[arg-type] - focused engine protocol fake
        engine
    )

    with caplog.at_level(logging.ERROR, logger="kp_database.outbox"):
        assert dispatcher.dispatch_queue(queue, limit=1) == 0

    assert queue.publish_calls == 1
    assert "outbox_queue_dispatch_failed" in caplog.text
    assert "exception_type=SecretDispatchFailure" in caplog.text
    assert str(outbox_id) in caplog.text
    assert "queue-secret" not in caplog.text
    assert "provider.invalid" not in caplog.text
    assert "must-not-be-logged" not in caplog.text
    assert "Traceback" not in caplog.text

    failure_calls = [call for call in engine._connection.executions if "kp_fail_outbox" in call[0]]
    assert failure_calls == [
        (
            "SELECT kp_fail_outbox(:id, :error)",
            {"id": outbox_id, "error": "queue_dispatch_failed"},
        )
    ]
    persisted = repr(failure_calls)
    assert len(failure_calls[0][1]["error"]) <= 128  # type: ignore[index]
    for secret in ("queue-secret", "opaque-secret", "provider.invalid", "must-not-be-logged"):
        assert secret not in persisted


def test_owner_fallback_persists_fixed_code_and_preserves_retry_transition() -> None:
    outbox_id = uuid.UUID("22222222-2222-4222-8222-222222222222")
    engine = _Engine(
        {
            "outbox_id": outbox_id,
            "topic": "ingest",
            "payload": {"token": "payload-secret"},
            "idempotency_key": "queue:fallback",
            "available_at": datetime(2026, 8, 27, tzinfo=UTC),
        },
        fail_claim_function=True,
    )
    queue = _FailingQueue()
    dispatcher = OutboxDispatcher(engine)  # type: ignore[arg-type] - focused engine protocol fake
    dispatcher.allow_owner_fallback_for_development()

    assert dispatcher.dispatch_queue(queue, limit=1) == 0

    assert queue.publish_calls == 1
    failure_calls = [
        call for call in engine._connection.executions if "UPDATE transactional_outbox SET status = 'failed'" in call[0]
    ]
    assert len(failure_calls) == 1
    sql, parameters = failure_calls[0]
    assert "lease_until = NULL" in sql
    assert "available_at = now() + interval '30 seconds'" in sql
    assert parameters == {"id": str(outbox_id), "error": "queue_dispatch_failed"}
    assert engine._connection.durable_state == {
        "status": "failed",
        "attempts": 1,
        "last_error": "queue_dispatch_failed",
        "retry_delay_seconds": 30,
    }
    persisted = repr(failure_calls)
    for secret in ("queue-secret", "opaque-secret", "provider.invalid", "payload-secret"):
        assert secret not in persisted


def test_queue_completion_failure_logs_phase_and_sqlstate_class_without_database_detail(caplog: Any) -> None:
    outbox_id = uuid.UUID("33333333-3333-4333-8333-333333333333")
    engine = _Engine(
        {
            "outbox_id": outbox_id,
            "topic": "directory",
            "payload": {"token": "payload-secret"},
            "idempotency_key": "queue:completion",
            "available_at": datetime(2026, 8, 27, tzinfo=UTC),
        },
        fail_complete_function=True,
    )
    dispatcher = OutboxDispatcher(engine)  # type: ignore[arg-type] - focused engine protocol fake

    with caplog.at_level(logging.ERROR, logger="kp_database.outbox"), pytest.raises(ProgrammingError):
        dispatcher.dispatch_queue(_SuccessfulQueue(), limit=1)

    assert "outbox_queue_completion_failed" in caplog.text
    assert "reason_code=database_operation_failed" in caplog.text
    assert "sqlstate_class=42" in caplog.text
    assert str(outbox_id) in caplog.text
    for secret in ("secret_statement", "secret-parameter", "secret-error", "payload-secret"):
        assert secret not in caplog.text
