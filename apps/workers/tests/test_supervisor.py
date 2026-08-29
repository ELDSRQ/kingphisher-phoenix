from __future__ import annotations

from collections import defaultdict
from types import SimpleNamespace
from typing import Any

import pytest
from kp_telemetry.errors import SafetyRejectionError
from kp_telemetry.logging import get_logger
from kp_workers.__main__ import WORKERS, _context, _enabled_roles, _install_shutdown_handlers, _role_settings
from kp_workers.config import WorkerSettings
from kp_workers.supervisor import RoleSpec, WorkerSupervisor


class FakeQueue:
    def __init__(self, messages: dict[str, list[dict[str, Any]]] | None = None) -> None:
        self.messages = defaultdict(list, messages or {})
        self.recovered: list[str] = []
        self.fail_recovery: set[str] = set()
        self.acked: list[tuple[str, str]] = []
        self.rejected: list[tuple[str, str]] = []
        self.pop_order: list[str] = []
        self.reject_error: Exception | None = None

    def pop(self, topic: str, *, timeout: int) -> dict[str, Any] | None:
        assert timeout == 0
        self.pop_order.append(topic)
        return self.messages[topic].pop(0) if self.messages[topic] else None

    def publish(self, topic: str, payload: dict[str, Any], *, idempotency_key: str) -> str:
        identifier = f"published-{len(self.messages[topic])}"
        self.messages[topic].append(
            {"id": identifier, "payload": payload, "idempotency_key": idempotency_key, "_raw": identifier}
        )
        return identifier

    def ack(self, topic: str, message: dict[str, Any]) -> None:
        self.acked.append((topic, message["id"]))

    def reject(self, topic: str, message: dict[str, Any], *, max_retries: int) -> None:
        assert max_retries == 3
        if self.reject_error is not None:
            raise self.reject_error
        self.rejected.append((topic, message["id"]))

    def recover_stale(self, topic: str, *, visibility_seconds: int, max_retries: int) -> int:
        assert visibility_seconds == 60
        assert max_retries == 3
        self.recovered.append(topic)
        if topic in self.fail_recovery:
            raise ConnectionError("unavailable")
        return 1 if topic == "ingest" else 0


class FakeAuditStore:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail

    def dispatch_pending_audit(self) -> None:
        if self.fail:
            raise ConnectionError("audit unavailable")

    def dispatch_pending_queue(self, queue: FakeQueue) -> None:
        if self.fail:
            raise ConnectionError("queue dispatch unavailable")


class FakeLogger:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def info(self, event: str, **values: Any) -> None:
        self.events.append((event, values))

    def warning(self, event: str, **values: Any) -> None:
        self.events.append((event, values))

    def error(self, event: str, **values: Any) -> None:
        self.events.append((event, values))


def _spec(name: str, topic: str, queue: FakeQueue, process: Any, *, audit_fail: bool = False) -> RoleSpec:
    settings = SimpleNamespace(
        visibility_seconds=60,
        max_retries=3,
        recovery_every_polls=2,
        retention_interval_seconds=3600,
        audit_anchor_interval_seconds=3600,
        poll_seconds=1,
        require_audit_anchor_configured=lambda: (
            "https://auditaccount.blob.core.windows.net/audit-head-anchors",
            "55555555-5555-4555-8555-555555555555",
        ),
    )
    context = SimpleNamespace(settings=settings, queue=queue, audit_store=FakeAuditStore(fail=audit_fail))
    return RoleSpec(name=name, topic=topic, process=process, context=context)


def _message(identifier: str) -> dict[str, Any]:
    return {"id": identifier, "payload": {}, "_raw": identifier}


def test_round_robin_polls_each_role_once_per_cycle() -> None:
    queue = FakeQueue(
        {
            "ingest": [_message("i1"), _message("i2")],
            "deliver": [_message("d1"), _message("d2")],
        }
    )
    processed: list[str] = []
    roles = {
        "ingestion": _spec("ingestion", "ingest", queue, lambda _ctx, message: processed.append(message["id"])),
        "delivery": _spec("delivery", "deliver", queue, lambda _ctx, message: processed.append(message["id"])),
    }
    supervisor = WorkerSupervisor(roles, logger=FakeLogger())

    assert supervisor.run_cycle() is True
    assert supervisor.run_cycle() is True

    assert processed == ["i1", "d1", "i2", "d2"]
    assert queue.pop_order == ["ingest", "deliver", "ingest", "deliver"]
    assert queue.acked == [("ingest", "i1"), ("deliver", "d1"), ("ingest", "i2"), ("deliver", "d2")]


def test_role_failure_is_isolated_and_backoff_does_not_starve_siblings() -> None:
    queue = FakeQueue({"bad": [_message("bad1")], "good": [_message("good1"), _message("good2")]})
    processed: list[str] = []
    clock = [10.0]

    def fail(_ctx: object, _message: dict[str, Any]) -> None:
        raise RuntimeError("role failure")

    roles = {
        "bad": _spec("bad", "bad", queue, fail),
        "good": _spec("good", "good", queue, lambda _ctx, message: processed.append(message["id"])),
    }
    supervisor = WorkerSupervisor(roles, clock=lambda: clock[0], logger=FakeLogger())

    supervisor.run_cycle()
    supervisor.run_cycle()

    assert queue.rejected == [("bad", "bad1")]
    assert processed == ["good1", "good2"]
    assert supervisor.readiness()["bad"] == {"ready": False, "reason": "processing_failed"}
    assert supervisor.readiness()["good"] == {"ready": True, "reason": "polling"}


def test_supervisor_failure_logs_are_bounded_to_event_role_and_exception_type(
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret = "password=supervisor-secret https://provider.invalid/private"

    class SecretProcessingFailure(RuntimeError):
        pass

    queue = FakeQueue({"deliver": [_message("d1")]})

    def fail(_ctx: object, _message: dict[str, Any]) -> None:
        raise SecretProcessingFailure(secret)

    supervisor = WorkerSupervisor(
        {"delivery": _spec("delivery", "deliver", queue, fail)},
        logger=get_logger("kp_workers.supervisor.test"),
    )

    assert supervisor.run_cycle() is True

    output = capsys.readouterr().out
    assert "worker_role_processing_failed" in output
    # Structlog may use its development renderer in isolation or JSON after
    # another application configures the shared logger. Assert the bounded
    # structured fields without coupling this security contract to a renderer.
    assert "role" in output and "delivery" in output
    assert "error_code" in output and "unexpected" in output
    assert "SecretProcessingFailure" not in output
    assert secret not in output
    assert "provider.invalid" not in output
    assert "Traceback" not in output


def test_failed_safety_rejection_keeps_role_unready_and_logs_only_fixed_codes() -> None:
    secret = "password=reject-secret https://provider.invalid/private/key.pem"
    exception_type = type("SecretInExceptionType", (RuntimeError,), {})
    queue = FakeQueue({"deliver": [_message("d1")]})
    queue.reject_error = exception_type(secret)
    logger = FakeLogger()

    def reject_safely(_ctx: object, _message: dict[str, Any]) -> None:
        raise SafetyRejectionError(secret, reasons=[secret])

    supervisor = WorkerSupervisor(
        {"delivery": _spec("delivery", "deliver", queue, reject_safely)},
        logger=logger,
    )

    assert supervisor.run_cycle() is True
    assert supervisor.readiness()["delivery"] == {"ready": False, "reason": "queue_reject_failed"}
    rendered = repr(logger.events)
    assert "worker_role_safety_rejection" in rendered
    assert "worker_role_reject_failed" in rendered
    assert "error_code" in rendered and "unexpected" in rendered
    assert secret not in rendered
    assert "provider.invalid" not in rendered
    assert "private/key.pem" not in rendered
    assert "SecretInExceptionType" not in rendered


def test_startup_lease_recovery_and_readiness_are_per_role() -> None:
    queue = FakeQueue()
    queue.fail_recovery.add("deliver")
    roles = {
        "ingestion": _spec("ingestion", "ingest", queue, lambda _ctx, _message: None),
        "delivery": _spec("delivery", "deliver", queue, lambda _ctx, _message: None),
    }
    clock = [10.0]
    supervisor = WorkerSupervisor(roles, clock=lambda: clock[0], logger=FakeLogger())

    supervisor.initialize()

    assert queue.recovered == ["ingest", "deliver"]
    assert supervisor.readiness()["ingestion"] == {"ready": True, "reason": "polling"}
    assert supervisor.readiness()["delivery"] == {"ready": False, "reason": "lease_recovery_failed"}

    clock[0] = 11.0
    supervisor.run_cycle()
    assert queue.recovered == ["ingest", "deliver", "deliver"]
    assert "deliver" not in queue.pop_order


def test_failed_integration_preflight_is_retried_before_recovery_or_polling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queue = FakeQueue({"directory": [_message("directory-1")]})
    clock = [10.0]
    attempts = 0
    processed: list[str] = []

    def ensure_state(_context: object) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise ConnectionError("directory state unavailable")

    monkeypatch.setattr("kp_workers.directory_jobs.ensure_directory_state", ensure_state)
    supervisor = WorkerSupervisor(
        {
            "directory": _spec(
                "directory",
                "directory",
                queue,
                lambda _context, message: processed.append(message["id"]),
            )
        },
        clock=lambda: clock[0],
        logger=FakeLogger(),
    )

    supervisor.initialize()
    assert attempts == 1
    assert queue.recovered == []
    assert queue.pop_order == []
    assert supervisor.readiness()["directory"] == {"ready": False, "reason": "integration_state_unavailable"}

    clock[0] = 10.5
    assert supervisor.run_cycle() is True
    assert attempts == 2
    assert queue.recovered == ["directory"]
    assert processed == ["directory-1"]
    assert queue.acked == [("directory", "directory-1")]
    assert supervisor.readiness()["directory"] == {"ready": True, "reason": "polling"}


def test_shutdown_event_stops_after_current_fair_cycle() -> None:
    queue = FakeQueue({"ingest": [_message("i1")]})
    processed: list[str] = []
    supervisor = WorkerSupervisor(
        {"ingestion": _spec("ingestion", "ingest", queue, lambda _ctx, message: processed.append(message["id"]))},
        logger=FakeLogger(),
    )

    class StopAfterWait:
        stopped = False

        def is_set(self) -> bool:
            return self.stopped

        def wait(self, timeout: float) -> bool:
            assert timeout == pytest.approx(0.1)
            self.stopped = True
            return True

    supervisor.run(StopAfterWait())
    assert processed == ["i1"]
    assert queue.acked == [("ingest", "i1")]


def test_audit_anchor_readiness_distinguishes_static_config_from_live_success() -> None:
    queue = FakeQueue()
    processed: list[str] = []
    clock = [10.0]
    supervisor = WorkerSupervisor(
        {
            "audit-anchor": _spec(
                "audit-anchor",
                "audit-anchor",
                queue,
                lambda _ctx, message: processed.append(message["id"]),
                audit_fail=True,
            )
        },
        clock=lambda: clock[0],
        logger=FakeLogger(),
    )

    supervisor.initialize()
    assert supervisor.readiness()["audit-anchor"] == {"ready": False, "reason": "configured_unproven"}

    assert supervisor.run_cycle() is True
    assert processed == ["published-0"]
    assert supervisor.readiness()["audit-anchor"] == {"ready": True, "reason": "live"}


def test_signal_handlers_request_graceful_shutdown(monkeypatch: pytest.MonkeyPatch) -> None:
    handlers: dict[int, Any] = {}
    event = __import__("threading").Event()
    monkeypatch.setattr("signal.signal", lambda signum, handler: handlers.__setitem__(signum, handler))

    _install_shutdown_handlers(event)
    handlers[__import__("signal").SIGTERM](__import__("signal").SIGTERM, None)

    assert event.is_set()


def test_supervise_roles_are_explicit_deduplicated_and_validated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KP_WORKER_ROLES", "ingestion,delivery,ingestion")
    assert _enabled_roles("supervise") == ("ingestion", "delivery")
    assert _enabled_roles("alert") == ("alert",)

    monkeypatch.setenv("KP_WORKER_ROLES", "")
    with pytest.raises(RuntimeError, match="at least one"):
        _enabled_roles("supervise")

    monkeypatch.setenv("KP_WORKER_ROLES", "ingestion,unknown")
    with pytest.raises(RuntimeError, match="unknown roles: unknown"):
        _enabled_roles("supervise")


def test_entrypoint_role_topics_match_their_single_owned_queues() -> None:
    assert {role: topic for role, (topic, _process) in WORKERS.items()} == {
        "audit-anchor": "audit-anchor",
        "ingestion": "ingest",
        "generation": "generate",
        "delivery": "deliver",
        "retention": "retention",
        "mailbox": "mailbox",
        "reminder": "remind",
        "alert": "alert",
        "directory": "directory",
    }


def test_each_supervised_role_requires_and_uses_its_own_database_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    base = WorkerSettings(worker_name="supervise", runtime_mode="development")
    monkeypatch.delenv("KP_WORKER_DATABASE_URL_INGESTION", raising=False)
    with pytest.raises(RuntimeError, match="KP_WORKER_DATABASE_URL_INGESTION is required"):
        _role_settings(base, "ingestion")

    role_url = "postgresql+psycopg://kp_worker_ingestion:secret@db.example/kingphisher"
    monkeypatch.setenv("KP_WORKER_DATABASE_URL_INGESTION", role_url)
    settings = _role_settings(base, "ingestion")

    assert settings.worker_name == "ingestion"
    assert settings.database_url == role_url


def test_hyphenated_supervised_role_uses_shell_safe_database_variable(monkeypatch: pytest.MonkeyPatch) -> None:
    base = WorkerSettings(worker_name="supervise", runtime_mode="development")
    role_url = "postgresql+psycopg://kp_worker_audit_anchor:secret@db.example/kingphisher"
    monkeypatch.setenv("KP_WORKER_DATABASE_URL_AUDIT_ANCHOR", role_url)

    settings = _role_settings(base, "audit-anchor")

    assert settings.worker_name == "audit-anchor"
    assert settings.database_url == role_url


def test_audit_anchor_context_uses_only_its_read_only_primary_engine(monkeypatch: pytest.MonkeyPatch) -> None:
    from kp_workers import __main__ as worker_main

    disposed: list[str] = []
    primary_engine = SimpleNamespace(name="anchor-primary", dispose=lambda: disposed.append("primary"))
    created_urls: list[str] = []

    def create_engine(url: str) -> Any:
        created_urls.append(url)
        return primary_engine

    class FakeAuditStoreContext:
        def __init__(self, engine: Any, _key: bytes | None) -> None:
            self.engine = engine
            self.bound = False

        def bind_intent_engine(self, _engine: Any) -> None:
            self.bound = True

    monkeypatch.setattr(worker_main, "create_db_engine", create_engine)
    monkeypatch.setattr(worker_main, "make_session_factory", lambda engine: SimpleNamespace(engine=engine))
    monkeypatch.setattr(worker_main, "AuditStore", FakeAuditStoreContext)
    monkeypatch.setattr(worker_main.CipherText, "configure_keyring", lambda _key_id, _key, _prior: None)
    settings = WorkerSettings(
        _env_file=None,
        worker_name="audit-anchor",
        database_url="postgresql+psycopg://anchor-primary",
        audit_database_url="postgresql+psycopg://shared-audit-writer",
        ciphertext_kek="11" * 32,
    )

    context = _context(settings, SimpleNamespace())  # type: ignore[arg-type]

    assert created_urls == ["postgresql+psycopg://anchor-primary"]
    assert context.audit_store.engine is primary_engine  # type: ignore[attr-defined]
    assert context.audit_store.bound is False  # type: ignore[attr-defined]
    context.close()
    context.close()
    assert disposed == ["primary"]


def test_context_construction_failure_disposes_every_created_engine(monkeypatch: pytest.MonkeyPatch) -> None:
    from kp_workers import __main__ as worker_main

    disposed: list[str] = []
    engines = [
        SimpleNamespace(name="primary", dispose=lambda: disposed.append("primary")),
        SimpleNamespace(name="audit", dispose=lambda: disposed.append("audit")),
    ]
    monkeypatch.setattr(worker_main, "create_db_engine", lambda _url: engines.pop(0))
    monkeypatch.setattr(worker_main, "make_session_factory", lambda engine: SimpleNamespace(engine=engine))
    monkeypatch.setattr(
        worker_main,
        "AuditStore",
        lambda _engine, _key: SimpleNamespace(bind_intent_engine=lambda _intent_engine: None),
    )
    monkeypatch.setattr(
        worker_main.CipherText,
        "configure_keyring",
        lambda _key_id, _key, _prior: (_ for _ in ()).throw(RuntimeError("keyring unavailable")),
    )
    settings = WorkerSettings(
        _env_file=None,
        worker_name="delivery",
        database_url="postgresql+psycopg://primary",
        audit_database_url="postgresql+psycopg://audit",
        ciphertext_kek="11" * 32,
    )

    with pytest.raises(RuntimeError, match="keyring unavailable"):
        _context(settings, SimpleNamespace())  # type: ignore[arg-type]

    assert disposed == ["audit", "primary"]


def test_main_closes_prior_contexts_and_queue_when_later_role_startup_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from kp_workers import __main__ as worker_main

    closed: list[str] = []
    queue_arguments: list[str] = []

    class FakeJobQueue:
        def __init__(self, redis_url: str) -> None:
            queue_arguments.append(redis_url)

        def close(self) -> None:
            closed.append("queue")

    contexts_created = 0

    def make_context(_settings: object, _queue: object) -> SimpleNamespace:
        nonlocal contexts_created
        contexts_created += 1
        if contexts_created == 2:
            raise RuntimeError("second role failed")
        return SimpleNamespace(close=lambda: closed.append("first-context"))

    monkeypatch.setattr("sys.argv", ["kp-worker", "supervise"])
    monkeypatch.setattr(
        worker_main,
        "WorkerSettings",
        lambda **_kwargs: SimpleNamespace(
            log_level="INFO",
            redis_url="redis://localhost:6379/0",
        ),
    )
    monkeypatch.setattr(worker_main, "configure_logging", lambda **_kwargs: None)
    monkeypatch.setattr(worker_main, "_enabled_roles", lambda _name: ("delivery", "reminder"))
    monkeypatch.setattr(worker_main, "_role_settings", lambda _base, role: SimpleNamespace(worker_name=role))
    monkeypatch.setattr(worker_main, "JobQueue", FakeJobQueue)
    monkeypatch.setattr(worker_main, "_context", make_context)

    with pytest.raises(RuntimeError, match="second role failed"):
        worker_main.main()

    assert queue_arguments == ["redis://localhost:6379/0"]
    assert closed == ["first-context", "queue"]
