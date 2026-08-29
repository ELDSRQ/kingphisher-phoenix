"""Regression coverage for resources owned by the operator ASGI lifespan."""

from __future__ import annotations

import sqlite3
from typing import Any

import kp_operator_api.main as main_module
import pytest
from fastapi.testclient import TestClient
from kp_operator_api.config import OperatorApiSettings
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.pool import QueuePool

_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


class _AuditStore:
    def __init__(self, _engine: Engine, _key: bytes | None) -> None:
        pass

    def bind_intent_engine(self, _engine: Engine) -> None:
        pass

    def dispatch_pending_audit(self) -> None:
        pass

    def verify(self) -> list[str]:
        return []

    def outbox_health(self) -> dict[str, int]:
        return {"overdue_pending": 0, "failed": 0, "dispatching_stale": 0}


class _Queue:
    closed = 0
    created_urls: list[str] = []

    def __init__(self, url: str) -> None:
        type(self).created_urls.append(url)
        self._client = self

    def ping(self) -> bool:
        return True

    def close(self) -> None:
        type(self).closed += 1


class _ExternalResource:
    def __init__(self) -> None:
        self.closed = 0

    def close(self) -> None:
        self.closed += 1

    def dispose(self) -> None:
        self.closed += 1


def _settings() -> OperatorApiSettings:
    return OperatorApiSettings(
        _env_file=None,
        database_url="postgresql+psycopg://unused/primary",
        audit_database_url="postgresql+psycopg://unused/audit",
        audit_hmac_key=_KEY,
        ciphertext_kek=_KEY,
        console_jwt_secret=_KEY,
        console_static_dir="/nonexistent-console-dir",
    )


def test_repeated_operator_lifespans_close_every_owned_pool_and_queue(monkeypatch: Any) -> None:
    open_connections = 0
    created_engines: list[Engine] = []
    dbapi_connections: list[sqlite3.Connection] = []
    settings = _settings()
    expected_queue_url = settings.redis_url
    assert expected_queue_url.strip(), "active lifecycle-test configuration must define a Redis URL"

    def engine_factory(_url: str) -> Engine:
        nonlocal open_connections
        # TestClient runs the ASGI lifespan in its portal thread. Allow that
        # owner thread to close connections checked out by this test thread.
        engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=QueuePool,
        )

        @event.listens_for(engine, "connect")
        def connected(dbapi_connection: sqlite3.Connection, *_args: object) -> None:
            nonlocal open_connections
            open_connections += 1
            dbapi_connections.append(dbapi_connection)

        @event.listens_for(engine, "close")
        def closed(*_args: object) -> None:
            nonlocal open_connections
            open_connections -= 1

        created_engines.append(engine)
        return engine

    _Queue.closed = 0
    _Queue.created_urls = []
    monkeypatch.setattr(main_module, "create_db_engine", engine_factory)
    monkeypatch.setattr(main_module, "AuditStore", _AuditStore)
    monkeypatch.setattr(main_module, "JobQueue", _Queue)

    for iteration in range(8):
        app = main_module.create_app(settings)
        with TestClient(app) as client:
            assert client.get("/livez").status_code == 200
            with app.state.db_engine.connect(), app.state.audit_engine.connect():
                assert open_connections == 2
        assert open_connections == 0, iteration

    assert len(created_engines) == 16
    assert _Queue.closed == 8
    assert len(_Queue.created_urls) == 8
    assert all(url == expected_queue_url for url in _Queue.created_urls)
    assert len(dbapi_connections) == 16
    for connection in dbapi_connections:
        with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
            connection.execute("SELECT 1")


def test_operator_shutdown_does_not_close_replaced_external_state(monkeypatch: Any) -> None:
    monkeypatch.setattr(main_module, "AuditStore", _AuditStore)
    monkeypatch.setattr(main_module, "JobQueue", _Queue)
    app = main_module.create_app(_settings())
    external_engine = _ExternalResource()
    external_queue = _ExternalResource()
    external_limiter = _ExternalResource()
    app.state.db_engine = external_engine
    app.state.queue = external_queue
    app.state.ip_limiter = external_limiter

    with TestClient(app):
        pass

    assert external_engine.closed == 0
    assert external_queue.closed == 0
    assert external_limiter.closed == 0


def test_partial_operator_construction_closes_resources(monkeypatch: Any) -> None:
    engines: list[Engine] = []

    def engine_factory(_url: str) -> Engine:
        engine = create_engine("sqlite+pysqlite:///:memory:", poolclass=QueuePool)
        with engine.connect():
            pass
        engines.append(engine)
        return engine

    _Queue.closed = 0
    monkeypatch.setattr(main_module, "create_db_engine", engine_factory)
    monkeypatch.setattr(main_module, "AuditStore", _AuditStore)
    monkeypatch.setattr(main_module, "JobQueue", _Queue)
    settings = _settings().model_copy(update={"acs_receipt_signing_key": "configured-alone"})

    try:
        main_module.create_app(settings)
    except ValueError as exc:
        assert "Event Grid" in str(exc)
    else:
        raise AssertionError("incomplete Event Grid configuration must fail")

    assert _Queue.closed == 1
    assert all(engine.pool.checkedin() == 0 for engine in engines)  # type: ignore[attr-defined]
