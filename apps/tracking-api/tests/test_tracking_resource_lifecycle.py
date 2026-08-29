"""Regression coverage for resources owned by the tracking ASGI lifespan."""

from __future__ import annotations

import sqlite3
from typing import Any

import kp_tracking_api.main as main_module
import pytest
from fastapi.testclient import TestClient
from kp_tracking_api.config import TrackingApiSettings
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.pool import QueuePool


def _settings() -> TrackingApiSettings:
    return TrackingApiSettings(
        _env_file=None,
        database_url="postgresql+psycopg://unused/tracking",
        tracking_token_hmac_key=(b"k" * 32).hex(),
    )


def test_repeated_tracking_lifespans_close_every_owned_pool(monkeypatch: Any) -> None:
    open_connections = 0
    dbapi_connections: list[sqlite3.Connection] = []

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

        return engine

    monkeypatch.setattr(main_module, "create_db_engine", engine_factory)

    for iteration in range(8):
        app = main_module.create_app(_settings())
        with TestClient(app) as client:
            assert client.get("/livez").status_code == 200
            with app.state.db_engine.connect():
                assert open_connections == 1
        assert open_connections == 0, iteration

    assert len(dbapi_connections) == 8
    for connection in dbapi_connections:
        with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
            connection.execute("SELECT 1")
