"""Audit store integration tests against a disposable Postgres.

These belong to the explicit ``make test-postgres`` profile and require its
migrated disposable database and roles.
"""

from __future__ import annotations

import os

import pytest
from kp_database.audit_store import AuditStore
from kp_database.base import Base
from kp_database.session import create_db_engine
from sqlalchemy import text

pytestmark = pytest.mark.postgres


TEST_URL = os.environ.get(
    "DATABASE_URL_TEST", "postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher_test"
)
AUDIT_URL = os.environ.get(
    "AUDIT_DATABASE_URL_TEST", "postgresql+psycopg://audit_writer:audit_writer@localhost:5432/kingphisher_test"
)
_HMAC_HEX = os.environ.get("AUDIT_HMAC_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
HMAC_KEY = bytes.fromhex(_HMAC_HEX)

_available = None


def _db_available() -> bool:
    if os.environ.get("KP_TEST_PROFILE") != "postgres":
        return False
    global _available
    if _available is None:
        try:
            engine = create_db_engine(TEST_URL)
            with engine.connect():
                pass
            engine.dispose()
            _available = True
        except Exception:  # noqa: BLE001 - DB simply not up
            _available = False
    return _available


requires_db = pytest.mark.skipif(not _db_available(), reason="PostgreSQL integration database is not reachable")


def _drop_tables() -> None:
    engine = create_db_engine(TEST_URL)
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


def _create_tables() -> None:
    engine = create_db_engine(TEST_URL)
    Base.metadata.create_all(bind=engine)
    with engine.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE IF NOT EXISTS audit_chain_head ("
                "id INTEGER PRIMARY KEY CHECK (id = 1), "
                "event_hash VARCHAR(64) NOT NULL, "
                "signature VARCHAR(64), "
                "signed_at TIMESTAMPTZ NOT NULL DEFAULT now())"
            )
        )
        conn.execute(text("GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO audit_writer"))
    engine.dispose()


@requires_db
def test_audit_store_roundtrip_and_chain() -> None:
    _drop_tables()
    _create_tables()
    engine = create_db_engine(TEST_URL)
    audit_engine = create_db_engine(AUDIT_URL)
    try:
        audit = AuditStore(audit_engine, hmac_key=HMAC_KEY)

        first = audit.record(
            actor="seed",
            action="seed.complete",
            object_type="campaign",
            object_id="c1",
            detail={"pattern": "p1"},
        )
        second = audit.record(
            actor="worker", action="campaign.deliver", object_type="campaign", object_id="c1", detail={"sent": 5}
        )

        assert first.prev_hash == "0" * 64
        assert second.prev_hash == first.event_hash
        assert audit.verify() == []
        snapshot = audit.head_snapshot()
        assert snapshot is not None
        assert snapshot.sequence == 2
        assert snapshot.event_hash == second.event_hash
        assert snapshot.signed_at.tzinfo is not None

        with engine.connect() as conn:
            rows = conn.execute(text("SELECT action, detail FROM audit_events ORDER BY occurred_at")).mappings().all()
        assert [r["action"] for r in rows] == ["seed.complete", "campaign.deliver"]
        assert rows[1]["detail"] == {"sent": 5}
    finally:
        audit_engine.dispose()
        engine.dispose()


@requires_db
def test_audit_store_resumes_from_persisted_head() -> None:
    _drop_tables()
    _create_tables()
    engine_a = create_db_engine(AUDIT_URL)
    engine_b = create_db_engine(AUDIT_URL)
    try:
        store_a = AuditStore(engine_a, hmac_key=HMAC_KEY)
        store_a.record(actor="api", action="campaign.create", object_type="campaign", object_id="c1")
        first = store_a.record(actor="api", action="campaign.update", object_type="campaign", object_id="c1")

        store_b = AuditStore(engine_b, hmac_key=HMAC_KEY)
        second = store_b.record(actor="worker", action="campaign.deliver", object_type="campaign", object_id="c1")

        assert second.prev_hash == first.event_hash
        assert store_b.verify() == []
    finally:
        engine_b.dispose()
        engine_a.dispose()


@requires_db
def test_verify_detects_tampered_detail() -> None:
    _drop_tables()
    _create_tables()
    engine = create_db_engine(TEST_URL)
    audit_engine = create_db_engine(AUDIT_URL)
    try:
        audit = AuditStore(audit_engine, hmac_key=HMAC_KEY)
        audit.record(actor="a", action="campaign.create", object_type="campaign", object_id="c1")

        with engine.begin() as conn:
            conn.execute(text("UPDATE audit_events SET detail = '{\"evil\": true}' WHERE actor = 'a'"))
        assert audit.verify() != []
    finally:
        audit_engine.dispose()
        engine.dispose()
