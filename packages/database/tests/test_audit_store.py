"""Audit store integration tests against a disposable Postgres.

These require the local dev stack (`docker compose up -d postgres`) and the
`kingphisher_test` database (created by `make db-init`). They are skipped when
the database is unreachable so the unit suite still runs anywhere.
"""

from __future__ import annotations

import pytest
from kp_database.audit_store import AuditStore
from kp_database.base import Base
from kp_database.session import create_db_engine
from sqlalchemy import text

TEST_URL = "postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher_test"
AUDIT_URL = "postgresql+psycopg://audit_writer:audit_writer@localhost:5432/kingphisher_test"
HMAC_KEY = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

_available = None


def _db_available() -> bool:
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


requires_db = pytest.mark.skipif(not _db_available(), reason="dev Postgres not reachable")


def _drop_tables() -> None:
    engine = create_db_engine(TEST_URL)
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


def _create_tables() -> None:
    engine = create_db_engine(TEST_URL)
    Base.metadata.create_all(bind=engine)
    with engine.begin() as conn:
        conn.execute(text("GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA public TO audit_writer"))
    engine.dispose()


@requires_db
def test_audit_store_roundtrip_and_chain() -> None:
    _drop_tables()
    _create_tables()
    engine = create_db_engine(TEST_URL)
    audit = AuditStore(create_db_engine(AUDIT_URL), hmac_key=HMAC_KEY)

    first = audit.record(actor="seed", action="seed.complete", object_type="campaign",
                         object_id="c1", detail={"pattern": "p1"})
    second = audit.record(actor="worker", action="campaign.deliver", object_type="campaign",
                          object_id="c1", detail={"sent": 5})

    assert first.prev_hash == "0" * 64
    assert second.prev_hash == first.event_hash
    assert audit.verify() == []

    with engine.connect() as conn:
        rows = conn.execute(text("SELECT action, detail FROM audit_events ORDER BY occurred_at")).mappings().all()
    assert [r["action"] for r in rows] == ["seed.complete", "campaign.deliver"]
    assert rows[1]["detail"] == {"sent": 5}
    engine.dispose()


@requires_db
def test_audit_store_resumes_from_persisted_head() -> None:
    _drop_tables()
    _create_tables()

    store_a = AuditStore(create_db_engine(AUDIT_URL), hmac_key=HMAC_KEY)
    store_a.record(actor="api", action="campaign.create", object_type="campaign", object_id="c1")
    first = store_a.record(actor="api", action="campaign.update", object_type="campaign", object_id="c1")

    store_b = AuditStore(create_db_engine(AUDIT_URL), hmac_key=HMAC_KEY)
    second = store_b.record(actor="worker", action="campaign.deliver", object_type="campaign", object_id="c1")

    assert second.prev_hash == first.event_hash
    assert store_b.verify() == []


@requires_db
def test_verify_detects_tampered_detail() -> None:
    _drop_tables()
    _create_tables()
    engine = create_db_engine(TEST_URL)
    audit = AuditStore(create_db_engine(AUDIT_URL), hmac_key=HMAC_KEY)
    audit.record(actor="a", action="campaign.create", object_type="campaign", object_id="c1")

    with engine.begin() as conn:
        conn.execute(
            text("UPDATE audit_events SET detail = '{\"evil\": true}' WHERE actor = 'a'")
        )
    assert audit.verify() != []
    engine.dispose()
