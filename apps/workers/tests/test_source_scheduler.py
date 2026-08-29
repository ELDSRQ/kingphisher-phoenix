from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, cast

import pytest
from kp_database.models import Source, SourceTerms
from kp_domain_models import models as dm
from kp_workers import jobs
from kp_workers.config import WorkerSettings
from kp_workers.jobs import WorkerContext, maybe_publish_source_ingestion
from kp_workers.supervisor import RoleSpec, WorkerSupervisor
from sqlalchemy import Engine, Table, create_engine, text
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool


class _Audit:
    def __init__(self) -> None:
        self.dispatches = 0

    def dispatch_pending_queue(self, _queue: object) -> None:
        self.dispatches += 1

    def dispatch_pending_audit(self) -> None:
        return None


class _Queue:
    def pop(self, _topic: str, *, timeout: int) -> None:
        assert timeout == 0
        return None

    def recover_stale(self, _topic: str, *, visibility_seconds: int, max_retries: int) -> int:
        assert visibility_seconds == 60
        assert max_retries == 3
        return 0

    def ack(self, _topic: str, _message: dict[str, Any]) -> None:
        return None

    def reject(self, _topic: str, _message: dict[str, Any], *, max_retries: int) -> None:
        return None


def _engine() -> Engine:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    cast(Table, Source.__table__).create(engine)
    cast(Table, SourceTerms.__table__).create(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TABLE transactional_outbox ("
            "outbox_id VARCHAR(36) PRIMARY KEY, kind VARCHAR(16) NOT NULL, topic VARCHAR(64), "
            "payload JSON NOT NULL, idempotency_key VARCHAR(128) NOT NULL UNIQUE, "
            "available_at DATETIME NOT NULL, status VARCHAR(16) NOT NULL DEFAULT 'pending')"
        )
    return engine


def _source_and_terms(
    index: int,
    *,
    now: datetime,
    enabled: bool = True,
    terms_enabled: bool = True,
    complete: bool = True,
    current: bool = True,
) -> tuple[Source, SourceTerms]:
    source_id = uuid.UUID(f"00000000-0000-4000-8000-{index:011x}f")
    terms_id = uuid.UUID(f"10000000-0000-4000-8000-{index:011x}e")
    source = Source(
        source_id=source_id,
        source_key=f"source-{index}",
        name=f"Source {index}",
        source_type=dm.SourceType.RSS,
        base_domain=f"feed-{index}.example.com",
        fetch_path="/feed.xml",
        license_state_id=terms_id,
        enabled=enabled,
        last_success_at=now - timedelta(days=2),
        last_attempt_at=now - timedelta(days=1),
        consecutive_failures=index,
    )
    terms = SourceTerms(
        source_terms_id=terms_id,
        source_id=source_id,
        terms_reference=f"https://feed-{index}.example.com/terms",
        terms_hash=f"{index:x}".rjust(64, "a")[-64:],
        commercial_use_ok=complete,
        automation_ok=complete,
        redistribution_ok=complete,
        retention_ok=complete,
        terms_reviewed_at=now - timedelta(days=30),
        next_review_at=now + timedelta(days=30) if current else now - timedelta(seconds=1),
        enabled=terms_enabled,
    )
    return source, terms


@contextmanager
def _context(engine: Engine) -> Iterator[tuple[WorkerContext, _Audit]]:
    @contextmanager
    def factory() -> Iterator[Session]:
        with Session(engine) as session:
            yield session

    audit = _Audit()
    context = WorkerContext(
        WorkerSettings(_env_file=None),
        factory,
        audit,  # type: ignore[arg-type]
        _Queue(),  # type: ignore[arg-type]
    )
    yield context, audit


def _keys(engine: Engine) -> list[str]:
    with engine.connect() as connection:
        return list(
            connection.scalars(
                text("SELECT idempotency_key FROM transactional_outbox WHERE kind = 'queue' ORDER BY idempotency_key")
            )
        )


def test_daily_source_scheduler_is_durable_idempotent_and_governance_bounded() -> None:
    engine = _engine()
    now = datetime(2026, 8, 29, 12, tzinfo=UTC)
    valid, valid_terms = _source_and_terms(1, now=now)
    disabled, disabled_terms = _source_and_terms(2, now=now, enabled=False)
    revoked, revoked_terms = _source_and_terms(3, now=now, terms_enabled=False)
    incomplete, incomplete_terms = _source_and_terms(4, now=now, complete=False)
    expired, expired_terms = _source_and_terms(5, now=now, current=False)
    valid_source_id = valid.source_id
    expected_status = (valid.last_attempt_at, valid.last_success_at, valid.consecutive_failures)
    with Session(engine) as session:
        session.add_all(
            [
                valid,
                valid_terms,
                disabled,
                disabled_terms,
                revoked,
                revoked_terms,
                incomplete,
                incomplete_terms,
                expired,
                expired_terms,
            ]
        )
        session.commit()
    with _context(engine) as (context, audit):
        first = maybe_publish_source_ingestion(context, now)
        repeated = maybe_publish_source_ingestion(context, now + timedelta(hours=1))

    bucket = int(now.timestamp()) // 86_400
    assert first == {"eligible": 1, "scheduled": 1, "truncated": False}
    assert repeated == first
    assert _keys(engine) == [f"ingest-daily:{valid_source_id}:{bucket}"]
    assert audit.dispatches == 2
    with Session(engine) as session:
        persisted = session.get(Source, valid_source_id)
        assert persisted is not None
        assert persisted.last_attempt_at == expected_status[0].replace(tzinfo=None)
        assert persisted.last_success_at == expected_status[1].replace(tzinfo=None)
        assert persisted.consecutive_failures == expected_status[2]
    engine.dispose()


def test_daily_source_scheduler_uses_a_fresh_key_next_day() -> None:
    engine = _engine()
    now = datetime(2026, 8, 29, 12, tzinfo=UTC)
    source, terms = _source_and_terms(10, now=now)
    source_id = source.source_id
    with Session(engine) as session:
        session.add_all([source, terms])
        session.commit()

    with _context(engine) as (context, _audit):
        maybe_publish_source_ingestion(context, now)
        maybe_publish_source_ingestion(context, now + timedelta(days=1))

    assert _keys(engine) == [
        f"ingest-daily:{source_id}:{int(now.timestamp()) // 86_400}",
        f"ingest-daily:{source_id}:{int((now + timedelta(days=1)).timestamp()) // 86_400}",
    ]
    engine.dispose()


def test_daily_source_scheduler_fails_closed_at_its_collection_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = _engine()
    now = datetime(2026, 8, 29, 12, tzinfo=UTC)
    first, first_terms = _source_and_terms(20, now=now)
    second, second_terms = _source_and_terms(21, now=now)
    with Session(engine) as session:
        session.add_all([first, first_terms, second, second_terms])
        session.commit()
    monkeypatch.setattr(jobs, "_SOURCE_INGESTION_DAILY_LIMIT", 1)

    with _context(engine) as (context, _audit):
        result = maybe_publish_source_ingestion(context, now)

    assert result == {"eligible": 1, "scheduled": 1, "truncated": True}
    assert len(_keys(engine)) == 1
    engine.dispose()


def test_ingestion_supervisor_self_schedules_once_per_daily_interval(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[datetime] = []
    queue = _Queue()
    audit = _Audit()
    context = SimpleNamespace(
        settings=SimpleNamespace(
            visibility_seconds=60,
            max_retries=3,
            recovery_every_polls=10,
            retention_interval_seconds=86_400,
            audit_anchor_interval_seconds=3_600,
            poll_seconds=1,
        ),
        queue=queue,
        audit_store=audit,
        session_factory=lambda: None,
    )
    monkeypatch.setattr(jobs, "maybe_publish_source_ingestion", lambda _context, now: calls.append(now))
    clock = [10.0]
    supervisor = WorkerSupervisor(
        {"ingestion": RoleSpec(name="ingestion", topic="ingest", process=lambda _ctx, _msg: None, context=context)},
        clock=lambda: clock[0],
    )

    supervisor.run_cycle()
    clock[0] += 86_399
    supervisor.run_cycle()
    clock[0] += 1
    supervisor.run_cycle()

    assert len(calls) == 2
