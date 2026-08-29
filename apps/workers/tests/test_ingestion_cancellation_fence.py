from __future__ import annotations

import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from kp_database.models import SourceTerms
from kp_domain_models import models as dm
from kp_workers.config import WorkerSettings
from kp_workers.jobs import WorkerContext, process_ingestion
from sqlalchemy.dialects import postgresql


class _Audit:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def record(self, **kwargs: Any) -> None:
        self.records.append(kwargs)


class _Session:
    def __init__(self, source: object, terms: object | None, scalar_results: list[object | None]) -> None:
        self.source = source
        self.terms = terms
        self.scalar_results = scalar_results
        self.scalar_statements: list[object] = []
        self.added: list[object] = []
        self.commits = 0

    def get(self, model: object, _identifier: object) -> object | None:
        if model is SourceTerms:
            return self.terms
        return self.source

    def scalar(self, statement: object) -> object | None:
        self.scalar_statements.append(statement)
        return self.scalar_results.pop(0)

    def add(self, value: object) -> None:
        self.added.append(value)

    def commit(self) -> None:
        self.commits += 1


def _source(*, enabled: bool = True, consecutive_failures: int = 0) -> SimpleNamespace:
    return SimpleNamespace(
        source_id=uuid.uuid4(),
        source_key="fence-test",
        name="Fence test",
        source_type=dm.SourceType.RSS,
        base_domain="feed.example.com",
        fetch_path="/feed.xml",
        license_state_id=uuid.uuid4(),
        enabled=enabled,
        last_success_at=datetime(2026, 8, 1, tzinfo=UTC),
        last_attempt_at=datetime(2026, 8, 2, tzinfo=UTC),
        consecutive_failures=consecutive_failures,
    )


def _terms(source: SimpleNamespace, *, enabled: bool = True) -> SimpleNamespace:
    return SimpleNamespace(
        source_terms_id=source.license_state_id,
        source_id=source.source_id,
        terms_reference="not exposed in audit",
        terms_hash="a" * 64,
        commercial_use_ok=True,
        automation_ok=True,
        redistribution_ok=True,
        retention_ok=True,
        terms_reviewed_at=datetime.now(UTC) - timedelta(days=1),
        next_review_at=datetime.now(UTC) + timedelta(days=30),
        enabled=enabled,
    )


def _item(source_id: uuid.UUID) -> dm.SourceItem:
    now = datetime(2026, 8, 27, tzinfo=UTC)
    return dm.SourceItem(
        source_id=source_id,
        publisher="Example",
        title="Fetched item",
        published_at=now,
        retrieved_at=now,
        sanitized_text="Safe source text",
        content_hash="a" * 64,
        source_reference="https://feed.example.com/item",
        confidence=dm.Confidence.HIGH,
    )


def _context(session: _Session, *, threshold: int = 3) -> tuple[WorkerContext, _Audit]:
    @contextmanager
    def factory() -> Any:
        yield session

    audit = _Audit()
    settings = WorkerSettings.model_validate({"source_failure_threshold": threshold})
    context = WorkerContext(settings, factory, audit, SimpleNamespace())  # type: ignore[arg-type]
    return context, audit


def _patch_adapter(monkeypatch: pytest.MonkeyPatch, fetch: object) -> None:
    monkeypatch.setattr("kp_workers.jobs._make_fetcher", lambda _source: object())
    monkeypatch.setattr("kp_workers.jobs._source_adapter", lambda _source, _fetcher: SimpleNamespace(fetch=fetch))


def test_disable_during_fetch_is_observed_under_lock_before_content_writes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    initial = _source(enabled=True, consecutive_failures=2)
    disabled = _source(enabled=False, consecutive_failures=2)
    disabled.source_id = initial.source_id
    prior_success = disabled.last_success_at
    prior_attempt = disabled.last_attempt_at
    session = _Session(initial, _terms(initial), [disabled])
    context, audit = _context(session)
    fetched = [_item(initial.source_id)]
    _patch_adapter(monkeypatch, lambda: fetched)

    process_ingestion(context, {"payload": {"source_id": str(initial.source_id)}})

    assert session.added == []
    assert session.commits == 1
    assert disabled.last_attempt_at > prior_attempt
    assert disabled.last_success_at == prior_success
    assert disabled.consecutive_failures == 2
    assert audit.records[0]["action"] == "ingest.fetch.discarded"
    assert audit.records[0]["detail"] == {"reason": "source_disabled_after_fetch"}
    assert len(session.scalar_statements) == 1
    fence_sql = str(
        session.scalar_statements[0].compile(dialect=postgresql.dialect())  # type: ignore[attr-defined, no-untyped-call]
    )
    assert "FOR UPDATE" in fence_sql


def test_worker_holding_post_fetch_lock_quarantines_new_evidence_without_pattern(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    initial = _source(enabled=True)
    locked = _source(enabled=True)
    locked.source_id = initial.source_id
    locked.license_state_id = initial.license_state_id
    item = _item(initial.source_id)
    session = _Session(initial, _terms(initial), [locked, None])
    context, audit = _context(session)
    _patch_adapter(monkeypatch, lambda: [item])
    process_ingestion(context, {"payload": {"source_id": str(initial.source_id)}})

    assert len(session.added) == 1
    assert session.added[0].license_state_id == initial.license_state_id
    assert session.added[0].quarantine_state == dm.QuarantineState.QUARANTINED
    assert session.added[0].quarantine_reason == "awaiting_operator_review"
    assert locked.last_attempt_at.tzinfo is UTC
    assert session.commits == 1
    assert locked.last_success_at == locked.last_attempt_at
    assert locked.consecutive_failures == 0
    assert audit.records[0]["action"] == "ingest.run"
    assert audit.records[0]["detail"] == {"inserted": 1, "patterns": 0}


def test_provider_failure_still_updates_breaker_without_entering_success_fence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _source(enabled=True)
    session = _Session(source, _terms(source), [])
    context, audit = _context(session, threshold=1)

    def fail() -> list[dm.SourceItem]:
        raise RuntimeError("provider unavailable")

    _patch_adapter(monkeypatch, fail)

    with pytest.raises(RuntimeError, match="provider unavailable"):
        process_ingestion(context, {"payload": {"source_id": str(source.source_id)}})

    assert session.scalar_statements == []
    assert session.added == []
    assert session.commits == 1
    assert source.enabled is False
    assert source.consecutive_failures == 1
    assert audit.records[0]["action"] == "ingest.source.disabled"


def test_revoked_terms_after_queue_skip_network_and_disable_source(monkeypatch: pytest.MonkeyPatch) -> None:
    source = _source(enabled=True)
    terms = _terms(source, enabled=False)
    session = _Session(source, terms, [])
    context, audit = _context(session)
    network_called = False

    def fetch() -> list[dm.SourceItem]:
        nonlocal network_called
        network_called = True
        return []

    _patch_adapter(monkeypatch, fetch)

    process_ingestion(context, {"payload": {"source_id": str(source.source_id)}})

    assert network_called is False
    assert source.enabled is False
    assert session.scalar_statements == []
    assert session.added == []
    assert session.commits == 1
    assert audit.records[0]["action"] == "ingest.source.governance_disabled"
    assert audit.records[0]["detail"] == {"reason": "source_terms_not_current"}
    assert terms.terms_reference not in str(audit.records[0])


def test_terms_revoked_during_fetch_are_rechecked_before_content_writes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    initial = _source(enabled=True)
    locked = _source(enabled=True)
    locked.source_id = initial.source_id
    locked.license_state_id = initial.license_state_id
    terms = _terms(initial)
    session = _Session(initial, terms, [locked])
    context, audit = _context(session)

    def fetch() -> list[dm.SourceItem]:
        terms.enabled = False
        return [_item(initial.source_id)]

    _patch_adapter(monkeypatch, fetch)

    process_ingestion(context, {"payload": {"source_id": str(initial.source_id)}})

    assert locked.enabled is False
    assert session.added == []
    assert session.commits == 1
    assert audit.records[0]["action"] == "ingest.source.governance_disabled"
    assert audit.records[0]["detail"] == {"reason": "source_terms_not_current"}
