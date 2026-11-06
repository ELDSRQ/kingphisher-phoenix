"""Hermetic tests for the KP-AUD-007 queue<->outbox reconciliation logic.

The companion PostgreSQL test covers the restricted-table read function using
actual least-privilege logins. These tests cover replay and reporting policy.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from kp_database.outbox import OutboxDispatcher


class _FakeQueue:
    def __init__(self, *, present: set[str]) -> None:
        self._present = present
        self.published: list[tuple[str, dict[str, Any], str, float | None]] = []

    def job_published(self, topic: str, idempotency_key: str) -> bool:
        return idempotency_key in self._present

    def publish(
        self,
        topic: str,
        payload: dict[str, Any],
        *,
        idempotency_key: str,
        available_at: float | None = None,
    ) -> str:
        self.published.append((topic, payload, idempotency_key, available_at))
        self._present.add(idempotency_key)
        return str(uuid.uuid4())


def _row(topic: str, key: str) -> dict[str, Any]:
    return {
        "outbox_id": uuid.uuid4(),
        "topic": topic,
        "payload": {"idempotency_key": key, "n": 1},
        "idempotency_key": key,
        "available_at": datetime(2026, 10, 1, tzinfo=UTC),
        "dispatched_at": datetime(2026, 10, 1, tzinfo=UTC),
    }


def _dispatcher(monkeypatch: pytest.MonkeyPatch, rows: list[dict[str, Any]]) -> OutboxDispatcher:
    dispatcher = OutboxDispatcher(engine=object())  # type: ignore[arg-type]
    monkeypatch.setattr(
        OutboxDispatcher,
        "_claim_reconcilable_dispatched",
        lambda _self, *, topic, window_seconds, limit: [r for r in rows if r["topic"] == topic],
    )
    return dispatcher


def test_replay_safe_topic_re_enqueues_only_jobs_redis_lost(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [_row("remind", "present-key"), _row("remind", "lost-key")]
    queue = _FakeQueue(present={"present-key"})
    dispatcher = _dispatcher(monkeypatch, rows)

    report = dispatcher.reconcile_queue(queue, topic="remind", replay_safe=True, window_seconds=86400)

    assert report == {"checked": 2, "replayed": 1, "review_required": 0, "present": 1}
    assert [p[2] for p in queue.published] == ["lost-key"]
    assert queue.published[0][0] == "remind"
    # The job still known to Redis is left untouched (no duplicate).


def test_review_only_topic_never_re_enqueues_even_when_lost(monkeypatch: pytest.MonkeyPatch) -> None:
    # KP-AUD-007 invariant: a delivery job whose provider acceptance is unknown
    # must never be auto re-submitted — that could re-send an employee a
    # duplicate simulated-phishing email. It is surfaced for human review.
    rows = [_row("deliver", "lost-1"), _row("deliver", "lost-2")]
    queue = _FakeQueue(present=set())
    dispatcher = _dispatcher(monkeypatch, rows)

    report = dispatcher.reconcile_queue(queue, topic="deliver", replay_safe=False, window_seconds=86400)

    assert report == {"checked": 2, "replayed": 0, "review_required": 2, "present": 0}
    assert queue.published == []


def test_reconcile_is_a_noop_when_queue_still_has_every_job(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [_row("remind", "a"), _row("remind", "b")]
    queue = _FakeQueue(present={"a", "b"})
    dispatcher = _dispatcher(monkeypatch, rows)

    report = dispatcher.reconcile_queue(queue, topic="remind", replay_safe=True, window_seconds=3600)

    assert report == {"checked": 2, "replayed": 0, "review_required": 0, "present": 2}
    assert queue.published == []


def test_replayed_job_preserves_its_original_idempotency_key(monkeypatch: pytest.MonkeyPatch) -> None:
    # At-least-once with dedup intact: re-publishing with the same key means a
    # survivor (if any) is deduped rather than duplicated.
    rows = [_row("remind", "stable-key")]
    queue = _FakeQueue(present=set())
    dispatcher = _dispatcher(monkeypatch, rows)

    dispatcher.reconcile_queue(queue, topic="remind", replay_safe=True, window_seconds=3600)

    assert queue.published[0][2] == "stable-key"
    assert queue.published[0][3] == datetime(2026, 10, 1, tzinfo=UTC).timestamp()


@pytest.mark.parametrize("topic", ["deliver", "reply-mailbox", "alert", "future-topic"])
def test_direct_call_cannot_override_review_only_policy(monkeypatch, topic):
    dispatcher = _dispatcher(monkeypatch, [_row(topic, "lost")])
    queue = _FakeQueue(present=set())
    assert dispatcher.reconcile_queue(queue, topic=topic, replay_safe=True, window_seconds=3600)["review_required"] == 1
    assert queue.published == []


def test_review_condition_logs_once_until_rows_change_or_clear(monkeypatch, caplog):
    rows = [_row("deliver", f"lost-{i}") for i in range(100)]
    dispatcher = _dispatcher(monkeypatch, rows)
    queue = _FakeQueue(present=set())
    for _ in range(3):
        report = dispatcher.reconcile_queue(queue, topic="deliver", replay_safe=False, window_seconds=3600)
        assert report["review_required"] == 100
    assert len(caplog.records) == 1
    assert "count=100 action=manual_provider_reconciliation" in caplog.text
    assert "outbox_id" not in caplog.text
    rows[0] = _row("deliver", "different-incident")
    dispatcher.reconcile_queue(queue, topic="deliver", replay_safe=False, window_seconds=3600)
    assert len(caplog.records) == 2
    queue._present = {r["idempotency_key"] for r in rows}
    dispatcher.reconcile_queue(queue, topic="deliver", replay_safe=False, window_seconds=3600)
    queue._present.clear()
    dispatcher.reconcile_queue(queue, topic="deliver", replay_safe=False, window_seconds=3600)
    assert len(caplog.records) == 3


@pytest.mark.parametrize("window,limit", [(0, 1), (7689601, 1), (1, 0), (1, 5001), (True, 1)])
def test_reconciliation_rejects_bounds_before_connecting(window, limit):
    with pytest.raises(ValueError):
        OutboxDispatcher(engine=object())._claim_reconcilable_dispatched(
            topic="remind", window_seconds=window, limit=limit
        )


def test_audit_store_binds_only_reconciliation_to_business_engine():
    from kp_database.audit_store import AuditStore
    from sqlalchemy import create_engine

    audit = create_engine("sqlite://")
    business = create_engine("sqlite:///worker")
    replacement = create_engine("sqlite:///replacement")
    store = AuditStore(audit, intent_engine=business)
    assert store._dispatcher._engine is audit
    assert store._dispatcher._reconciliation_engine is business
    store.bind_intent_engine(replacement)
    assert store._dispatcher._engine is audit
    assert store._dispatcher._reconciliation_engine is replacement
    assert not store._dispatcher._allow_owner_fallback


def _paging_dispatcher(monkeypatch, rows):
    dispatcher = OutboxDispatcher(engine=object())

    def page(_self, *, topic, window_seconds, limit, before_dispatched_at=None, before_outbox_id=None):
        matching = sorted(
            (row for row in rows if row["topic"] == topic),
            key=lambda row: (row["dispatched_at"], row["outbox_id"]),
            reverse=True,
        )
        if before_dispatched_at is not None:
            matching = [
                row
                for row in matching
                if (row["dispatched_at"], row["outbox_id"]) < (before_dispatched_at, before_outbox_id)
            ]
        return matching[:limit]

    monkeypatch.setattr(OutboxDispatcher, "_claim_reconcilable_dispatched", page)
    return dispatcher


def test_sweep_recovers_more_than_limit_despite_new_publications(monkeypatch):
    from datetime import timedelta

    rows = [_row("remind", f"lost-{i}") for i in range(501)]
    dispatcher = _paging_dispatcher(monkeypatch, rows)
    queue = _FakeQueue(present=set())
    assert dispatcher.reconcile_queue(queue, topic="remind", replay_safe=True, window_seconds=86400)["replayed"] == 500
    newest = _row("remind", "new-publication")
    newest["dispatched_at"] += timedelta(seconds=1)
    rows.append(newest)
    assert dispatcher.reconcile_queue(queue, topic="remind", replay_safe=True, window_seconds=86400)["replayed"] == 1
    assert {f"lost-{i}" for i in range(501)} <= queue._present
    assert "new-publication" not in queue._present
    assert dispatcher.reconcile_queue(queue, topic="remind", replay_safe=True, window_seconds=86400)["replayed"] == 1
    assert "new-publication" in queue._present


def test_review_condition_is_reported_once_per_complete_sweep(monkeypatch, caplog):
    rows = [_row("deliver", f"lost-{i}") for i in range(3)]
    dispatcher = _paging_dispatcher(monkeypatch, rows)
    queue = _FakeQueue(present=set())
    for _ in range(2):
        dispatcher.reconcile_queue(queue, topic="deliver", replay_safe=False, window_seconds=86400, limit=2)
        dispatcher.reconcile_queue(queue, topic="deliver", replay_safe=False, window_seconds=86400, limit=2)
    assert len(caplog.records) == 1
    assert "count=3" in caplog.text
    queue._present.update(row["idempotency_key"] for row in rows)
    for _ in range(2):
        dispatcher.reconcile_queue(queue, topic="deliver", replay_safe=False, window_seconds=86400, limit=2)
    assert "deliver" not in dispatcher._review_conditions


def test_page_failure_does_not_skip_unpublished_rows(monkeypatch):
    rows = [_row("remind", f"lost-{i}") for i in range(3)]
    dispatcher = _paging_dispatcher(monkeypatch, rows)
    queue = _FakeQueue(present=set())
    publish = queue.publish
    calls = 0

    def fail_once(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise ConnectionError("synthetic publish failure")
        return publish(*args, **kwargs)

    monkeypatch.setattr(queue, "publish", fail_once)
    with pytest.raises(ConnectionError):
        dispatcher.reconcile_queue(queue, topic="remind", replay_safe=True, window_seconds=86400, limit=2)
    assert "remind" not in dispatcher._reconciliation_cursors
    for _ in range(2):
        dispatcher.reconcile_queue(queue, topic="remind", replay_safe=True, window_seconds=86400, limit=2)
    assert len(queue.published) == 3
    assert queue._present == {row["idempotency_key"] for row in rows}


def test_cursor_pair_validation_happens_before_connecting():
    dispatcher = OutboxDispatcher(engine=object())
    with pytest.raises(ValueError, match="both timestamp"):
        dispatcher._claim_reconcilable_dispatched(
            topic="remind", window_seconds=86400, limit=2, before_outbox_id=uuid.uuid4()
        )
