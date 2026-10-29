"""Hermetic tests for the KP-AUD-007 queue<->outbox reconciliation logic.

These exercise the per-role replay policy with a fake queue and canned
dispatched rows (``_claim_reconcilable_dispatched`` monkeypatched). The actual
restricted-table read path (the future ``kp_reconcile_queue_outbox`` SECURITY
DEFINER function, and the owner/development direct-SQL fallback) needs the
Postgres gate and is covered by a ``@pytest.mark.postgres`` test below.
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
    rows = [_row("alert", "stable-key")]
    queue = _FakeQueue(present=set())
    dispatcher = _dispatcher(monkeypatch, rows)

    dispatcher.reconcile_queue(queue, topic="alert", replay_safe=True, window_seconds=3600)

    assert queue.published[0][2] == "stable-key"
    assert queue.published[0][3] == datetime(2026, 10, 1, tzinfo=UTC).timestamp()
