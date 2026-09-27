"""H10: the weekly awareness digest enqueue.

Off unless enabled; one enqueue per ISO week (idempotency key); the payload is a
system alert on the H8 channel carrying the five headline counts.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from kp_workers.digest_jobs import maybe_publish_weekly_digest


class _Session:
    def __init__(self, count: int = 3) -> None:
        self.count = count
        self.enqueued: list[tuple[Any, dict[str, Any]]] = []
        self.commits = 0

    def scalar(self, _statement: Any) -> int:
        return self.count

    def execute(self, statement: Any, params: dict[str, Any] | None = None) -> None:
        # enqueue_queue calls session.execute with the outbox insert + params.
        self.enqueued.append((statement, params or {}))

    def commit(self) -> None:
        self.commits += 1


def _ctx(session: _Session, *, enabled: bool):
    @contextmanager
    def factory():
        yield session

    return SimpleNamespace(
        settings=SimpleNamespace(weekly_digest_enabled=enabled),
        session_factory=factory,
    )


def test_disabled_digest_does_nothing() -> None:
    session = _Session()
    maybe_publish_weekly_digest(_ctx(session, enabled=False), datetime(2026, 9, 27, tzinfo=UTC))
    assert session.enqueued == []
    assert session.commits == 0


def test_enabled_digest_enqueues_a_system_alert_with_iso_week_key() -> None:
    session = _Session(count=5)
    # 2026-09-27 is ISO week 39.
    maybe_publish_weekly_digest(_ctx(session, enabled=True), datetime(2026, 9, 27, tzinfo=UTC))
    assert len(session.enqueued) == 1
    _stmt, params = session.enqueued[0]
    assert params["key"] == "digest:2026-W39"
    assert params["topic"] == "alert"
    # payload is JSON-encoded by enqueue_queue; assert the system-scope digest shape.
    payload = params["payload"]
    assert '"scope":"system"' in payload
    assert '"event_type":"digest.weekly"' in payload
    assert '"send_accepted":' in payload
    assert session.commits == 1


def test_key_tracks_the_iso_week_not_the_calendar_date() -> None:
    # 2027-01-01 is ISO week 53 of 2026 (ISO year differs from calendar year).
    session = _Session()
    maybe_publish_weekly_digest(_ctx(session, enabled=True), datetime(2027, 1, 1, tzinfo=UTC))
    _stmt, params = session.enqueued[0]
    assert params["key"] == "digest:2026-W53"
