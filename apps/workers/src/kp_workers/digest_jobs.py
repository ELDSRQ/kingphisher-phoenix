"""H10: the weekly awareness digest.

A once-a-week aggregate ("this week: X sent / Y opened / Z reported") delivered
through the H8 system-alert channel. Off unless KP_WORKER_WEEKLY_DIGEST_ENABLED
is set, and a no-op sender unless a system-alert destination is also configured.

Dedup is by data, not by an in-memory timer: the enqueue is keyed on the ISO
week, and the outbox ON CONFLICT (idempotency_key) DO NOTHING means exactly one
digest is ever enqueued per week no matter how often — or by how many replicas —
this is called.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from kp_database.models import TrackingEvent
from kp_database.outbox import enqueue_queue
from kp_domain_models import models as dm
from sqlalchemy import func, select

if TYPE_CHECKING:
    from kp_workers.jobs import WorkerContext

# The five counts a two-person team cares about at a glance. Kept small so the
# digest stays a nudge, not a report.
_DIGEST_EVENTS = (
    dm.EventType.SEND_ACCEPTED,
    dm.EventType.OPENED,
    dm.EventType.CLICKED,
    dm.EventType.MESSAGE_REPORTED,
    dm.EventType.TRAINING_COMPLETED,
)
_DIGEST_WINDOW_DAYS = 7


def maybe_publish_weekly_digest(ctx: WorkerContext, now: datetime) -> None:
    """Enqueue at most one weekly-digest system alert per ISO week."""
    if not ctx.settings.weekly_digest_enabled:
        return
    iso = now.isocalendar()
    idempotency_key = f"digest:{iso.year}-W{iso.week:02d}"
    since = now - timedelta(days=_DIGEST_WINDOW_DAYS)
    with ctx.session_factory() as session:
        counts = {
            event_type.value: int(
                session.scalar(
                    select(func.count())
                    .select_from(TrackingEvent)
                    .where(TrackingEvent.event_type == event_type, TrackingEvent.occurred_at >= since)
                )
                or 0
            )
            for event_type in _DIGEST_EVENTS
        }
        enqueue_queue(
            session,
            topic="alert",
            payload={
                "scope": "system",
                "event_type": "digest.weekly",
                "occurred_at": now.isoformat(),
                "detail": {"window_days": _DIGEST_WINDOW_DAYS, "counts": counts},
            },
            idempotency_key=idempotency_key,
        )
        session.commit()
