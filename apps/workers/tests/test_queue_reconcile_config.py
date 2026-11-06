"""Reconciliation must not mistake expired queue memory for lost work."""

import pytest
from kp_contracts.queue import MAX_QUEUE_RECONCILE_WINDOW_HOURS, QUEUE_PUBLISH_DEDUP_TTL_SECONDS
from kp_workers.config import WorkerSettings
from pydantic import ValidationError


def test_reconciliation_window_is_bounded_below_actual_publish_retention() -> None:
    settings = WorkerSettings(_env_file=None, queue_reconcile_window_hours=MAX_QUEUE_RECONCILE_WINDOW_HOURS)
    assert settings.queue_reconcile_window_hours * 3600 < QUEUE_PUBLISH_DEDUP_TTL_SECONDS
    assert WorkerSettings(_env_file=None).queue_reconcile_window_hours == 24


@pytest.mark.parametrize("hours", (MAX_QUEUE_RECONCILE_WINDOW_HOURS + 1, QUEUE_PUBLISH_DEDUP_TTL_SECONDS // 3600))
def test_unsafe_reconciliation_window_is_rejected(hours: int) -> None:
    with pytest.raises(ValidationError):
        WorkerSettings(_env_file=None, queue_reconcile_window_hours=hours)
