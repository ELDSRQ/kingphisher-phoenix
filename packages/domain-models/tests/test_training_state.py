from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from kp_domain_models.models import TrainingState, training_state

ASSIGNED = datetime(2026, 8, 1, tzinfo=UTC)
DUE = ASSIGNED + timedelta(days=3)


@pytest.mark.parametrize(
    ("opened_at", "completed_at", "as_of", "expected"),
    [
        (None, None, ASSIGNED, TrainingState.ASSIGNED),
        (ASSIGNED + timedelta(hours=1), None, ASSIGNED + timedelta(days=1), TrainingState.OPENED),
        (None, None, DUE, TrainingState.OVERDUE),
        (ASSIGNED + timedelta(hours=1), None, DUE + timedelta(days=1), TrainingState.OVERDUE),
        (ASSIGNED + timedelta(days=4), ASSIGNED + timedelta(days=5), DUE + timedelta(days=10), TrainingState.COMPLETED),
    ],
)
def test_training_state_is_derived_from_first_write_timestamps(
    opened_at: datetime | None,
    completed_at: datetime | None,
    as_of: datetime,
    expected: TrainingState,
) -> None:
    assert (
        training_state(
            assigned_at=ASSIGNED,
            due_at=DUE,
            opened_at=opened_at,
            completed_at=completed_at,
            as_of=as_of,
        )
        is expected
    )


def test_training_state_rejects_impossible_timestamp_order() -> None:
    with pytest.raises(ValueError, match="opened_at"):
        training_state(
            assigned_at=ASSIGNED,
            due_at=DUE,
            opened_at=ASSIGNED - timedelta(seconds=1),
            completed_at=None,
            as_of=ASSIGNED,
        )

    with pytest.raises(ValueError, match="completed_at cannot precede opened_at"):
        training_state(
            assigned_at=ASSIGNED,
            due_at=DUE,
            opened_at=ASSIGNED + timedelta(hours=2),
            completed_at=ASSIGNED + timedelta(hours=1),
            as_of=DUE,
        )


def test_training_state_does_not_apply_future_events_to_historical_view() -> None:
    assert (
        training_state(
            assigned_at=ASSIGNED,
            due_at=DUE,
            opened_at=ASSIGNED + timedelta(days=1),
            completed_at=ASSIGNED + timedelta(days=2),
            as_of=ASSIGNED + timedelta(hours=1),
        )
        is TrainingState.ASSIGNED
    )


def test_training_state_rejects_naive_or_pre_assignment_as_of() -> None:
    with pytest.raises(ValueError, match="timezone"):
        training_state(
            assigned_at=ASSIGNED.replace(tzinfo=None),
            due_at=DUE,
            opened_at=None,
            completed_at=None,
            as_of=DUE,
        )
    with pytest.raises(ValueError, match="as_of"):
        training_state(
            assigned_at=ASSIGNED,
            due_at=DUE,
            opened_at=None,
            completed_at=None,
            as_of=ASSIGNED - timedelta(seconds=1),
        )
