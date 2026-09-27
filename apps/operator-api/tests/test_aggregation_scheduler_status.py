"""F2: the aggregation scheduler's state must be visible to the operator.

The scheduler ships OFF by default, so trend/candidate data can sit stale with
nothing on screen saying so. `status_snapshot()` is what the Aggregation view
reads to warn about that; these pin its shape and the disabled/enabled states.
"""

from __future__ import annotations

from types import SimpleNamespace

from kp_operator_api.console.aggregation_routes import AggregationScheduler, aggregation_status


def _scheduler(*, enabled: bool) -> AggregationScheduler:
    return AggregationScheduler(
        SimpleNamespace(ai_gateway_url=""),
        session_factory=lambda: None,
        enabled=enabled,
        interval_seconds=900.0,
        max_items=10,
        max_candidates=5,
    )


def test_disabled_scheduler_snapshot_says_disabled_and_never_run() -> None:
    snap = _scheduler(enabled=False).status_snapshot()
    assert snap == {"enabled": False, "status": "disabled", "interval_seconds": 900.0, "last_run_at": None}


def test_enabled_scheduler_starts_pending_with_no_last_run() -> None:
    snap = _scheduler(enabled=True).status_snapshot()
    assert snap["enabled"] is True
    assert snap["status"] == "pending"
    assert snap["last_run_at"] is None


def test_status_endpoint_reports_the_scheduler_on_app_state() -> None:
    sched = _scheduler(enabled=False)
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(aggregation_scheduler=sched)))
    assert aggregation_status(request, _principal=None) == {"scheduler": sched.status_snapshot()}


def test_status_endpoint_fails_safe_when_no_scheduler_is_wired() -> None:
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace()))
    body = aggregation_status(request, _principal=None)
    assert body["scheduler"]["enabled"] is False
    assert body["scheduler"]["status"] == "disabled"
