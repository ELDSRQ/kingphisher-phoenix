"""AUD-003 (F1): the audit-anchor staleness trip must not be silent.

Before this, a present-but-stale anchor heartbeat tripped the mutation gate
(503) but emitted no log and no alert — the single most safety-critical event
(audit anchoring stalled) reached no operator. These tests pin that the alert
sink fires exactly once per staleness episode, resets on recovery, and can never
turn a health check into a crash.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from kp_operator_api.main import (
    _anchor_heartbeat_is_stale,
    _make_audit_health_check,
)

_INTERVAL = 3600.0


def _healthy_verifier():
    return SimpleNamespace(status="ok")


def _healthy_store():
    return SimpleNamespace(outbox_health=lambda: {"overdue_pending": 0, "failed": 0, "dispatching_stale": 0})


def _app_state(anchor_at, sink):
    return SimpleNamespace(
        audit_verifier=_healthy_verifier(),
        audit_store=_healthy_store(),
        last_successful_anchor_at=lambda: anchor_at,
        audit_anchor_gate_interval_seconds=_INTERVAL,
        audit_anchor_alert_sink=sink,
    )


class _Logger:
    def __init__(self):
        self.warnings, self.errors, self.exceptions = [], [], []

    def warning(self, msg, *a, **k):
        self.warnings.append(msg)

    def error(self, msg, *a, **k):
        self.errors.append(msg)

    def exception(self, msg, *a, **k):
        self.exceptions.append(msg)


def test_staleness_helper_only_trips_on_a_present_tzaware_stale_heartbeat() -> None:
    now = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)
    fresh = now - timedelta(seconds=_INTERVAL)  # within 2x
    stale = now - timedelta(seconds=3 * _INTERVAL)  # beyond 2x
    assert _anchor_heartbeat_is_stale(stale, _INTERVAL, now=now) is True
    assert _anchor_heartbeat_is_stale(fresh, _INTERVAL, now=now) is False
    # absence / disabled gate / naive timestamp are NOT stale (gate fails open)
    assert _anchor_heartbeat_is_stale(None, _INTERVAL, now=now) is False
    assert _anchor_heartbeat_is_stale(stale, None, now=now) is False
    assert _anchor_heartbeat_is_stale(stale.replace(tzinfo=None), _INTERVAL, now=now) is False


def test_stale_anchor_fires_the_alert_sink_exactly_once_per_episode() -> None:
    stale = datetime.now(UTC) - timedelta(seconds=3 * _INTERVAL)
    fired = []
    state = _app_state(stale, lambda at, iv: fired.append((at, iv)))
    check = _make_audit_health_check(state, logger=_Logger())

    # Gate is evaluated per mutation; the alert must fire once, not per call.
    assert check() is False
    assert check() is False
    assert check() is False
    assert len(fired) == 1
    assert fired[0] == (stale, _INTERVAL)


def test_recovery_resets_the_episode_so_a_later_stall_alerts_again() -> None:
    stale = datetime.now(UTC) - timedelta(seconds=3 * _INTERVAL)
    fresh = datetime.now(UTC)
    fired = []
    holder = {"anchor": stale}
    state = SimpleNamespace(
        audit_verifier=_healthy_verifier(),
        audit_store=_healthy_store(),
        last_successful_anchor_at=lambda: holder["anchor"],
        audit_anchor_gate_interval_seconds=_INTERVAL,
        audit_anchor_alert_sink=lambda at, iv: fired.append(at),
    )
    logger = _Logger()
    check = _make_audit_health_check(state, logger=logger)

    assert check() is False and len(fired) == 1  # stale -> alert
    holder["anchor"] = fresh
    assert check() is True  # recovered -> healthy again
    assert "audit_anchor_recovered" in logger.warnings
    holder["anchor"] = stale
    assert check() is False and len(fired) == 2  # stale again -> alert again


def test_a_failing_alert_sink_never_breaks_the_gate() -> None:
    stale = datetime.now(UTC) - timedelta(seconds=3 * _INTERVAL)

    def boom(_at, _iv):
        raise RuntimeError("sink is down")

    logger = _Logger()
    check = _make_audit_health_check(_app_state(stale, boom), logger=logger)

    # The gate must still return its bool; the sink failure is logged, not raised.
    assert check() is False
    assert "audit_anchor_alert_sink_failed" in logger.exceptions


def test_healthy_anchor_never_alerts() -> None:
    fresh = datetime.now(UTC) - timedelta(seconds=_INTERVAL // 2)
    fired = []
    check = _make_audit_health_check(_app_state(fresh, lambda at, iv: fired.append(at)), logger=_Logger())
    assert check() is True
    assert fired == []
