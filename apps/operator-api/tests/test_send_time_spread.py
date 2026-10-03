"""Send-time spread (H9): staggering the full-audience publish over a window.

These tests pin the behavior of :func:`_publish_delivery_batches` directly so
they do not depend on a live database. The invariant under test is narrow and
safety-critical: with no spread configured the publish is byte-for-byte the
original single-``available_at`` burst, and with a spread the *only* thing that
changes is when each batch becomes claimable — every assignment id is still
published exactly once, and the whole audience is released within the window.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from kp_operator_api.routes import campaigns as campaigns_module


class _CapturingSession:
    """Stands in for the DB session; the real enqueue is monkeypatched away."""

    def execute(self, *args: Any, **kwargs: Any) -> None:  # pragma: no cover - unused
        return None


def _request(batch_size: int) -> SimpleNamespace:
    return SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                settings=SimpleNamespace(delivery_batch_size=batch_size),
                audit_store=SimpleNamespace(dispatch_pending_queue=lambda queue: None),
                queue=object(),
            )
        )
    )


def _publish(monkeypatch: pytest.MonkeyPatch, *, count: int, batch_size: int, **kwargs: Any) -> list[dict[str, Any]]:
    """Run a full-phase publish and return the captured enqueue calls in order."""

    captured: list[dict[str, Any]] = []
    monkeypatch.setattr(
        campaigns_module,
        "enqueue_queue",
        lambda session, *, topic, payload, idempotency_key, available_at=None: captured.append(
            {"payload": payload, "idempotency_key": idempotency_key, "available_at": available_at}
        ),
    )
    monkeypatch.setattr(campaigns_module, "dispatch_after_commit", lambda session, fn: None)

    assignment_ids = [str(uuid.uuid4()) for _ in range(count)]
    tracking_bearers = {
        aid: {"bearer": "b", "verifier": f"v{i}", "checksum": "c"} for i, aid in enumerate(assignment_ids)
    }
    campaign = SimpleNamespace(campaign_id=uuid.uuid4(), manifest_hash="m" * 64)
    gate = SimpleNamespace(
        review_manifest_hash="r" * 64,
        canary_evidence_hash="e" * 64,
        provider="acs",
        provider_config_hash="p" * 64,
    )
    campaigns_module._publish_delivery_batches(
        _request(batch_size),
        _CapturingSession(),
        campaign=campaign,
        campaign_id=str(campaign.campaign_id),
        assignment_ids=assignment_ids,
        tracking_bearers=tracking_bearers,
        idempotency_prefix="deliver:full:x",
        test_send=False,
        delivery_phase="full",
        launch_gate=gate,
        **kwargs,
    )
    # Every assignment is published exactly once regardless of spread.
    published = [aid for call in captured for aid in call["payload"]["recipient_assignment_ids"]]
    assert sorted(published) == sorted(assignment_ids)
    return captured


def test_no_spread_preserves_single_burst(monkeypatch: pytest.MonkeyPatch) -> None:
    base = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)
    calls = _publish(monkeypatch, count=125, batch_size=200, available_at=base.timestamp(), spread_over_hours=None)
    # 125 <= batch_size(200): a single batch, released at the base time.
    assert len(calls) == 1
    assert calls[0]["available_at"] == base


def test_spread_staggers_batches_within_window(monkeypatch: pytest.MonkeyPatch) -> None:
    base = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)
    window_hours = 4
    calls = _publish(
        monkeypatch,
        count=125,
        batch_size=200,
        available_at=base.timestamp(),
        spread_over_hours=window_hours,
    )
    # A 125-recipient audience that would be one burst is now several batches.
    assert len(calls) > 1
    times = [c["available_at"] for c in calls]
    # Strictly increasing release times, first at base, all within the window.
    assert times[0] == base
    assert times == sorted(times)
    assert len(set(times)) == len(times)
    window_end = base.timestamp() + window_hours * 3600
    assert all(t.timestamp() < window_end for t in times)


def test_spread_batch_size_never_exceeds_configured_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    # A large audience over a short window must not defeat the 1MiB payload
    # guarantee: batch size stays <= the configured cap, so more (smaller)
    # batches are produced rather than one oversized one.
    base = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)
    calls = _publish(monkeypatch, count=5000, batch_size=200, available_at=base.timestamp(), spread_over_hours=1)
    assert all(len(c["payload"]["recipient_assignment_ids"]) <= 200 for c in calls)


def test_spread_ignored_without_base_time(monkeypatch: pytest.MonkeyPatch) -> None:
    # No available_at (e.g. an immediate publish) means there is no window to
    # anchor the stagger to; fall back to the single default batch, unspread.
    calls = _publish(monkeypatch, count=125, batch_size=200, available_at=None, spread_over_hours=4)
    assert len(calls) == 1
    assert calls[0]["available_at"] is None


def test_spread_clamps_to_deliver_by_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    # H9 defect fix: a spread_over_hours longer than the time left before the
    # delivery deadline (canary-evidence TTL / schedule_end) must NOT stagger
    # batches past that deadline — late batches would trip the worker's launch
    # gate ("canary_evidence_expired") and strand QUEUED forever.
    base = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)
    deliver_by = base + timedelta(hours=6)  # only 6h left, but 48h requested
    calls = _publish(
        monkeypatch,
        count=125,
        batch_size=200,
        available_at=base.timestamp(),
        spread_over_hours=48,
        deliver_by=deliver_by,
    )
    times = [c["available_at"] for c in calls]
    assert len(calls) > 1
    # Every batch is released before the deadline — none can strand.
    assert all(t < deliver_by for t in times)
    # The window was actually compressed below the 48h request.
    assert (times[-1] - base) < timedelta(hours=48)


def test_spread_uses_full_window_when_deadline_is_ample(monkeypatch: pytest.MonkeyPatch) -> None:
    base = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)
    deliver_by = base + timedelta(hours=72)  # far beyond the 4h spread
    calls = _publish(
        monkeypatch,
        count=125,
        batch_size=200,
        available_at=base.timestamp(),
        spread_over_hours=4,
        deliver_by=deliver_by,
    )
    times = [c["available_at"] for c in calls]
    assert times[0] == base
    assert (times[-1] - base) < timedelta(hours=4)  # unchanged: fits in 4h
    assert all(t < deliver_by for t in times)


def test_spread_collapses_to_burst_when_deadline_imminent(monkeypatch: pytest.MonkeyPatch) -> None:
    # Deadline within the processing margin → window clamps to 0 → prompt burst
    # at base, which is still strictly before the deadline (safe, not stranded).
    base = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)
    deliver_by = base + timedelta(seconds=60)
    calls = _publish(
        monkeypatch,
        count=125,
        batch_size=200,
        available_at=base.timestamp(),
        spread_over_hours=24,
        deliver_by=deliver_by,
    )
    times = [c["available_at"] for c in calls]
    assert all(t == base for t in times)
    assert all(t < deliver_by for t in times)
