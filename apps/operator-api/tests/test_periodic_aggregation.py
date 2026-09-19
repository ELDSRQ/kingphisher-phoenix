"""Periodic unattended aggregation (B2): bounded, fail-closed, never promotes."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import cast

import pytest
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.console.aggregation_routes import AggregationScheduler


def _settings(url: str = "http://127.0.0.1:8090") -> OperatorApiSettings:
    # The scheduler only reads ai_gateway_url / ai_aggregate_timeout_seconds.
    return cast(
        OperatorApiSettings,
        SimpleNamespace(ai_gateway_url=url, ai_aggregate_timeout_seconds=300),
    )


def _session_factory():
    """A callable whose returned sessions are inert context managers."""

    class _Session:
        def __enter__(self):
            return object()

        def __exit__(self, *args: object) -> bool:
            return False

    return _Session()


def test_disabled_scheduler_run_returns_immediately() -> None:
    scheduler = AggregationScheduler(
        _settings(), _session_factory, enabled=False, interval_seconds=1.0, max_items=50, max_candidates=5
    )
    assert scheduler.status == "disabled"
    # run() is a no-op when disabled — no loop, no pass.
    assert asyncio.run(scheduler.run()) is None


def test_no_gateway_url_skips_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    scheduler = AggregationScheduler(
        _settings(""), _session_factory, enabled=True, interval_seconds=1.0, max_items=50, max_candidates=5
    )
    called: dict[str, bool] = {}
    monkeypatch.setattr(
        "kp_operator_api.console.aggregation_routes._execute_run", lambda *a, **k: called.update(execute=True)
    )
    scheduler._run_once_blocking()
    assert called.get("execute") is not True


def test_no_items_skips_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    scheduler = AggregationScheduler(
        _settings(), _session_factory, enabled=True, interval_seconds=1.0, max_items=50, max_candidates=5
    )
    monkeypatch.setattr("kp_operator_api.console.aggregation_routes._load_governed_items", lambda *a, **k: [])
    called: dict[str, bool] = {}
    monkeypatch.setattr(
        "kp_operator_api.console.aggregation_routes._execute_run", lambda *a, **k: called.update(execute=True)
    )
    scheduler._run_once_blocking()
    assert called.get("execute") is not True


def test_items_trigger_execute_run(monkeypatch: pytest.MonkeyPatch) -> None:
    items = [{"item_id": "x"}]
    scheduler = AggregationScheduler(
        _settings(), _session_factory, enabled=True, interval_seconds=1.0, max_items=50, max_candidates=5
    )
    monkeypatch.setattr("kp_operator_api.console.aggregation_routes._load_governed_items", lambda *a, **k: items)
    calls: list[tuple] = []
    monkeypatch.setattr("kp_operator_api.console.aggregation_routes._execute_run", lambda *a, **k: calls.append(a))
    scheduler._run_once_blocking()
    assert len(calls) == 1
    # _execute_run(settings, session_factory, run_id, items, max_candidates)
    assert calls[0][3] == items
    assert calls[0][4] == 5


def test_item_load_failure_is_swallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    scheduler = AggregationScheduler(
        _settings(), _session_factory, enabled=True, interval_seconds=1.0, max_items=50, max_candidates=5
    )

    def boom(*args: object, **kwargs: object) -> list:
        raise RuntimeError("database unavailable")

    monkeypatch.setattr("kp_operator_api.console.aggregation_routes._load_governed_items", boom)
    scheduler._run_once_blocking()  # must not raise


def test_interval_is_clamped_non_negative() -> None:
    scheduler = AggregationScheduler(
        _settings(), _session_factory, enabled=True, interval_seconds=-5.0, max_items=50, max_candidates=5
    )
    assert scheduler._interval_seconds == 0.0


def test_scheduler_never_promotes() -> None:
    # The scheduler's only side effect is `_execute_run` (insert PENDING
    # candidates). Promotion is a separate operator-authenticated route; the
    # scheduler structurally cannot reach it.
    assert not hasattr(AggregationScheduler, "promote")
