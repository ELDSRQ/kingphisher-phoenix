"""Memory-safety tests for the in-process rate limiter."""

from __future__ import annotations

import pytest
from kp_telemetry.ratelimit import RateLimiter


def test_high_cardinality_is_globally_bounded() -> None:
    limiter = RateLimiter(limit=2, window_seconds=60, max_keys=25)
    for index in range(10_000):
        assert limiter.allow(f"attacker-{index}", now=float(index) / 1000)
    assert limiter.key_count == 25


def test_idle_keys_are_evicted_after_window() -> None:
    limiter = RateLimiter(limit=1, window_seconds=10, max_keys=10)
    assert limiter.allow("old", now=1)
    assert limiter.allow("new", now=12)
    assert limiter.key_count == 1
    assert limiter.allow("old", now=12)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"limit": 0},
        {"limit": 1, "window_seconds": 0},
        {"limit": 1, "max_keys": 0},
    ],
)
def test_invalid_configuration_rejected(kwargs: dict[str, int]) -> None:
    with pytest.raises(ValueError):
        RateLimiter(**kwargs)
