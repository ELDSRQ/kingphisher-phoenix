"""Managed tracking replicas share fail-closed Redis abuse controls."""

from __future__ import annotations

import kp_tracking_api.main as main_module
import pytest
from fastapi.testclient import TestClient
from kp_tracking_api.config import TrackingApiSettings
from kp_tracking_api.main import create_app


class _SharedRedis:
    def __init__(self, *, available: bool = True) -> None:
        self.available = available
        self.counts: dict[str, int] = {}

    def eval(self, script: str, numkeys: int, *args: object) -> int:
        if not self.available:
            raise ConnectionError("unavailable")
        if "kp_rate_limit_fixed_window_v1" not in script:
            raise AssertionError("unexpected script")
        key = str(args[0])
        self.counts[key] = self.counts.get(key, 0) + 1
        return int(self.counts[key] <= int(args[numkeys]))

    def ping(self) -> bool:
        if not self.available:
            raise ConnectionError("unavailable")
        return True


def _settings(**overrides: object) -> TrackingApiSettings:
    values: dict[str, object] = {
        "tracking_token_hmac_key": (b"k" * 32).hex(),
        "rate_limit_backend": "redis",
        "redis_url": "rediss://redis.example:10000/0",
    }
    values.update(overrides)
    return TrackingApiSettings(**values)  # type: ignore[arg-type]


def test_managed_tracking_instances_share_limits_across_restart(monkeypatch: pytest.MonkeyPatch) -> None:
    shared = _SharedRedis()
    monkeypatch.setattr("kp_telemetry.ratelimit._redis_client", lambda _url: shared)
    settings = _settings(rate_limit_ip_per_min=2)

    first = create_app(settings)
    second = create_app(settings)
    assert first.state.ip_limiter.allow("198.51.100.5") is True
    assert second.state.ip_limiter.allow("198.51.100.5") is True
    assert first.state.ip_limiter.allow("198.51.100.5") is False

    restarted = create_app(settings)
    assert restarted.state.ip_limiter.allow("198.51.100.5") is False
    assert restarted.state.ip_limiter.distributed is True
    assert restarted.state.token_limiter.distributed is True
    assert restarted.state.global_limiter.distributed is True


def test_tracking_memory_backend_remains_the_development_default() -> None:
    app = create_app(TrackingApiSettings(tracking_token_hmac_key=(b"k" * 32).hex()))

    assert app.state.ip_limiter.distributed is False
    assert app.state.token_limiter.distributed is False
    assert app.state.global_limiter.distributed is False


def test_tracking_redis_backend_requires_a_connection_url() -> None:
    with pytest.raises(ValueError, match="TRACKING_API_REDIS_URL"):
        TrackingApiSettings(rate_limit_backend="redis", redis_url="")


def test_tracking_readiness_fails_when_shared_limiter_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    shared = _SharedRedis(available=False)
    monkeypatch.setattr("kp_telemetry.ratelimit._redis_client", lambda _url: shared)
    monkeypatch.setattr(main_module, "_database_is_ready", lambda _engine: True)
    app = create_app(_settings())

    response = TestClient(app).get("/readyz")

    assert response.status_code == 503
    assert response.json() == {"status": "not_ready"}
