"""Managed operator abuse controls use shared fail-closed Redis state."""

from __future__ import annotations

import kp_operator_api.main as main_module
import pytest
from fastapi.testclient import TestClient
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.main import create_app

KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"


class _SharedRedis:
    def __init__(self, *, available: bool = True) -> None:
        self.available = available
        self.counts: dict[str, int] = {}

    def eval(self, script: str, numkeys: int, *args: object) -> int:
        if not self.available:
            raise ConnectionError("unavailable")
        key = str(args[0])
        if "kp_rate_limit_fixed_window_v1" in script:
            self.counts[key] = self.counts.get(key, 0) + 1
            return int(self.counts[key] <= int(args[numkeys]))
        raise AssertionError("unexpected script")

    def ping(self) -> bool:
        if not self.available:
            raise ConnectionError("unavailable")
        return True


def _settings(tmp_path, **overrides: object) -> OperatorApiSettings:
    values: dict[str, object] = {
        "audit_hmac_key": HMAC,
        "ciphertext_kek": KEK,
        "console_jwt_secret": CONSOLE_JWT,
        "env_file": str(tmp_path / ".env"),
        "console_static_dir": "/nonexistent-console-dir",
        "redis_url": "rediss://redis.example:10000/0",
    }
    values.update(overrides)
    return OperatorApiSettings(**values)  # type: ignore[arg-type]


def test_managed_operator_instances_share_limits_across_restart(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    shared = _SharedRedis()
    monkeypatch.setenv("OPERATOR_API_RATE_LIMIT_BACKEND", "redis")
    monkeypatch.setattr("kp_telemetry.ratelimit._redis_client", lambda _url: shared)
    settings = _settings(tmp_path, config_store="managed", rate_limit_user_per_min=2)

    first = create_app(settings)
    second = create_app(settings)
    assert first.state.user_limiter.allow("operator-1") is True
    assert second.state.user_limiter.allow("operator-1") is True
    assert first.state.user_limiter.allow("operator-1") is False

    restarted = create_app(settings)
    assert restarted.state.user_limiter.allow("operator-1") is False
    assert restarted.state.user_limiter.distributed is True
    assert restarted.state.login_throttle.distributed is True


def test_local_operator_keeps_in_memory_limiter(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPERATOR_API_RATE_LIMIT_BACKEND", raising=False)
    app = create_app(_settings(tmp_path, config_store="env_file"))

    assert app.state.user_limiter.distributed is False
    assert app.state.ip_limiter.distributed is False
    assert app.state.login_throttle.distributed is False


def test_managed_operator_readiness_fails_when_shared_limiter_is_unavailable(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shared = _SharedRedis(available=False)
    monkeypatch.setenv("OPERATOR_API_RATE_LIMIT_BACKEND", "redis")
    monkeypatch.setattr("kp_telemetry.ratelimit._redis_client", lambda _url: shared)
    monkeypatch.setattr(main_module, "_database_is_ready", lambda _engine: True)
    monkeypatch.setattr(main_module, "_queue_is_ready", lambda _queue: True)
    app = create_app(_settings(tmp_path, config_store="managed"))
    app.state.audit_verifier.status = "ok"

    response = TestClient(app).get("/readyz")

    assert response.status_code == 503
    assert response.json() == {"status": "not_ready"}


def test_operator_ip_limit_ignores_untrusted_forwarding_headers(tmp_path) -> None:
    app = create_app(_settings(tmp_path, rate_limit_ip_per_min=1))

    @app.get("/rate-limit-probe")
    def probe() -> dict[str, bool]:
        return {"ok": True}

    client = TestClient(app)
    first = client.get("/rate-limit-probe", headers={"X-Forwarded-For": "198.51.100.1"})
    second = client.get("/rate-limit-probe", headers={"X-Forwarded-For": "198.51.100.2"})

    assert first.status_code == 200
    assert second.status_code == 429
