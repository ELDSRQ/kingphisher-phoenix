"""Memory-safety tests for the in-process rate limiter."""

from __future__ import annotations

import contextlib
import logging
import os
import uuid

import kp_telemetry.ratelimit as ratelimit_module
import pytest
import redis
from kp_telemetry.ratelimit import LoginThrottle, RateLimiter


class _SharedRedis:
    """Small script-aware fake; state is shared by every simulated replica."""

    def __init__(self) -> None:
        self.values: dict[str, int] = {}
        self.last_keys: list[str] = []
        self.close_calls = 0

    def eval(self, script: str, numkeys: int, *args: object) -> int:
        keys = [str(value) for value in args[:numkeys]]
        argv = args[numkeys:]
        self.last_keys = keys
        if "kp_rate_limit_fixed_window_v1" in script:
            key = keys[0]
            self.values[key] = self.values.get(key, 0) + 1
            return int(self.values[key] <= int(argv[0]))
        if "kp_login_failure_v1" in script:
            failure_key, lock_key = keys
            self.values[failure_key] = self.values.get(failure_key, 0) + 1
            if self.values[failure_key] >= int(argv[0]):
                self.values[lock_key] = 1
                self.values.pop(failure_key, None)
                return 1
            return 0
        if "kp_login_success_v1" in script:
            for key in keys:
                self.values.pop(key, None)
            return 1
        raise AssertionError("unexpected Redis script")

    def exists(self, key: str) -> int:
        return int(key in self.values)

    def ping(self) -> bool:
        return True

    def close(self) -> None:
        self.close_calls += 1


class _BrokenRedis:
    def eval(self, *_args: object) -> int:
        raise ConnectionError("unavailable")

    def exists(self, _key: str) -> int:
        raise ConnectionError("unavailable")

    def ping(self) -> bool:
        raise ConnectionError("unavailable")


class RedisSecretFailure(ConnectionError):
    pass


class _SecretBearingRedis:
    @staticmethod
    def _fail() -> None:
        raise RedisSecretFailure(
            "password=must-not-log rediss://user:secret@redis/0 key=kp:private identity=alice@example.com"
        )

    def eval(self, *_args: object) -> int:
        self._fail()

    def exists(self, _key: str) -> int:
        self._fail()


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


def test_distributed_limits_are_shared_across_instances_and_survive_restart() -> None:
    shared = _SharedRedis()
    first_replica = RateLimiter(limit=2, redis_client=shared, namespace="tracking-ip")
    second_replica = RateLimiter(limit=2, redis_client=shared, namespace="tracking-ip")

    assert first_replica.allow("198.51.100.10") is True
    assert second_replica.allow("198.51.100.10") is True
    assert first_replica.allow("198.51.100.10") is False

    restarted_replica = RateLimiter(limit=2, redis_client=shared, namespace="tracking-ip")
    assert restarted_replica.allow("198.51.100.10") is False
    assert restarted_replica.distributed is True
    assert "198.51.100.10" not in shared.last_keys[0]


def test_distributed_namespaces_do_not_share_buckets() -> None:
    shared = _SharedRedis()
    ip_limiter = RateLimiter(limit=1, redis_client=shared, namespace="tracking-ip")
    token_limiter = RateLimiter(limit=1, redis_client=shared, namespace="tracking-token")

    assert ip_limiter.allow("same-input") is True
    assert token_limiter.allow("same-input") is True
    assert ip_limiter.allow("same-input") is False
    assert token_limiter.allow("same-input") is False


def test_distributed_rate_limiter_fails_closed_when_redis_is_unavailable() -> None:
    limiter = RateLimiter(limit=10, redis_client=_BrokenRedis(), namespace="operator-ip")

    assert limiter.allow("203.0.113.1") is False
    assert limiter.ready() is False


def test_distributed_login_lockout_is_shared_and_survives_restart() -> None:
    shared = _SharedRedis()
    first_replica = LoginThrottle(max_failures=2, redis_client=shared)
    second_replica = LoginThrottle(max_failures=2, redis_client=shared)

    first_replica.record_failure("203.0.113.2")
    assert second_replica.locked("203.0.113.2") is False
    second_replica.record_failure("203.0.113.2")

    restarted_replica = LoginThrottle(max_failures=2, redis_client=shared)
    assert restarted_replica.locked("203.0.113.2") is True
    restarted_replica.record_success("203.0.113.2")
    assert first_replica.locked("203.0.113.2") is False


def test_distributed_login_throttle_fails_closed_when_redis_is_unavailable() -> None:
    throttle = LoginThrottle(redis_client=_BrokenRedis())

    assert throttle.locked("203.0.113.3") is True
    assert throttle.ready() is False


@pytest.mark.parametrize(
    ("operation", "expected_event"),
    [
        ("rate_allow", "distributed_rate_limiter_unavailable"),
        ("login_locked", "distributed_login_throttle_lock_check_unavailable"),
        ("login_failure", "distributed_login_throttle_record_failure_unavailable"),
        ("login_success", "distributed_login_throttle_record_success_unavailable"),
    ],
)
def test_distributed_failure_logs_are_bounded_across_formatters(
    operation: str,
    expected_event: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    backend = _SecretBearingRedis()
    caplog.set_level(logging.ERROR, logger=ratelimit_module.__name__)

    if operation == "rate_allow":
        assert RateLimiter(limit=1, redis_client=backend).allow("private-rate-identity") is False
    else:
        throttle = LoginThrottle(redis_client=backend)
        if operation == "login_locked":
            assert throttle.locked("private-login-identity") is True
        elif operation == "login_failure":
            assert throttle.record_failure("private-login-identity") is None
        else:
            assert throttle.record_success("private-login-identity") is None

    assert len(caplog.records) == 1
    record = caplog.records[0]
    assert record.getMessage() == f"{expected_event} exception_type=RedisSecretFailure"
    assert record.exc_info is None
    rendered = [
        logging.Formatter("%(message)s").format(record),
        logging.Formatter("%(levelname)s %(name)s %(message)s").format(record),
    ]
    for output in rendered:
        assert expected_event in output
        assert "RedisSecretFailure" in output
        assert "password=must-not-log" not in output
        assert "rediss://" not in output
        assert "kp:private" not in output
        assert "private-login-identity" not in output
        assert "private-rate-identity" not in output
        assert "alice@example.com" not in output
        assert "Traceback" not in output


def test_redis_resource_ownership_closes_only_factory_created_clients(monkeypatch: pytest.MonkeyPatch) -> None:
    owned = _SharedRedis()
    monkeypatch.setattr(ratelimit_module, "_redis_client", lambda _url: owned)
    RateLimiter(limit=1, redis_url="rediss://redis.example/0").close()
    LoginThrottle(redis_url="rediss://redis.example/0").close()
    assert owned.close_calls == 2

    external = _SharedRedis()
    RateLimiter(limit=1, redis_client=external).close()
    LoginThrottle(redis_client=external).close()
    assert external.close_calls == 0


@pytest.mark.contract
@pytest.mark.redis
def test_live_redis_shares_rate_and_login_state_across_replicas_and_restarts() -> None:
    """Exercise the real Lua scripts, not only the script-aware unit-test fake."""
    redis_url = os.getenv("REDIS_URL")
    if not redis_url:
        pytest.skip("REDIS_URL is not configured")

    namespace = f"live-{uuid.uuid4()}"
    rate_identity = "198.51.100.20"
    login_identity = "203.0.113.20"
    first_rate = RateLimiter(limit=2, window_seconds=60, redis_url=redis_url, namespace=f"{namespace}-rate")
    second_rate = RateLimiter(limit=2, window_seconds=60, redis_url=redis_url, namespace=f"{namespace}-rate")
    first_login = LoginThrottle(
        max_failures=2,
        window_seconds=60,
        lockout_seconds=60,
        redis_url=redis_url,
        namespace=f"{namespace}-login",
    )
    second_login = LoginThrottle(
        max_failures=2,
        window_seconds=60,
        lockout_seconds=60,
        redis_url=redis_url,
        namespace=f"{namespace}-login",
    )
    rate_key = first_rate._redis_key(rate_identity)
    login_keys = first_login._redis_keys(login_identity)

    try:
        try:
            assert first_rate.ready() is True
            assert first_login.ready() is True
        except redis.RedisError as exc:
            pytest.skip(f"Redis is unreachable: {type(exc).__name__}")

        assert first_rate.allow(rate_identity) is True
        assert second_rate.allow(rate_identity) is True
        assert first_rate.allow(rate_identity) is False

        restarted_rate = RateLimiter(
            limit=2,
            window_seconds=60,
            redis_url=redis_url,
            namespace=f"{namespace}-rate",
        )
        try:
            assert restarted_rate.allow(rate_identity) is False
        finally:
            restarted_rate.close()

        first_login.record_failure(login_identity)
        assert second_login.locked(login_identity) is False
        second_login.record_failure(login_identity)
        assert first_login.locked(login_identity) is True

        restarted_login = LoginThrottle(
            max_failures=2,
            window_seconds=60,
            lockout_seconds=60,
            redis_url=redis_url,
            namespace=f"{namespace}-login",
        )
        try:
            assert restarted_login.locked(login_identity) is True
            restarted_login.record_success(login_identity)
        finally:
            restarted_login.close()
        assert first_login.locked(login_identity) is False
    finally:
        client = first_rate._redis
        if client is not None:
            with contextlib.suppress(redis.RedisError):
                client.delete(rate_key, *login_keys)
        first_rate.close()
        second_rate.close()
        first_login.close()
        second_login.close()
