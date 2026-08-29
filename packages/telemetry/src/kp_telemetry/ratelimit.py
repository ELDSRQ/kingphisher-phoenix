"""Bounded local and atomic Redis-backed abuse controls.

Development uses small in-process structures with no infrastructure
dependency. Managed deployments pass a Redis URL, which makes counters shared
across replicas and persistent across process restarts. Redis failures deny
new work rather than silently falling back to replica-local state.
"""

from __future__ import annotations

import hashlib
import logging
import math
import threading
import time
from collections import OrderedDict, deque
from typing import Any

logger = logging.getLogger(__name__)


def _log_backend_failure(event: str, exc: Exception) -> None:
    """Log a bounded backend-failure signal without exception content or context."""
    logger.error("%s exception_type=%s", event, type(exc).__name__[:128])


_RATE_LIMIT_SCRIPT = """-- kp_rate_limit_fixed_window_v1
local count = redis.call('INCR', KEYS[1])
if count == 1 then
    redis.call('PEXPIRE', KEYS[1], ARGV[2])
end
if count > tonumber(ARGV[1]) then
    return 0
end
return 1
"""

_LOGIN_FAILURE_SCRIPT = """-- kp_login_failure_v1
local count = redis.call('INCR', KEYS[1])
if count == 1 then
    redis.call('PEXPIRE', KEYS[1], ARGV[2])
end
if count >= tonumber(ARGV[1]) then
    redis.call('SET', KEYS[2], '1', 'PX', ARGV[3])
    redis.call('DEL', KEYS[1])
    return 1
end
return 0
"""

_LOGIN_SUCCESS_SCRIPT = """-- kp_login_success_v1
redis.call('DEL', KEYS[1], KEYS[2])
return 1
"""


def _redis_client(redis_url: str) -> Any:
    # Redis is an existing managed-app dependency, but it stays lazy so the
    # telemetry package's memory-only development use needs no Redis install.
    from redis import Redis

    return Redis.from_url(
        redis_url,
        decode_responses=True,
        socket_connect_timeout=1.0,
        socket_timeout=1.0,
    )


def _milliseconds(seconds: float) -> int:
    return max(1, math.ceil(seconds * 1000))


def _identity_digest(namespace: str, key: str) -> str:
    # Tokens, user IDs, and IP addresses must not be exposed as Redis key names.
    return hashlib.sha256(f"{namespace}\0{key}".encode()).hexdigest()


class RateLimiter:
    """Rate limiter with a memory backend by default and Redis when configured.

    The Redis backend uses one atomic fixed-window script per attempt. Keys are
    SHA-256 identifiers and Redis hash tags keep each operation cluster-safe.
    ``allow`` deliberately returns ``False`` on any backend error.
    """

    def __init__(
        self,
        *,
        limit: int,
        window_seconds: float = 60.0,
        max_keys: int = 10_000,
        redis_url: str | None = None,
        namespace: str = "default",
        redis_client: Any | None = None,
    ) -> None:
        if limit < 1 or window_seconds <= 0 or max_keys < 1:
            raise ValueError("limit, window_seconds, and max_keys must be positive")
        if not namespace:
            raise ValueError("namespace must not be empty")
        self._limit = limit
        self._window = window_seconds
        self._max_keys = max_keys
        self._namespace = namespace
        self._owns_redis = redis_client is None and redis_url is not None
        self._redis = redis_client if redis_client is not None else (_redis_client(redis_url) if redis_url else None)
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = threading.Lock()

    @property
    def distributed(self) -> bool:
        return self._redis is not None

    def _redis_key(self, key: str) -> str:
        digest = _identity_digest(self._namespace, key)
        return f"kp:ratelimit:{{{digest}}}"

    def _evict(self, cutoff: float) -> None:
        while self._hits:
            _, hits = next(iter(self._hits.items()))
            if hits and hits[-1] >= cutoff:
                break
            self._hits.popitem(last=False)

        # If all keys are active, discard the least recently used key. This
        # bounds attacker-controlled cardinality in development.
        while len(self._hits) >= self._max_keys:
            self._hits.popitem(last=False)

    def allow(self, key: str, *, now: float | None = None) -> bool:
        if self._redis is not None:
            try:
                result = self._redis.eval(
                    _RATE_LIMIT_SCRIPT,
                    1,
                    self._redis_key(key),
                    self._limit,
                    _milliseconds(self._window),
                )
                return int(result) == 1
            except Exception as exc:
                _log_backend_failure("distributed_rate_limiter_unavailable", exc)
                return False

        current = now if now is not None else time.monotonic()
        cutoff = current - self._window
        with self._lock:
            hits = self._hits.get(key)
            if hits is None:
                self._evict(cutoff)
                self._hits[key] = deque([current])
                return True
            while hits and hits[0] < cutoff:
                hits.popleft()
            if len(hits) >= self._limit:
                return False
            hits.append(current)
            self._hits.move_to_end(key)
            return True

    @property
    def key_count(self) -> int:
        """Local allocation count; distributed cardinality is intentionally not scanned."""
        if self._redis is not None:
            return 0
        with self._lock:
            return len(self._hits)

    def clear(self) -> None:
        """Clear local test/development state.

        Distributed state expires automatically. Bulk-scanning Redis from an
        application request would be an unsafe production operation.
        """
        if self._redis is not None:
            return
        with self._lock:
            self._hits.clear()

    def ready(self) -> bool:
        if self._redis is None:
            return True
        try:
            return bool(self._redis.ping())
        except Exception:
            return False

    def close(self) -> None:
        """Close only a Redis client constructed by this limiter."""
        if self._owns_redis and self._redis is not None:
            close = getattr(self._redis, "close", None)
            if callable(close):
                close()


class LoginThrottle:
    """Per-IP failed-login throttle with local or shared Redis state."""

    def __init__(
        self,
        *,
        max_failures: int = 5,
        window_seconds: float = 900.0,
        lockout_seconds: float = 900.0,
        redis_url: str | None = None,
        namespace: str = "operator-login",
        redis_client: Any | None = None,
    ) -> None:
        if max_failures < 1 or window_seconds <= 0 or lockout_seconds <= 0:
            raise ValueError("max_failures, window_seconds, and lockout_seconds must be positive")
        if not namespace:
            raise ValueError("namespace must not be empty")
        self._max_failures = max_failures
        self._window = window_seconds
        self._lockout = lockout_seconds
        self._namespace = namespace
        self._owns_redis = redis_client is None and redis_url is not None
        self._redis = redis_client if redis_client is not None else (_redis_client(redis_url) if redis_url else None)
        self._failures: dict[str, list[float]] = {}
        self._locked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    @property
    def distributed(self) -> bool:
        return self._redis is not None

    def _redis_keys(self, key: str) -> tuple[str, str]:
        digest = _identity_digest(self._namespace, key)
        prefix = f"kp:login:{{{digest}}}"
        return f"{prefix}:failures", f"{prefix}:locked"

    def _now(self) -> float:
        return time.monotonic()

    def locked(self, key: str) -> bool:
        if self._redis is not None:
            _, lock_key = self._redis_keys(key)
            try:
                return bool(self._redis.exists(lock_key))
            except Exception as exc:
                _log_backend_failure("distributed_login_throttle_lock_check_unavailable", exc)
                return True

        now = self._now()
        with self._lock:
            until = self._locked_until.get(key)
            if until is None:
                return False
            if now >= until:
                del self._locked_until[key]
                return False
            return True

    def record_failure(self, key: str) -> None:
        if self._redis is not None:
            failure_key, lock_key = self._redis_keys(key)
            try:
                self._redis.eval(
                    _LOGIN_FAILURE_SCRIPT,
                    2,
                    failure_key,
                    lock_key,
                    self._max_failures,
                    _milliseconds(self._window),
                    _milliseconds(self._lockout),
                )
            except Exception as exc:
                _log_backend_failure("distributed_login_throttle_record_failure_unavailable", exc)
            return

        now = self._now()
        cutoff = now - self._window
        with self._lock:
            hits = [timestamp for timestamp in self._failures.get(key, []) if timestamp >= cutoff]
            hits.append(now)
            self._failures[key] = hits
            if len(hits) >= self._max_failures:
                self._locked_until[key] = now + self._lockout
                self._failures.pop(key, None)

    def record_success(self, key: str) -> None:
        if self._redis is not None:
            failure_key, lock_key = self._redis_keys(key)
            try:
                self._redis.eval(_LOGIN_SUCCESS_SCRIPT, 2, failure_key, lock_key)
            except Exception as exc:
                _log_backend_failure("distributed_login_throttle_record_success_unavailable", exc)
            return

        with self._lock:
            self._failures.pop(key, None)
            self._locked_until.pop(key, None)

    def ready(self) -> bool:
        if self._redis is None:
            return True
        try:
            return bool(self._redis.ping())
        except Exception:
            return False

    def close(self) -> None:
        """Close only a Redis client constructed by this throttle."""
        if self._owns_redis and self._redis is not None:
            close = getattr(self._redis, "close", None)
            if callable(close):
                close()
