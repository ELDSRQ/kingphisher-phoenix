"""In-memory sliding-window rate limiters.

Single-process dev/operator deployment, so an in-process limiter is adequate
and stays testable without Redis. The window is keyed by the caller's identity
(client IP or principal subject id). Shared across the operator API and the
tracking API (HIGH-04 / HIGH-10).
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque


class RateLimiter:
    def __init__(self, *, limit: int, window_seconds: float = 60.0, max_keys: int = 10_000) -> None:
        if limit < 1 or window_seconds <= 0 or max_keys < 1:
            raise ValueError("limit, window_seconds, and max_keys must be positive")
        self._limit = limit
        self._window = window_seconds
        self._max_keys = max_keys
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = threading.Lock()

    def _evict(self, cutoff: float) -> None:
        while self._hits:
            _, hits = next(iter(self._hits.items()))
            if hits and hits[-1] >= cutoff:
                break
            self._hits.popitem(last=False)

        # If all keys are active, discard the least recently used key. This
        # keeps attacker-controlled cardinality bounded at a deterministic
        # memory cost while preserving limits for the most recent callers.
        while len(self._hits) >= self._max_keys:
            self._hits.popitem(last=False)

    def allow(self, key: str, *, now: float | None = None) -> bool:
        now = now if now is not None else time.monotonic()
        cutoff = now - self._window
        with self._lock:
            hits = self._hits.get(key)
            if hits is None:
                self._evict(cutoff)
                self._hits[key] = deque([now])
                return True
            while hits and hits[0] < cutoff:
                hits.popleft()
            if len(hits) >= self._limit:
                return False
            hits.append(now)
            self._hits.move_to_end(key)
            return True

    @property
    def key_count(self) -> int:
        """Current allocation count, exposed for metrics and verification."""
        with self._lock:
            return len(self._hits)

    def clear(self) -> None:
        with self._lock:
            self._hits.clear()


class LoginThrottle:
    """Per-IP failed-login throttle with a lockout window.

    After `max_failures` failed attempts within `window_seconds`, the key is
    locked for `lockout_seconds`. A successful login resets the counter.
    """

    def __init__(self, *, max_failures: int = 5, window_seconds: float = 900.0, lockout_seconds: float = 900.0) -> None:
        self._max_failures = max_failures
        self._window = window_seconds
        self._lockout = lockout_seconds
        self._failures: dict[str, list[float]] = {}
        self._locked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def _now(self) -> float:
        return time.monotonic()

    def locked(self, key: str) -> bool:
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
        now = self._now()
        cutoff = now - self._window
        with self._lock:
            hits = [t for t in self._failures.get(key, []) if t >= cutoff]
            hits.append(now)
            self._failures[key] = hits
            if len(hits) >= self._max_failures:
                self._locked_until[key] = now + self._lockout
                self._failures.pop(key, None)

    def record_success(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)
            self._locked_until.pop(key, None)
