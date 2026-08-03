"""Unit tests for the Redis job queue.

The publish/pop round-trip requires a live Redis (`docker compose up -d redis`)
and is skipped when it is unreachable. The idle-poll timeout behavior is tested
without any Redis by faking the client, so the unit suite stays runnable
anywhere.
"""

from __future__ import annotations

import redis
from kp_contracts.queue import JobQueue


class _FakeClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def blpop(self, key: str, timeout: int) -> object:
        self.calls.append((key, {"timeout": timeout}))
        raise redis.TimeoutError("Timeout reading from socket")

    def close(self) -> None:
        return None


def test_pop_treats_redis_blocking_timeout_as_idle() -> None:
    """Regression: redis-py raises TimeoutError when the blpop block deadline
    elapses on an empty queue; that is an idle poll, not an error."""
    queue = JobQueue("redis://localhost:6379/0")
    queue._client = _FakeClient()  # noqa: SLF001 - test seam
    assert queue.pop("deliver", timeout=3) is None
    assert queue._client.calls == [("kp:queue:deliver", {"timeout": 3})]  # noqa: SLF001
    queue.close()
