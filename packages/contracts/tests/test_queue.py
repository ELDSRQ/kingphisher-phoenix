"""Unit tests for the Redis job queue.

The publish/pop round-trip requires a live Redis (`docker compose up -d redis`)
and is skipped when it is unreachable. The at-least-once mechanics (claim,
ack, reject/DLQ, stale recovery) are tested without any Redis by faking the
client, so the unit suite stays runnable anywhere.
"""

from __future__ import annotations

import json

import pytest
import redis
from kp_contracts.queue import JobQueue


class _MemoryClient:
    """Tiny in-memory Redis list stand-in for the queue primitives."""

    def __init__(self) -> None:
        self.lists: dict[str, list[str]] = {}
        self.timeout_error = False

    def rpush(self, key: str, value: str) -> int:
        self.lists.setdefault(key, []).append(value)
        return len(self.lists[key])

    def lpush(self, key: str, value: str) -> int:
        self.lists.setdefault(key, []).insert(0, value)
        return len(self.lists[key])

    def blpop(self, key: str, timeout: int) -> object:
        if self.timeout_error:
            raise redis.TimeoutError("Timeout reading from socket")
        return (key, self.lpop(key))

    def brpoplpush(self, src: str, dst: str, timeout: int) -> object:
        if self.timeout_error:
            raise redis.TimeoutError("Timeout reading from socket")
        values = self.lists.get(src)
        if not values:
            return None
        item = values.pop(0)
        self.lpush(dst, item)
        return item

    def lpop(self, key: str) -> str:
        values = self.lists.get(key)
        if not values:
            raise KeyError(key)
        return values.pop(0)

    def lrem(self, key: str, count: int, value: str) -> int:
        values = self.lists.get(key, [])
        removed = 0
        keep: list[str] = []
        for item in values:
            if item == value and (count == 0 or removed < count):
                removed += 1
            else:
                keep.append(item)
        self.lists[key] = keep
        return removed

    def lrange(self, key: str, start: int, stop: int) -> list[str]:
        values = self.lists.get(key, [])
        return values[start:] if stop == -1 else values[start : stop + 1]

    def close(self) -> None:
        return None


@pytest.fixture
def queue() -> JobQueue:
    q = JobQueue("redis://localhost:6379/0")
    q._client = _MemoryClient()  # noqa: SLF001 - test seam
    yield q
    q.close()


def test_pop_treats_redis_blocking_timeout_as_idle(queue: JobQueue) -> None:
    queue._client.timeout_error = True  # type: ignore[attr-defined]  # noqa: SLF001
    assert queue.pop("deliver", timeout=3) is None


def test_pop_claims_message_atomically(queue: JobQueue) -> None:
    queue.publish("deliver", {"campaign_id": "c1"}, idempotency_key="k1")
    message = queue.pop("deliver", timeout=1)
    assert message is not None
    assert message["payload"] == {"campaign_id": "c1"}
    assert message["idempotency_key"] == "k1"
    assert "started_at" in message
    # message moved out of the queue into :processing
    client = queue._client  # type: ignore[attr-defined]
    assert client.lists.get("kp:queue:deliver") == []
    assert len(client.lists.get("kp:queue:deliver:processing", [])) == 1


def test_ack_removes_from_processing(queue: JobQueue) -> None:
    queue.publish("deliver", {"n": 1})
    message = queue.pop("deliver", timeout=1)
    assert message is not None
    queue.ack("deliver", message)
    client = queue._client  # type: ignore[attr-defined]
    assert client.lists.get("kp:queue:deliver:processing") == []


def test_reject_requeues_then_moves_to_dlq_after_max_retries(queue: JobQueue) -> None:
    queue.publish("deliver", {"n": 1})
    for attempt in range(1, 4):
        message = queue.pop("deliver", timeout=1)
        assert message is not None, f"message lost before attempt {attempt}"
        queue.reject("deliver", message, max_retries=3)
    client = queue._client  # type: ignore[attr-defined]
    assert client.lists.get("kp:queue:deliver", []) == []
    dlq = client.lists.get("kp:queue:dlq:deliver", [])
    assert len(dlq) == 1
    assert json.loads(dlq[0])["retry"] == 3


def test_recover_stale_requeues_crashed_claim(queue: JobQueue) -> None:
    queue.publish("generation", {"pattern_id": "p1"})
    message = queue.pop("generation", timeout=1)
    assert message is not None
    # simulate a crash: the claim stays in :processing with an old started_at
    message["started_at"] = 0.0
    client = queue._client  # type: ignore[attr-defined]
    old_raw = message["_raw"]
    client.lrem("kp:queue:generation:processing", 0, old_raw)
    client.rpush("kp:queue:generation:processing", json.dumps(message))

    recovered = queue.recover_stale("generation", visibility_seconds=60)
    assert recovered == 1
    assert client.lists.get("kp:queue:generation:processing", []) == []
    queued = client.lists.get("kp:queue:generation", [])
    assert len(queued) == 1
    assert json.loads(queued[0])["retry"] == 1


def test_recover_stale_leaves_fresh_claims_alone(queue: JobQueue) -> None:
    queue.publish("generation", {"pattern_id": "p1"})
    queue.pop("generation", timeout=1)
    assert queue.recover_stale("generation", visibility_seconds=600) == 0
    client = queue._client  # type: ignore[attr-defined]
    assert len(client.lists.get("kp:queue:generation:processing", [])) == 1
