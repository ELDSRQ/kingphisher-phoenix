"""Unit and live-contract tests for the Redis job queue.

The live contract belongs to the explicit ``make test-redis`` profile, which
requires ``REDIS_URL`` and rejects skips. The at-least-once mechanics are also
tested with a small script-aware fake so the hermetic suite needs no Redis.
"""

from __future__ import annotations

import contextlib
import json
import os
import time
import uuid
from collections.abc import Callable
from typing import Any

import pytest
import redis
from kp_contracts.queue import JobQueue


def _key(topic: str, suffix: str = "") -> str:
    """Mirror the public queue namespace while asserting Redis hash tags."""
    return f"kp:queue:{{{topic}}}{suffix}"


class _MemoryClient:
    """Tiny in-memory Redis stand-in for the queue's atomic Lua scripts."""

    def __init__(self) -> None:
        self.lists: dict[str, list[str]] = {}
        self.sorted_sets: dict[str, dict[str, float]] = {}
        self.timeout_error = False
        self.eval_calls: list[str] = []
        self.before_move: Callable[[str, str, str], None] | None = None
        self.strings: dict[str, str] = {}

    def rpush(self, key: str, value: str) -> int:
        self.lists.setdefault(key, []).append(value)
        return len(self.lists[key])

    def lpush(self, key: str, value: str) -> int:
        self.lists.setdefault(key, []).insert(0, value)
        return len(self.lists[key])

    def eval(self, script: str, numkeys: int, *values: object) -> object:
        del numkeys
        if self.timeout_error:
            raise redis.TimeoutError("Timeout reading from socket")
        marker = script.splitlines()[0]
        self.eval_calls.append(marker)

        if "kp_queue_publish_once_v1" in marker:
            dedup, destination, raw, _ttl, mode, score, job_id = values
            dedup_key = str(dedup)
            if dedup_key in self.strings:
                return self.strings[dedup_key]
            self.strings[dedup_key] = str(job_id)
            if str(mode) == "delayed":
                self.zadd(str(destination), {str(raw): float(score)})
            else:
                self.rpush(str(destination), str(raw))
            return str(job_id)

        if "kp_queue_promote_due_v1" in marker:
            delayed, ready, now, limit = values
            delayed_key = str(delayed)
            due = sorted(
                (
                    (score, raw)
                    for raw, score in self.sorted_sets.get(delayed_key, {}).items()
                    if score <= float(now)  # type: ignore[arg-type]
                ),
                key=lambda item: (item[0], item[1]),
            )[: int(limit)]  # type: ignore[arg-type]
            for _, raw in due:
                del self.sorted_sets[delayed_key][raw]
                self.rpush(str(ready), raw)
            return len(due)

        if "kp_queue_claim_v1" in marker:
            ready, processing, dlq, started_at = map(str, values)
            ready_values = self.lists.get(ready, [])
            while ready_values:
                raw = ready_values.pop(0)
                try:
                    message: Any = json.loads(raw)
                except json.JSONDecodeError:
                    message = None
                if (
                    isinstance(message, dict)
                    and isinstance(message.get("id"), str)
                    and isinstance(message.get("idempotency_key"), str)
                    and isinstance(message.get("retry"), int | float)
                    and isinstance(message.get("payload"), dict)
                ):
                    message["started_at"] = float(started_at)
                    claimed = json.dumps(message, separators=(",", ":"))
                    self.lpush(processing, claimed)
                    return claimed
                self.rpush(dlq, raw)
            return None

        if "kp_queue_move_if_present_v1" in marker:
            source, destination, old_raw, new_raw = map(str, values)
            if self.before_move is not None:
                before_move = self.before_move
                self.before_move = None
                before_move(source, destination, old_raw)
            if self.lrem(source, 1, old_raw) == 0:
                return 0
            self.rpush(destination, new_raw)
            return 1

        if "kp_queue_replay_dlq_v1" in marker:
            dlq, ready, reference, limit, replayed_at = values
            for raw in list(self.lists.get(str(dlq), []))[: int(limit)]:
                try:
                    message = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if not isinstance(message, dict) or message.get("id") != str(reference):
                    continue
                if not isinstance(message.get("idempotency_key"), str) or not isinstance(message.get("payload"), dict):
                    continue
                if self.lrem(str(dlq), 1, raw) == 0:
                    return None
                message["retry"] = 0
                message["replay_count"] = int(message.get("replay_count", 0)) + 1
                message["replayed_at"] = float(replayed_at)
                message.pop("dead_lettered_at", None)
                message.pop("started_at", None)
                encoded = json.dumps(message, separators=(",", ":"))
                self.rpush(str(ready), encoded)
                return encoded
            return None

        raise AssertionError(f"unexpected Lua script: {marker}")

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

    def llen(self, key: str) -> int:
        return len(self.lists.get(key, []))

    def lindex(self, key: str, index: int) -> str | None:
        values = self.lists.get(key, [])
        try:
            return values[index]
        except IndexError:
            return None

    def zadd(self, key: str, values: dict[str, float]) -> int:
        self.sorted_sets.setdefault(key, {}).update(values)
        return len(values)

    def zcard(self, key: str) -> int:
        return len(self.sorted_sets.get(key, {}))

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
    assert client.lists.get(_key("deliver")) == []
    assert len(client.lists.get(_key("deliver", ":processing"), [])) == 1
    assert "-- kp_queue_claim_v1" in client.eval_calls


def test_publish_idempotency_key_is_enforced_by_redis(queue: JobQueue) -> None:
    first = queue.publish("deliver", {"campaign_id": "c1"}, idempotency_key="same")
    duplicate = queue.publish("deliver", {"campaign_id": "c1"}, idempotency_key="same")
    client = queue._client  # type: ignore[attr-defined]
    assert len(client.lists[_key("deliver")]) == 1
    assert duplicate == first


def test_queue_is_fifo(queue: JobQueue) -> None:
    first_id = queue.publish("deliver", {"sequence": 1})
    queue.publish("deliver", {"sequence": 2})
    first = queue.pop("deliver", timeout=0)
    assert first is not None
    assert first["id"] == first_id
    assert first["payload"] == {"sequence": 1}


def test_ack_removes_from_processing(queue: JobQueue) -> None:
    queue.publish("deliver", {"n": 1})
    message = queue.pop("deliver", timeout=1)
    assert message is not None
    queue.ack("deliver", message)
    client = queue._client  # type: ignore[attr-defined]
    assert client.lists.get(_key("deliver", ":processing")) == []


def test_reject_requeues_then_moves_to_dlq_after_max_retries(queue: JobQueue) -> None:
    queue.publish("deliver", {"n": 1})
    for attempt in range(1, 4):
        message = queue.pop("deliver", timeout=1)
        assert message is not None, f"message lost before attempt {attempt}"
        queue.reject("deliver", message, max_retries=3)
    client = queue._client  # type: ignore[attr-defined]
    assert client.lists.get(_key("deliver"), []) == []
    dlq = client.lists.get(_key("deliver", ":dlq"), [])
    assert len(dlq) == 1
    assert json.loads(dlq[0])["retry"] == 3
    assert isinstance(json.loads(dlq[0])["dead_lettered_at"], float)


def test_dead_letter_can_be_listed_inspected_and_atomically_replayed(queue: JobQueue) -> None:
    job_id = queue.publish("deliver", {"campaign_id": "c1", "tracking_token": "secret"})
    for _ in range(3):
        claimed = queue.pop("deliver", timeout=0)
        assert claimed is not None
        queue.reject("deliver", claimed, max_retries=3)

    page = queue.list_dead_letters("deliver")
    assert queue.dead_letter_count("deliver") == 1
    assert page[0]["reference"] == job_id
    assert page[0]["message"]["payload"]["tracking_token"] == "secret"
    assert queue.get_dead_letter("deliver", job_id) == page[0]

    replayed = queue.replay_dead_letter("deliver", job_id)
    assert replayed is not None
    assert replayed["retry"] == 0
    assert replayed["replay_count"] == 1
    assert "dead_lettered_at" not in replayed
    assert queue.replay_dead_letter("deliver", job_id) is None
    assert queue.dead_letter_count("deliver") == 0
    claimed_again = queue.pop("deliver", timeout=0)
    assert claimed_again is not None and claimed_again["id"] == job_id


def test_malformed_dead_letter_is_quarantined_and_not_replayable(queue: JobQueue) -> None:
    client = queue._client  # type: ignore[attr-defined]  # noqa: SLF001
    client.rpush(_key("deliver", ":dlq"), "not-json")
    item = queue.list_dead_letters("deliver")[0]
    assert item["malformed"] is True
    assert item["reference"].startswith("malformed-")
    with pytest.raises(ValueError, match="malformed"):
        queue.replay_dead_letter("deliver", item["reference"])


def test_queue_stats_are_non_sensitive_and_report_oldest_age(queue: JobQueue, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("kp_contracts.queue.time.time", lambda: 100.0)
    queue.publish("deliver", {"secret": "never-in-stats"})
    monkeypatch.setattr("kp_contracts.queue.time.time", lambda: 125.0)
    assert queue.queue_stats("deliver") == {
        "ready": 1,
        "processing": 0,
        "delayed": 0,
        "dead_letter": 0,
        "oldest_ready_age_seconds": 25.0,
    }


def test_reject_is_idempotent_for_the_same_claim(queue: JobQueue) -> None:
    queue.publish("deliver", {"n": 1})
    message = queue.pop("deliver", timeout=0)
    assert message is not None

    queue.reject("deliver", message)
    queue.reject("deliver", message)

    client = queue._client  # type: ignore[attr-defined]  # noqa: SLF001
    assert len(client.lists.get(_key("deliver"), [])) == 1
    assert client.lists.get(_key("deliver", ":processing"), []) == []


def test_recover_stale_requeues_crashed_claim(queue: JobQueue) -> None:
    queue.publish("generation", {"pattern_id": "p1"})
    message = queue.pop("generation", timeout=1)
    assert message is not None
    # simulate a crash: the claim stays in :processing with an old started_at
    message["started_at"] = 0.0
    client = queue._client  # type: ignore[attr-defined]
    old_raw = message["_raw"]
    client.lrem(_key("generation", ":processing"), 0, old_raw)
    client.rpush(_key("generation", ":processing"), json.dumps(message))

    recovered = queue.recover_stale("generation", visibility_seconds=60)
    assert recovered == 1
    assert client.lists.get(_key("generation", ":processing"), []) == []
    queued = client.lists.get(_key("generation"), [])
    assert len(queued) == 1
    assert json.loads(queued[0])["retry"] == 1


def test_recover_stale_leaves_fresh_claims_alone(queue: JobQueue) -> None:
    queue.publish("generation", {"pattern_id": "p1"})
    queue.pop("generation", timeout=1)
    assert queue.recover_stale("generation", visibility_seconds=600) == 0
    client = queue._client  # type: ignore[attr-defined]
    assert len(client.lists.get(_key("generation", ":processing"), [])) == 1


def test_recover_stale_moves_exhausted_claim_to_dlq(queue: JobQueue) -> None:
    queue.publish("generation", {"pattern_id": "p1"})
    message = queue.pop("generation", timeout=1)
    assert message is not None
    message["started_at"] = 0.0
    message["retry"] = 2
    client = queue._client  # type: ignore[attr-defined]
    client.lrem(_key("generation", ":processing"), 0, message["_raw"])
    client.rpush(_key("generation", ":processing"), json.dumps(message))

    assert queue.recover_stale("generation", visibility_seconds=60, max_retries=3) == 1
    assert client.lists.get(_key("generation"), []) == []
    assert len(client.lists.get(_key("generation", ":dlq"), [])) == 1


def test_recover_stale_does_not_duplicate_a_concurrently_acked_claim(queue: JobQueue) -> None:
    queue.publish("generation", {"pattern_id": "p1"})
    message = queue.pop("generation", timeout=0)
    assert message is not None
    client = queue._client  # type: ignore[attr-defined]  # noqa: SLF001

    def ack_immediately_before_recovery(source: str, destination: str, raw: str) -> None:
        del destination
        client.lrem(source, 1, raw)

    client.before_move = ack_immediately_before_recovery
    assert queue.recover_stale("generation", visibility_seconds=-1) == 0
    assert client.lists.get(_key("generation"), []) == []
    assert client.lists.get(_key("generation", ":processing"), []) == []


def test_malformed_ready_message_is_preserved_in_dlq(queue: JobQueue) -> None:
    client = queue._client  # type: ignore[attr-defined]  # noqa: SLF001
    queue.publish("deliver", {"valid": True})
    client.rpush(_key("deliver"), "not-json")

    message = queue.pop("deliver", timeout=0)

    assert message is not None
    assert message["payload"] == {"valid": True}
    assert queue.pop("deliver", timeout=0) is None
    assert client.lists[_key("deliver", ":dlq")] == ["not-json"]


def test_non_object_ready_message_is_preserved_in_dlq(queue: JobQueue) -> None:
    client = queue._client  # type: ignore[attr-defined]  # noqa: SLF001
    queue.publish("deliver", {"valid": True})
    client.rpush(_key("deliver"), "[]")

    message = queue.pop("deliver", timeout=0)

    assert message is not None
    assert message["payload"] == {"valid": True}
    assert queue.pop("deliver", timeout=0) is None
    assert client.lists[_key("deliver", ":dlq")] == ["[]"]


def test_malformed_processing_message_is_preserved_in_dlq(queue: JobQueue) -> None:
    client = queue._client  # type: ignore[attr-defined]  # noqa: SLF001
    client.rpush(_key("generation", ":processing"), "not-json")

    assert queue.recover_stale("generation") == 0
    assert client.lists[_key("generation", ":processing")] == []
    assert client.lists[_key("generation", ":dlq")] == ["not-json"]


def test_publish_rejects_oversized_message() -> None:
    queue = JobQueue("redis://localhost:6379/0", max_message_bytes=100)
    queue._client = _MemoryClient()  # noqa: SLF001 - test seam
    with pytest.raises(ValueError, match="maximum size"):
        queue.publish("deliver", {"value": "x" * 500})


def test_delayed_message_is_not_visible_until_due(queue: JobQueue, monkeypatch: pytest.MonkeyPatch) -> None:
    now = time.time()
    monkeypatch.setattr("kp_contracts.queue.time.time", lambda: now)
    queue.publish("deliver", {"campaign_id": "c1"}, available_at=now + 60)
    assert queue.pop("deliver", timeout=0) is None

    monkeypatch.setattr("kp_contracts.queue.time.time", lambda: now + 61)
    message = queue.pop("deliver", timeout=0)
    assert message is not None
    assert message["payload"]["campaign_id"] == "c1"


@pytest.mark.contract
@pytest.mark.redis
def test_live_redis_atomic_queue_lifecycle() -> None:
    redis_url = os.getenv("REDIS_URL")
    if not redis_url:
        pytest.skip("REDIS_URL is not configured")
    prefix = f"kp:test:queue:{uuid.uuid4()}:"
    queue = JobQueue(redis_url, prefix=prefix)
    topics = ("deliver", "delayed", "recovery", "dlq")
    keys = [
        key
        for topic in topics
        for key in (
            queue._topic(topic),  # noqa: SLF001 - focused contract cleanup
            queue._processing(topic),  # noqa: SLF001 - focused contract cleanup
            queue._dlq(topic),  # noqa: SLF001 - focused contract cleanup
            queue._delayed(topic),  # noqa: SLF001 - focused contract cleanup
        )
    ]
    published_keys: list[str] = []
    try:
        try:
            queue._client.ping()  # noqa: SLF001 - live contract preflight
        except redis.RedisError as exc:
            pytest.skip(f"Redis is unreachable: {type(exc).__name__}")

        queue.publish("deliver", {"n": 1}, idempotency_key="live-deliver")
        published_keys.append(queue._published("deliver", "live-deliver"))  # noqa: SLF001
        claimed = queue.pop("deliver", timeout=1)
        assert claimed is not None
        queue.reject("deliver", claimed)
        retried = queue.pop("deliver", timeout=1)
        assert retried is not None
        assert retried["retry"] == 1
        queue.ack("deliver", retried)

        delayed_id = queue.publish("delayed", {"n": 2}, available_at=time.time() + 0.05)
        published_keys.append(queue._published("delayed", f"delayed-{delayed_id}"))  # noqa: SLF001
        delayed = queue.pop("delayed", timeout=1)
        assert delayed is not None
        queue.ack("delayed", delayed)

        recovery_id = queue.publish("recovery", {"n": 3})
        published_keys.append(queue._published("recovery", f"recovery-{recovery_id}"))  # noqa: SLF001
        crashed = queue.pop("recovery", timeout=1)
        assert crashed is not None
        assert queue.recover_stale("recovery", visibility_seconds=-1) == 1
        recovered = queue.pop("recovery", timeout=1)
        assert recovered is not None
        assert recovered["retry"] == 1
        queue.ack("recovery", recovered)

        dlq_id = queue.publish("dlq", {"n": 4})
        published_keys.append(queue._published("dlq", f"dlq-{dlq_id}"))  # noqa: SLF001
        for _ in range(3):
            failed = queue.pop("dlq", timeout=1)
            assert failed is not None
            queue.reject("dlq", failed, max_retries=3)
        assert queue.dead_letter_count("dlq") == 1
        assert queue.replay_dead_letter("dlq", dlq_id) is not None
        assert queue.replay_dead_letter("dlq", dlq_id) is None
        replayed = queue.pop("dlq", timeout=1)
        assert replayed is not None and replayed["id"] == dlq_id
        queue.ack("dlq", replayed)
    finally:
        with contextlib.suppress(redis.RedisError):
            queue._client.delete(
                *keys,
                *published_keys,
            )  # noqa: SLF001 - focused contract cleanup
        queue.close()
