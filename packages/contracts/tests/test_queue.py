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
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
import redis
from kp_contracts.queue import (
    AUDIT_ANCHOR_HEARTBEAT_KEY,
    CRITICAL_QUEUE_TOPICS,
    DEFAULT_QUEUE_TOPICS,
    QUEUE_PUBLISH_DEDUP_TTL_SECONDS,
    QUEUE_REPLAY_REVIEW_ONLY_TOPICS,
    QUEUE_REPLAY_SAFE_TOPICS,
    JobQueue,
    QueueOverflowError,
)


def _key(topic: str, suffix: str = "") -> str:
    """Mirror the public queue namespace while asserting Redis hash tags."""
    return f"kp:queue:{{{topic}}}{suffix}"


def test_default_queue_topics_cover_every_worker_consumed_queue() -> None:
    # KP-AUD-004: the admin DLQ allowlist must list every topic a worker role
    # consumes, or that queue's dead letters are invisible/undetailed/unreplayable
    # through the operator console. Mirror the worker role registry
    # (apps/workers/src/kp_workers/__main__.py WORKERS) without importing the
    # worker application into the contracts package.
    worker_consumed_topics = {
        "audit-anchor",
        "ingest",
        "generate",
        "deliver",
        "retention",
        "mailbox",
        "reply-mailbox",
        "remind",
        "alert",
        "directory",
        "curate",
    }
    assert "curate" in DEFAULT_QUEUE_TOPICS
    assert worker_consumed_topics <= set(DEFAULT_QUEUE_TOPICS)
    # No duplicates crept in while extending the fixed allowlist.
    assert len(DEFAULT_QUEUE_TOPICS) == len(set(DEFAULT_QUEUE_TOPICS))


def test_critical_queue_topics_are_the_audit_named_set() -> None:
    # KP-AUD-024: the critical set that is isolated from non-critical
    # backpressure must be exactly retention, delivery, and audit-anchor.
    expected = frozenset({"deliver", "retention", "audit-anchor"})
    assert expected == CRITICAL_QUEUE_TOPICS
    assert set(DEFAULT_QUEUE_TOPICS) >= CRITICAL_QUEUE_TOPICS


def test_automatic_replay_requires_explicit_topic_membership() -> None:
    assert set(DEFAULT_QUEUE_TOPICS) >= QUEUE_REPLAY_SAFE_TOPICS
    assert not QUEUE_REPLAY_SAFE_TOPICS & QUEUE_REPLAY_REVIEW_ONLY_TOPICS
    assert {"deliver", "reply-mailbox", "alert"} <= QUEUE_REPLAY_REVIEW_ONLY_TOPICS
    assert "future-external-send" not in QUEUE_REPLAY_SAFE_TOPICS


class _MemoryClient:
    """Tiny in-memory Redis stand-in for the queue's atomic Lua scripts."""

    def __init__(self) -> None:
        self.lists: dict[str, list[str]] = {}
        self.sorted_sets: dict[str, dict[str, float]] = {}
        self.timeout_error = False
        self.eval_calls: list[str] = []
        self.before_move: Callable[[str, str, str], None] | None = None
        self.strings: dict[str, str] = {}
        self.counters: dict[str, int] = {}

    def incr(self, key: str) -> int:
        self.counters[key] = self.counters.get(key, 0) + 1
        return self.counters[key]

    def exists(self, key: str) -> int:
        return 1 if (key in self.strings or key in self.lists or key in self.sorted_sets) else 0

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
            ready, processing, dlq, fence_key, started_at, owner, lease = map(str, values)
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
                    now = float(started_at)
                    message["started_at"] = now
                    message["owner"] = owner
                    message["fence"] = self.incr(fence_key)
                    message["lease_deadline"] = now + float(lease)
                    claimed = json.dumps(message, separators=(",", ":"))
                    self.lpush(processing, claimed)
                    return claimed
                self.rpush(dlq, raw)
            return None

        if "kp_queue_renew_lease_v2" in marker:
            processing, job_id, owner, fence, new_deadline = map(str, values)
            for raw in list(self.lists.get(processing, [])):
                try:
                    message = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if not isinstance(message, dict):
                    continue
                if message.get("id") == job_id and message.get("owner") == owner and message.get("fence") == int(fence):
                    message["lease_deadline"] = float(new_deadline)
                    encoded = json.dumps(message, separators=(",", ":"))
                    self.lrem(processing, 1, raw)
                    self.lpush(processing, encoded)
                    return encoded
            return None

        if "kp_queue_ack_claim_v1" in marker or "kp_queue_reject_claim_v1" in marker:
            rejecting = "kp_queue_reject_claim_v1" in marker
            if rejecting:
                processing, ready, dlq, job_id, owner, fence, max_retries, rejected_at = map(str, values)
            else:
                processing, job_id, owner, fence = map(str, values)
            for raw in list(self.lists.get(processing, [])):
                try:
                    message = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if (
                    not isinstance(message, dict)
                    or message.get("id") != job_id
                    or message.get("owner") != owner
                    or message.get("fence") != int(fence)
                ):
                    continue
                if not rejecting:
                    return self.lrem(processing, 1, raw)
                retries = int(message["retry"]) + 1
                message["retry"] = retries
                for key in ("started_at", "owner", "fence", "lease_deadline"):
                    message.pop(key, None)
                exhausted = retries >= int(max_retries)
                if exhausted:
                    message["dead_lettered_at"] = float(rejected_at)
                encoded = json.dumps(message, separators=(",", ":"))
                if self.lrem(processing, 1, raw) == 0:
                    return 0
                self.rpush(dlq if exhausted else ready, encoded)
                return 2 if exhausted else 1
            return 0

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
    q._client = _MemoryClient()
    yield q
    q.close()


class _StringClient:
    """Minimal string-only Redis stand-in for the AUD-003 heartbeat."""

    def __init__(self) -> None:
        self.strings: dict[str, str] = {}
        self.raise_on_get = False

    def set(self, key: str, value: str) -> None:
        self.strings[key] = value

    def get(self, key: str) -> str | None:
        if self.raise_on_get:
            raise redis.RedisError("unreachable")
        return self.strings.get(key)

    def close(self) -> None:
        return None


def _heartbeat_queue() -> JobQueue:
    q = JobQueue("redis://localhost:6379/0")
    q._client = _StringClient()  # type: ignore[assignment]
    return q


def test_audit_anchor_heartbeat_round_trips_as_utc_iso8601() -> None:
    q = _heartbeat_queue()
    when = datetime(2026, 9, 6, 12, 0, tzinfo=UTC)

    q.record_audit_anchor_heartbeat(when)

    assert q._client.strings[AUDIT_ANCHOR_HEARTBEAT_KEY] == "2026-09-06T12:00:00+00:00"  # type: ignore[attr-defined]
    assert q.read_audit_anchor_heartbeat() == when


def test_record_heartbeat_normalizes_non_utc_offsets() -> None:
    q = _heartbeat_queue()
    when = datetime(2026, 9, 6, 14, 0, tzinfo=timezone(timedelta(hours=2)))

    q.record_audit_anchor_heartbeat(when)

    assert q._client.strings[AUDIT_ANCHOR_HEARTBEAT_KEY] == "2026-09-06T12:00:00+00:00"  # type: ignore[attr-defined]


def test_read_heartbeat_is_none_when_absent() -> None:
    assert _heartbeat_queue().read_audit_anchor_heartbeat() is None


def test_read_heartbeat_is_none_for_naive_or_garbage_values() -> None:
    q = _heartbeat_queue()
    q._client.strings[AUDIT_ANCHOR_HEARTBEAT_KEY] = "2026-09-06T12:00:00"  # type: ignore[attr-defined]  # naive
    assert q.read_audit_anchor_heartbeat() is None
    q._client.strings[AUDIT_ANCHOR_HEARTBEAT_KEY] = "not-a-timestamp"  # type: ignore[attr-defined]
    assert q.read_audit_anchor_heartbeat() is None


def test_read_heartbeat_propagates_redis_errors_for_fail_open_handling() -> None:
    q = _heartbeat_queue()
    q._client.raise_on_get = True  # type: ignore[attr-defined]
    with pytest.raises(redis.RedisError):
        q.read_audit_anchor_heartbeat()


def test_pop_treats_redis_blocking_timeout_as_idle(queue: JobQueue) -> None:
    queue._client.timeout_error = True  # type: ignore[attr-defined]
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
    client = queue._client  # type: ignore[attr-defined]
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
    # "deliver" is a critical topic, so its depth budget is unbounded (None) and
    # it is never over the depth budget; the age budget still applies and is not
    # breached at 25s. The stats carry the budget/health fields (KP-AUD-024).
    assert queue.queue_stats("deliver") == {
        "ready": 1,
        "processing": 0,
        "delayed": 0,
        "dead_letter": 0,
        "oldest_ready_age_seconds": 25.0,
        "ready_depth_budget": None,
        "oldest_ready_age_budget_seconds": 900.0,
        "critical": True,
        "over_depth_budget": False,
        "over_age_budget": False,
        "healthy": True,
    }


def test_reject_is_idempotent_for_the_same_claim(queue: JobQueue) -> None:
    queue.publish("deliver", {"n": 1})
    message = queue.pop("deliver", timeout=0)
    assert message is not None

    queue.reject("deliver", message)
    queue.reject("deliver", message)

    client = queue._client  # type: ignore[attr-defined]
    assert len(client.lists.get(_key("deliver"), [])) == 1
    assert client.lists.get(_key("deliver", ":processing"), []) == []


def test_recover_stale_requeues_crashed_claim(queue: JobQueue) -> None:
    queue.publish("generation", {"pattern_id": "p1"})
    message = queue.pop("generation", timeout=1)
    assert message is not None
    # simulate a crash: the claim stays in :processing with an expired lease
    message["started_at"] = 0.0
    message["lease_deadline"] = 0.0
    message.pop("_raw", None)
    client = queue._client  # type: ignore[attr-defined]
    client.lists[_key("generation", ":processing")] = [json.dumps(message)]

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
    message["lease_deadline"] = 0.0
    message["retry"] = 2
    message.pop("_raw", None)
    client = queue._client  # type: ignore[attr-defined]
    client.lists[_key("generation", ":processing")] = [json.dumps(message)]

    assert queue.recover_stale("generation", visibility_seconds=60, max_retries=3) == 1
    assert client.lists.get(_key("generation"), []) == []
    assert len(client.lists.get(_key("generation", ":dlq"), [])) == 1


def test_recover_stale_does_not_duplicate_a_concurrently_acked_claim(queue: JobQueue) -> None:
    queue.publish("generation", {"pattern_id": "p1"})
    message = queue.pop("generation", timeout=0)
    assert message is not None
    client = queue._client  # type: ignore[attr-defined]
    # Force the lease expired so recovery attempts the atomic move.
    message["lease_deadline"] = 0.0
    message.pop("_raw", None)
    client.lists[_key("generation", ":processing")] = [json.dumps(message)]

    def ack_immediately_before_recovery(source: str, destination: str, raw: str) -> None:
        del destination
        client.lrem(source, 1, raw)

    client.before_move = ack_immediately_before_recovery
    assert queue.recover_stale("generation", visibility_seconds=-1) == 0
    assert client.lists.get(_key("generation"), []) == []
    assert client.lists.get(_key("generation", ":processing"), []) == []


def test_claim_stamps_owner_fencing_token_and_lease(queue: JobQueue) -> None:
    queue.publish("deliver", {"n": 1})
    message = queue.pop("deliver", timeout=0, owner="owner-a", lease_seconds=120)
    assert message is not None
    assert message["owner"] == "owner-a"
    assert message["fence"] == 1
    assert message["lease_deadline"] == message["started_at"] + 120
    # A second claim takes a strictly higher fencing token.
    queue.publish("deliver", {"n": 2})
    second = queue.pop("deliver", timeout=0, owner="owner-b")
    assert second is not None
    assert second["fence"] == 2


def test_default_owner_is_a_fresh_uuid_per_claim(queue: JobQueue) -> None:
    queue.publish("deliver", {"n": 1})
    queue.publish("deliver", {"n": 2})
    first = queue.pop("deliver", timeout=0)
    second = queue.pop("deliver", timeout=0)
    assert first is not None and second is not None
    assert first["owner"] and second["owner"]
    assert first["owner"] != second["owner"]


def test_renew_lease_extends_only_for_the_current_owner(queue: JobQueue) -> None:
    queue.publish("generation", {"pattern_id": "p1"})
    message = queue.pop("generation", timeout=0, owner="owner-a", lease_seconds=30)
    assert message is not None
    original_deadline = message["lease_deadline"]
    original_raw = message["_raw"]

    assert queue.renew_lease("generation", message, lease_seconds=300) is True
    assert message["lease_deadline"] > original_deadline
    # The stored envelope was rewritten, so ack still matches the live claim.
    assert message["_raw"] != original_raw
    client = queue._client  # type: ignore[attr-defined]
    stored = json.loads(client.lists[_key("generation", ":processing")][0])
    assert stored["lease_deadline"] == message["lease_deadline"]

    # A renewal presenting a stale owner is refused (fencing).
    stale = dict(message)
    stale["owner"] = "owner-zombie"
    assert queue.renew_lease("generation", stale, lease_seconds=999) is False


@pytest.mark.parametrize("outcome", ("ack", "reject", "dead-letter"))
def test_lost_renewal_response_does_not_prevent_finalizing_current_claim(
    queue: JobQueue, monkeypatch: pytest.MonkeyPatch, outcome: str
) -> None:
    queue.publish("generate", {"pattern_id": "p1"})
    message = queue.pop("generate", timeout=0, owner="owner-a", lease_seconds=30)
    assert message is not None
    old_raw = message["_raw"]
    client = queue._client
    original_eval = client.eval

    def lose_renewal_reply(script: str, *args: Any, **kwargs: Any) -> Any:
        result = original_eval(script, *args, **kwargs)
        if "kp_queue_renew_lease_v2" in script:
            raise redis.TimeoutError("synthetic lost reply after Redis applied renewal")
        return result

    monkeypatch.setattr(client, "eval", lose_renewal_reply)
    with pytest.raises(redis.TimeoutError):
        queue.renew_lease("generate", message, lease_seconds=300)
    assert message["_raw"] == old_raw
    assert client.lists[_key("generate", ":processing")][0] != old_raw  # type: ignore[attr-defined]

    if outcome == "ack":
        queue.ack("generate", message)
        assert queue.pop("generate", timeout=0) is None
    else:
        # Neither payload nor retry state from this caller may overwrite the
        # authoritative renewed Redis envelope.
        message["retry"] = 900
        message["payload"] = {"untrusted_caller_copy": True}
        queue.reject("generate", message, max_retries=1 if outcome == "dead-letter" else 3)
        if outcome == "dead-letter":
            assert queue.dead_letter_count("generate") == 1
            assert queue.list_dead_letters("generate")[0]["message"]["retry"] == 1
        else:
            retried = queue.pop("generate", timeout=0)
            assert retried is not None
            assert retried["payload"] == {"pattern_id": "p1"}
            assert retried["retry"] == 1
            queue.ack("generate", retried)
    assert client.lists[_key("generate", ":processing")] == []  # type: ignore[attr-defined]


def test_reused_owner_cannot_finalize_or_renew_an_older_fence(queue: JobQueue) -> None:
    queue.publish("generate", {"pattern_id": "p1"})
    old = queue.pop("generate", timeout=0, owner="reused-owner", lease_seconds=-1)
    assert old is not None
    assert queue.recover_stale("generate") == 1
    current = queue.pop("generate", timeout=0, owner="reused-owner", lease_seconds=300)
    assert current is not None
    assert current["fence"] > old["fence"]
    queue.ack("generate", old)
    queue.reject("generate", old)
    assert queue.renew_lease("generate", old, lease_seconds=600) is False
    assert queue._client.lrange(_key("generate", ":processing"), 0, -1) == [current["_raw"]]
    queue.ack("generate", current)
    assert queue._client.lrange(_key("generate", ":processing"), 0, -1) == []


@pytest.mark.parametrize("fence", (None, True, "1", 0, -1))
def test_finalize_without_an_authentic_claim_fence_is_a_noop(queue: JobQueue, fence: Any) -> None:
    queue.publish("generate", {"pattern_id": "p1"})
    current = queue.pop("generate", timeout=0)
    assert current is not None
    invalid = {**current, "fence": fence}
    queue.ack("generate", invalid)
    queue.reject("generate", invalid)
    assert queue.renew_lease("generate", invalid, lease_seconds=300) is False
    assert queue._client.lrange(_key("generate", ":processing"), 0, -1) == [current["_raw"]]


def test_recovery_reassigns_owner_and_fences_out_the_zombie(queue: JobQueue) -> None:
    queue.publish("generation", {"pattern_id": "p1"})
    zombie = queue.pop("generation", timeout=0, owner="owner-a", lease_seconds=30)
    assert zombie is not None
    client = queue._client  # type: ignore[attr-defined]

    # Force the lease expired and recover it (as a crashed worker would be).
    expired = {key: value for key, value in zombie.items() if key != "_raw"}
    expired["lease_deadline"] = 0.0
    client.lists[_key("generation", ":processing")] = [json.dumps(expired)]
    assert queue.recover_stale("generation") == 1

    # A different worker re-claims it: new owner, strictly higher fencing token.
    fresh = queue.pop("generation", timeout=0, owner="owner-b", lease_seconds=30)
    assert fresh is not None
    assert fresh["owner"] == "owner-b"
    assert fresh["fence"] > zombie["fence"]

    # The resumed zombie's ack/reject/renew are fenced: they target the old
    # envelope, which no longer exists, so they are no-ops and cannot complete
    # or re-queue a message another worker now owns.
    queue.ack("generation", zombie)
    assert len(client.lists[_key("generation", ":processing")]) == 1
    assert queue.renew_lease("generation", zombie, lease_seconds=999) is False
    queue.reject("generation", zombie)
    assert len(client.lists[_key("generation", ":processing")]) == 1
    assert client.lists.get(_key("generation"), []) == []


def test_recover_stale_leaves_a_live_lease_even_past_visibility(queue: JobQueue) -> None:
    # A slow-but-healthy handler: visibility elapsed, but the lease is live.
    queue.publish("generation", {"pattern_id": "p1"})
    message = queue.pop("generation", timeout=0, lease_seconds=3600)
    assert message is not None
    assert queue.recover_stale("generation", visibility_seconds=-1) == 0
    client = queue._client  # type: ignore[attr-defined]
    assert len(client.lists.get(_key("generation", ":processing"), [])) == 1


def test_job_published_tracks_dedup_marker_presence(queue: JobQueue) -> None:
    assert queue.job_published("deliver", "k-absent") is False
    queue.publish("deliver", {"n": 1}, idempotency_key="k-present")
    assert queue.job_published("deliver", "k-present") is True
    # The marker survives consumption, so a reconciliation treats an acked job
    # as still "known" to Redis rather than lost.
    message = queue.pop("deliver", timeout=0)
    assert message is not None
    queue.ack("deliver", message)
    assert queue.job_published("deliver", "k-present") is True


def test_malformed_ready_message_is_preserved_in_dlq(queue: JobQueue) -> None:
    client = queue._client  # type: ignore[attr-defined]
    queue.publish("deliver", {"valid": True})
    client.rpush(_key("deliver"), "not-json")

    message = queue.pop("deliver", timeout=0)

    assert message is not None
    assert message["payload"] == {"valid": True}
    assert queue.pop("deliver", timeout=0) is None
    assert client.lists[_key("deliver", ":dlq")] == ["not-json"]


def test_non_object_ready_message_is_preserved_in_dlq(queue: JobQueue) -> None:
    client = queue._client  # type: ignore[attr-defined]
    queue.publish("deliver", {"valid": True})
    client.rpush(_key("deliver"), "[]")

    message = queue.pop("deliver", timeout=0)

    assert message is not None
    assert message["payload"] == {"valid": True}
    assert queue.pop("deliver", timeout=0) is None
    assert client.lists[_key("deliver", ":dlq")] == ["[]"]


def test_malformed_processing_message_is_preserved_in_dlq(queue: JobQueue) -> None:
    client = queue._client  # type: ignore[attr-defined]
    client.rpush(_key("generation", ":processing"), "not-json")

    assert queue.recover_stale("generation") == 0
    assert client.lists[_key("generation", ":processing")] == []
    assert client.lists[_key("generation", ":dlq")] == ["not-json"]


def test_publish_rejects_oversized_message() -> None:
    queue = JobQueue("redis://localhost:6379/0", max_message_bytes=100)
    queue._client = _MemoryClient()
    with pytest.raises(ValueError, match="maximum size"):
        queue.publish("deliver", {"value": "x" * 500})


def _budgeted_queue(**budgets: Any) -> JobQueue:
    q = JobQueue("redis://localhost:6379/0", **budgets)
    q._client = _MemoryClient()  # type: ignore[assignment]
    return q


def test_publish_fails_fast_with_typed_error_at_the_ready_depth_budget() -> None:
    # KP-AUD-024 producer backpressure: a non-critical topic at/over its ready
    # depth budget refuses further publishes with the typed QueueOverflowError
    # instead of growing the queue without bound.
    queue = _budgeted_queue(ready_depth_budget=2)
    queue.publish("generate", {"n": 1})
    queue.publish("generate", {"n": 2})

    with pytest.raises(QueueOverflowError) as excinfo:
        queue.publish("generate", {"n": 3})
    assert excinfo.value.topic == "generate"
    assert excinfo.value.depth == 2
    assert excinfo.value.budget == 2

    # Nothing was enqueued by the refused publish; the ready list stays at budget.
    client = queue._client  # type: ignore[attr-defined]
    assert client.llen(_key("generate")) == 2


def test_backpressure_does_not_shed_critical_topics_when_noncritical_is_flooded() -> None:
    # KP-AUD-024 critical-role isolation: a flooded non-critical topic must never
    # fail-fast a retention/delivery/audit-anchor publish. Critical topics carry
    # their own (unbounded-by-default) budget.
    queue = _budgeted_queue(ready_depth_budget=1)
    queue.publish("generate", {"n": 1})  # non-critical now at budget
    with pytest.raises(QueueOverflowError):
        queue.publish("generate", {"n": 2})

    # Every critical topic still accepts work no matter how flooded "generate" is.
    for critical_topic in ("deliver", "retention", "audit-anchor"):
        for index in range(5):
            assert queue.publish(critical_topic, {"n": index})
    client = queue._client  # type: ignore[attr-defined]
    assert client.llen(_key("deliver")) == 5
    assert client.llen(_key("retention")) == 5
    assert client.llen(_key("audit-anchor")) == 5


def test_critical_topic_budget_is_enforced_when_configured() -> None:
    # Critical isolation is "unbounded by default", but an operator can still set
    # a (higher) explicit critical budget; backpressure then applies to it too.
    queue = _budgeted_queue(ready_depth_budget=1, critical_ready_depth_budget=2)
    queue.publish("deliver", {"n": 1})
    queue.publish("deliver", {"n": 2})
    with pytest.raises(QueueOverflowError):
        queue.publish("deliver", {"n": 3})


def test_delayed_publish_bypasses_ready_depth_backpressure() -> None:
    # A delayed publish targets the scheduled set, not the ready list, so it is
    # not refused by a saturated ready list (it adds no ready depth yet).
    queue = _budgeted_queue(ready_depth_budget=1)
    queue.publish("generate", {"n": 1})  # ready list now at budget
    delayed_id = queue.publish("generate", {"n": 2}, available_at=time.time() + 3600)
    assert delayed_id
    client = queue._client  # type: ignore[attr-defined]
    assert client.llen(_key("generate")) == 1
    assert client.zcard(_key("generate", ":delayed")) == 1


def test_queue_stats_report_over_depth_and_over_age_budget_as_unhealthy(monkeypatch: pytest.MonkeyPatch) -> None:
    # KP-AUD-024 actionable health: a topic over its depth OR age budget is
    # reported unhealthy through the existing stats surface.
    queue = _budgeted_queue(ready_depth_budget=2, oldest_ready_age_budget_seconds=30.0)
    monkeypatch.setattr("kp_contracts.queue.time.time", lambda: 100.0)
    queue.publish("generate", {"n": 1})
    queue.publish("generate", {"n": 2})

    # At depth budget and oldest job aged past the age budget -> both breached.
    monkeypatch.setattr("kp_contracts.queue.time.time", lambda: 140.0)
    stats = queue.queue_stats("generate")
    assert stats["ready_depth_budget"] == 2
    assert stats["oldest_ready_age_budget_seconds"] == 30.0
    assert stats["critical"] is False
    assert stats["over_depth_budget"] is True
    assert stats["over_age_budget"] is True
    assert stats["healthy"] is False


def test_queue_stats_healthy_when_within_budgets(monkeypatch: pytest.MonkeyPatch) -> None:
    queue = _budgeted_queue(ready_depth_budget=10, oldest_ready_age_budget_seconds=300.0)
    monkeypatch.setattr("kp_contracts.queue.time.time", lambda: 100.0)
    queue.publish("generate", {"n": 1})
    monkeypatch.setattr("kp_contracts.queue.time.time", lambda: 110.0)
    stats = queue.queue_stats("generate")
    assert stats["over_depth_budget"] is False
    assert stats["over_age_budget"] is False
    assert stats["healthy"] is True


def test_unbounded_budget_never_applies_backpressure() -> None:
    queue = _budgeted_queue(ready_depth_budget=None)
    for index in range(50):
        assert queue.publish("generate", {"n": index})
    client = queue._client  # type: ignore[attr-defined]
    assert client.llen(_key("generate")) == 50


def test_already_published_idempotent_republish_is_not_failed_fast_at_budget() -> None:
    # N5: an idempotent re-publish of an already-enqueued job (its dedup marker is
    # present) adds no ready depth, so it must return the existing id instead of
    # being refused — otherwise an outbox retry would be rejected every cycle
    # while depth stays high.
    queue = _budgeted_queue(ready_depth_budget=1)
    first = queue.publish("generate", {"n": 1}, idempotency_key="k-dupe")
    # The topic is now at budget; a NEW job is refused...
    with pytest.raises(QueueOverflowError):
        queue.publish("generate", {"n": 2}, idempotency_key="k-new")
    # ...but re-publishing the SAME key is accepted and returns the existing id.
    again = queue.publish("generate", {"n": 1}, idempotency_key="k-dupe")
    assert again == first
    client = queue._client  # type: ignore[attr-defined]
    assert client.llen(_key("generate")) == 1


def test_queue_overflow_error_is_an_exception_subclass() -> None:
    # A producer's generic ``except Exception`` (e.g. the transactional outbox
    # dispatcher) must catch backpressure so it marks the row failed-and-kept and
    # retries later, rather than letting it escape.
    queue = _budgeted_queue(ready_depth_budget=1)
    queue.publish("generate", {"n": 1})
    caught: Exception | None = None
    try:
        queue.publish("generate", {"n": 2})
    except Exception as exc:  # noqa: BLE001 - exactly the outbox's catch
        caught = exc
    assert isinstance(caught, QueueOverflowError)


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
@pytest.mark.parametrize("outcome", ("ack", "reject"))
def test_live_redis_finalizes_claim_after_lost_renewal_reply(monkeypatch: pytest.MonkeyPatch, outcome: str) -> None:
    redis_url = os.getenv("REDIS_URL")
    if not redis_url:
        pytest.skip("REDIS_URL is not configured")
    # Preserve this generated namespace as evidence; never flush a database or
    # remove another run's keys. The publish marker has its normal bounded TTL.
    queue = JobQueue(redis_url, prefix=f"kp:test:lease-effect:{uuid.uuid4()}:")
    try:
        queue.publish("generate", {"pattern_id": "synthetic"}, idempotency_key="lost-reply")
        assert (
            QUEUE_PUBLISH_DEDUP_TTL_SECONDS - 5
            <= queue._client.ttl(queue._published("generate", "lost-reply"))
            <= QUEUE_PUBLISH_DEDUP_TTL_SECONDS
        )
        message = queue.pop("generate", timeout=0, owner="same-owner", lease_seconds=30)
        assert message is not None
        original_raw = message["_raw"]
        original_eval = queue._client.eval

        def lose_reply(script: str, *args: Any, **kwargs: Any) -> Any:
            result = original_eval(script, *args, **kwargs)
            if "kp_queue_renew_lease_v2" in script:
                raise redis.TimeoutError("synthetic lost reply after Redis applied renewal")
            return result

        monkeypatch.setattr(queue._client, "eval", lose_reply)
        with pytest.raises(redis.TimeoutError):
            queue.renew_lease("generate", message, lease_seconds=300)
        assert message["_raw"] == original_raw
        stored = queue._client.lrange(queue._processing("generate"), 0, -1)
        assert len(stored) == 1 and stored[0] != original_raw
        monkeypatch.setattr(queue._client, "eval", original_eval)
        if outcome == "ack":
            queue.ack("generate", message)
            assert queue.pop("generate", timeout=0) is None
        else:
            queue.reject("generate", message)
            current = queue.pop("generate", timeout=0, owner="same-owner", lease_seconds=300)
            assert current is not None and current["retry"] == 1
            assert current["fence"] > message["fence"]
            queue.ack("generate", message)
            queue.reject("generate", message)
            assert queue.renew_lease("generate", message, lease_seconds=600) is False
            assert queue._client.lrange(queue._processing("generate"), 0, -1) == [current["_raw"]]
            queue.ack("generate", current)
        assert queue._client.llen(queue._processing("generate")) == 0
        assert queue._client.llen(queue._topic("generate")) == 0
    finally:
        queue.close()


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
            queue._topic(topic),
            queue._processing(topic),
            queue._dlq(topic),
            queue._delayed(topic),
            queue._fence(topic),
        )
    ]
    published_keys: list[str] = []
    try:
        try:
            queue._client.ping()
        except redis.RedisError as exc:
            pytest.skip(f"Redis is unreachable: {type(exc).__name__}")

        queue.publish("deliver", {"n": 1}, idempotency_key="live-deliver")
        published_keys.append(queue._published("deliver", "live-deliver"))
        claimed = queue.pop("deliver", timeout=1)
        assert claimed is not None
        queue.reject("deliver", claimed)
        retried = queue.pop("deliver", timeout=1)
        assert retried is not None
        assert retried["retry"] == 1
        queue.ack("deliver", retried)

        delayed_id = queue.publish("delayed", {"n": 2}, available_at=time.time() + 0.05)
        published_keys.append(queue._published("delayed", f"delayed-{delayed_id}"))
        delayed = queue.pop("delayed", timeout=1)
        assert delayed is not None
        queue.ack("delayed", delayed)

        recovery_id = queue.publish("recovery", {"n": 3})
        published_keys.append(queue._published("recovery", f"recovery-{recovery_id}"))
        # A negative lease makes the claim's lease_deadline immediately past, so
        # recovery treats it as a crashed/expired owner.
        crashed = queue.pop("recovery", timeout=1, lease_seconds=-1)
        assert crashed is not None
        assert crashed["owner"]
        assert queue.recover_stale("recovery") == 1
        recovered = queue.pop("recovery", timeout=1)
        assert recovered is not None
        assert recovered["retry"] == 1
        queue.ack("recovery", recovered)

        dlq_id = queue.publish("dlq", {"n": 4})
        published_keys.append(queue._published("dlq", f"dlq-{dlq_id}"))
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
            )
        queue.close()
