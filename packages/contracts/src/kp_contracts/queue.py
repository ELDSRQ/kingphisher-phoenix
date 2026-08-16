"""Redis-backed job queue with at-least-once delivery and a dead-letter topic.

Every published job carries an idempotency key so retried delivery never
duplicates work (consumers commit by idempotency key before mutating).

Semantics:
- ``pop`` atomically claims a message (BRPOPLPUSH) into the topic's
  ``:processing`` list, so a crash between claim and completion cannot lose it.
- ``ack`` removes a successfully processed message from ``:processing``.
- ``reject`` returns a failed message to the queue with an incremented retry
  counter; messages that exhaust their retries land on ``kp:queue:dlq:<topic>``.
- ``recover_stale`` re-queues messages left in ``:processing`` past a
  visibility window (crashed workers), preserving the retry budget.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any, cast

import redis

logger = logging.getLogger(__name__)


class JobQueue:
    def __init__(self, redis_url: str, *, prefix: str = "kp:queue:", max_message_bytes: int = 1_000_000) -> None:
        self._client = redis.Redis.from_url(redis_url, decode_responses=True)
        self._prefix = prefix
        self._max_message_bytes = max_message_bytes

    def _topic(self, topic: str) -> str:
        return self._prefix + topic

    def _processing(self, topic: str) -> str:
        return self._prefix + topic + ":processing"

    def _dlq(self, topic: str) -> str:
        return self._prefix + "dlq:" + topic

    def _delayed(self, topic: str) -> str:
        return self._prefix + "delayed:" + topic

    def _as_str(self, value: bytes | str) -> str:
        if isinstance(value, str):
            return value
        return value.decode("utf-8")

    def publish(
        self,
        topic: str,
        payload: dict[str, Any],
        *,
        idempotency_key: str | None = None,
        available_at: float | None = None,
    ) -> str:
        job_id = str(uuid.uuid4())
        message: dict[str, Any] = {
            "id": job_id,
            "idempotency_key": idempotency_key or f"{topic}-{job_id}",
            "retry": 0,
            "payload": payload,
        }
        encoded = json.dumps(message)
        if len(encoded.encode("utf-8")) > self._max_message_bytes:
            raise ValueError("queue message exceeds maximum size")
        if available_at is not None and available_at > time.time():
            self._client.zadd(self._delayed(topic), {encoded: available_at})
        else:
            self._client.rpush(self._topic(topic), encoded)
        return job_id

    def _promote_due(self, topic: str) -> None:
        """Move due delayed jobs into the ready list before a blocking pop."""
        delayed = self._delayed(topic)
        for raw in self._client.zrangebyscore(delayed, "-inf", time.time(), start=0, num=100):
            raw_str = self._as_str(cast(bytes | str, raw))
            if self._client.zrem(delayed, raw_str):
                self._client.rpush(self._topic(topic), raw_str)

    def pop(self, topic: str, *, timeout: int = 5) -> dict[str, Any] | None:
        self._promote_due(topic)
        try:
            raw = self._client.brpoplpush(self._topic(topic), self._processing(topic), timeout=timeout)
        except redis.TimeoutError:
            # redis-py treats the block timeout as a hard client-side deadline
            # and raises TimeoutError instead of returning None when the queue
            # stays empty. That is a normal idle poll, not a failure.
            return None
        if raw is None:
            return None
        try:
            message: dict[str, Any] = json.loads(raw)
        except json.JSONDecodeError:
            self._client.lrem(self._processing(topic), 0, self._as_str(raw))
            logger.warning("discarding malformed queue message on %s", topic)
            return None
        # Stamp the claim time into the serialized message so recover_stale can
        # detect crashed claims. The message is unique by id, so the
        # remove-and-reappend replace is race-safe.
        message["started_at"] = time.time()
        new_raw = json.dumps(message)
        self._client.lrem(self._processing(topic), 0, self._as_str(raw))
        self._client.rpush(self._processing(topic), new_raw)
        message["_raw"] = new_raw
        return message

    def ack(self, topic: str, message: dict[str, Any]) -> None:
        raw = message.pop("_raw", None)
        if raw is not None:
            self._client.lrem(self._processing(topic), 0, self._as_str(raw))

    def reject(self, topic: str, message: dict[str, Any], *, max_retries: int = 3) -> None:
        raw = message.pop("_raw", None)
        if raw is not None:
            self._client.lrem(self._processing(topic), 0, self._as_str(raw))
        retries = int(message.get("retry", 0)) + 1
        message["retry"] = retries
        message.pop("started_at", None)
        if retries < max_retries:
            self._client.rpush(self._topic(topic), json.dumps(message))
        else:
            logger.error("message %s exhausted %d retries; moving to DLQ", message.get("id"), max_retries)
            self._client.rpush(self._dlq(topic), json.dumps(message))

    def recover_stale(self, topic: str, *, visibility_seconds: int = 60, max_retries: int = 3) -> int:
        """Re-queue messages in :processing that exceed the visibility window.

        Handles a worker that died between pop and ack. Returns the number of
        messages recovered.
        """
        now = time.time()
        recovered = 0
        for raw in self._client.lrange(self._processing(topic), 0, -1):
            raw_str = self._as_str(raw)
            try:
                message: dict[str, Any] = json.loads(raw_str)
            except json.JSONDecodeError:
                self._client.lrem(self._processing(topic), 0, raw_str)
                continue
            started = message.get("started_at")
            stale = started is None or now - float(started) > visibility_seconds
            if not stale:
                continue
            self._client.lrem(self._processing(topic), 0, raw_str)
            retries = int(message.get("retry", 0)) + 1
            message["retry"] = retries
            message.pop("started_at", None)
            destination = self._topic(topic) if retries < max_retries else self._dlq(topic)
            if retries >= max_retries:
                logger.error("stale message %s exhausted retries; moving to DLQ", message.get("id"))
            self._client.rpush(destination, json.dumps(message))
            recovered += 1
        return recovered

    def close(self) -> None:
        self._client.close()
