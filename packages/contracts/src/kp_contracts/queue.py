"""Redis-backed job queue with idempotency keys.

Every published job carries an idempotency key so at-least-once delivery from
the queue never duplicates work. Consumers commit by idempotency key before
performing any mutation.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

import redis

logger = logging.getLogger(__name__)


class JobQueue:
    def __init__(self, redis_url: str, *, prefix: str = "kp:queue:") -> None:
        self._client = redis.Redis.from_url(redis_url, decode_responses=True)
        self._prefix = prefix

    def publish(self, topic: str, payload: dict[str, Any], *, idempotency_key: str | None = None) -> str:
        job_id = str(uuid.uuid4())
        message: dict[str, Any] = {
            "id": job_id,
            "idempotency_key": idempotency_key or f"{topic}-{job_id}",
            "payload": payload,
        }
        self._client.rpush(self._prefix + topic, json.dumps(message))
        return job_id

    def pop(self, topic: str, *, timeout: int = 5) -> dict[str, Any] | None:
        try:
            item = self._client.blpop(self._prefix + topic, timeout=timeout)
        except redis.TimeoutError:
            # redis-py treats the block timeout as a hard client-side deadline
            # and raises TimeoutError instead of returning None when the queue
            # stays empty. That is a normal idle poll, not a failure.
            return None
        if item is None:
            return None
        try:
            return json.loads(item[1])  # type: ignore[no-any-return]
        except json.JSONDecodeError:
            logger.warning("discarding malformed queue message on %s", topic)
            return None

    def close(self) -> None:
        self._client.close()
