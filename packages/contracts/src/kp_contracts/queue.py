"""Redis-backed job queue with at-least-once delivery and a dead-letter topic.

Every published job carries an idempotency key so retried delivery never
duplicates work (consumers commit by idempotency key before mutating).

Semantics:
- ``pop`` atomically moves a message into the topic's ``:processing`` list and
  stamps it with an *owner* token, a monotonic *fencing* token, and a
  *lease_deadline*, so a crash between claim and completion cannot lose it and a
  slow-but-healthy handler cannot be recovered out from under its owner.
- ``renew_lease`` extends the ``lease_deadline`` of an in-flight claim, but only
  for the current owner (a heartbeat issued by the supervisor while a handler
  runs). A stale owner's renewal is refused.
- ``ack`` removes a successfully processed message from ``:processing``. Because
  it matches the exact claimed envelope (which embeds the owner), an ack issued
  by a stale owner removes nothing — it is fenced.
- ``reject`` returns a failed message to the queue with an incremented retry
  counter; messages that exhaust their retries land on ``kp:queue:dlq:<topic>``.
  It is fenced by the same exact-envelope match as ``ack``.
- ``recover_stale`` re-queues ONLY genuinely-expired claims (``lease_deadline``
  in the past), so a concurrent recovery pass or a slow healthy handler can no
  longer trigger duplicate delivery. Crashed workers are still recovered once
  their lease expires, preserving the retry budget.

KP-AUD-006: the owner token plus the monotonic fencing token make every
``ack``/``reject``/``renew_lease`` reject a stale owner. Recovery assigns a new
owner and a higher fencing token on the next claim, so a resumed zombie handler
can never complete or re-queue a message that now belongs to another worker.
This Redis-side fence is independent of — and does not weaken — the PostgreSQL
assignment-claim fence and INDETERMINATE reconciliation.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from datetime import UTC, datetime
from typing import Any, cast

import redis

logger = logging.getLogger(__name__)


# A blocking Redis list move cannot also transform the claimed value.  The old
# implementation therefore used BRPOPLPUSH followed by LREM and RPUSH, leaving
# a loss/duplicate window while stamping ``started_at``.  These short scripts
# make every state transition a single Redis operation.  ``pop`` polls the
# atomic claim script so due delayed work is also noticed during its timeout.
_PROMOTE_DUE_SCRIPT = """-- kp_queue_promote_due_v1
local due = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', ARGV[1], 'LIMIT', 0, ARGV[2])
for _, raw in ipairs(due) do
    redis.call('ZREM', KEYS[1], raw)
    redis.call('RPUSH', KEYS[2], raw)
end
return #due
"""

_CLAIM_SCRIPT = """-- kp_queue_claim_v1
while true do
    local raw = redis.call('LPOP', KEYS[1])
    if not raw then
        return nil
    end

    local decoded, message = pcall(cjson.decode, raw)
    if decoded
        and type(message) == 'table'
        and type(message['id']) == 'string'
        and type(message['idempotency_key']) == 'string'
        and type(message['retry']) == 'number'
        and type(message['payload']) == 'table'
    then
        -- Stamp a fresh owner, a monotonic fencing token, and a lease deadline
        -- so recovery can tell a live claim from an expired one and so a stale
        -- owner's ack/reject/renew is fenced out (KP-AUD-006).
        local now = tonumber(ARGV[1])
        message['started_at'] = now
        message['owner'] = ARGV[2]
        message['fence'] = redis.call('INCR', KEYS[4])
        message['lease_deadline'] = now + tonumber(ARGV[3])
        local encoded, claimed = pcall(cjson.encode, message)
        if encoded then
            redis.call('LPUSH', KEYS[2], claimed)
            return claimed
        end
    end

    -- Invalid queue data must not poison the topic or silently disappear.
    redis.call('RPUSH', KEYS[3], raw)
end
"""

_RENEW_LEASE_SCRIPT = """-- kp_queue_renew_lease_v1
-- Extend a claim's lease, fenced to the presenting owner. A renewal from a
-- stale owner (the claim was already recovered and re-owned) finds no match
-- and is refused, so a zombie handler cannot keep a message it no longer owns.
local items = redis.call('LRANGE', KEYS[1], 0, -1)
for _, raw in ipairs(items) do
    local ok, message = pcall(cjson.decode, raw)
    if ok
        and type(message) == 'table'
        and message['id'] == ARGV[1]
        and message['owner'] == ARGV[2]
    then
        message['lease_deadline'] = tonumber(ARGV[3])
        local encoded = cjson.encode(message)
        redis.call('LREM', KEYS[1], 1, raw)
        redis.call('LPUSH', KEYS[1], encoded)
        return encoded
    end
end
return nil
"""

_MOVE_IF_PRESENT_SCRIPT = """-- kp_queue_move_if_present_v1
if redis.call('LREM', KEYS[1], 1, ARGV[1]) == 0 then
    return 0
end
redis.call('RPUSH', KEYS[2], ARGV[2])
return 1
"""

_PUBLISH_ONCE_SCRIPT = """-- kp_queue_publish_once_v1
if redis.call('SET', KEYS[1], ARGV[5], 'NX', 'EX', ARGV[2]) == false then
    return redis.call('GET', KEYS[1])
end
if ARGV[3] == 'delayed' then
    redis.call('ZADD', KEYS[2], ARGV[4], ARGV[1])
else
    redis.call('RPUSH', KEYS[2], ARGV[1])
end
return ARGV[5]
"""

_REPLAY_DLQ_SCRIPT = """-- kp_queue_replay_dlq_v1
local values = redis.call('LRANGE', KEYS[1], 0, tonumber(ARGV[2]) - 1)
for _, raw in ipairs(values) do
    local decoded, message = pcall(cjson.decode, raw)
    if decoded
        and type(message) == 'table'
        and message['id'] == ARGV[1]
        and type(message['idempotency_key']) == 'string'
        and type(message['payload']) == 'table'
    then
        if redis.call('LREM', KEYS[1], 1, raw) == 0 then
            return nil
        end
        message['retry'] = 0
        message['replay_count'] = (tonumber(message['replay_count']) or 0) + 1
        message['replayed_at'] = tonumber(ARGV[3])
        message['dead_lettered_at'] = nil
        message['started_at'] = nil
        local encoded = cjson.encode(message)
        redis.call('RPUSH', KEYS[2], encoded)
        return encoded
    end
end
return nil
"""

_POLL_INTERVAL_SECONDS = 0.05
_MAX_DLQ_SCAN = 10_000

#: Fallback visibility lease applied to a claim when a caller does not pass an
#: explicit ``lease_seconds``. The supervisor derives a per-role lease from the
#: role's enforced handler deadline (``WorkerSettings.effective_lease_seconds``)
#: and passes it to ``pop``; this constant only covers direct/ad-hoc callers.
DEFAULT_LEASE_SECONDS = 60

#: Topics whose jobs perform an externally-visible send whose provider
#: acceptance is unknown after a Redis data loss. A queue<->outbox reconciliation
#: (KP-AUD-007) must NEVER auto re-enqueue these — doing so could re-send an
#: employee a duplicate simulated-phishing email. They are surfaced for human
#: review instead. Every other topic (reminder/alert and internal maintenance
#: roles) is safe to re-enqueue because its handler is idempotent by
#: idempotency key / training token. The consuming worker, which knows its own
#: topic, decides ``replay_safe`` and passes it to the reconciler.
QUEUE_REPLAY_REVIEW_ONLY_TOPICS = frozenset({"deliver", "reply-mailbox"})

# Fixed operational topics prevent an API caller from turning a topic name into
# an arbitrary Redis key. Keep this aligned with the worker role registry.
DEFAULT_QUEUE_TOPICS = (
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
)

#: Fixed Redis key holding the ISO-8601 UTC time of the last successful audit
#: anchor. Deliberately outside the ``kp:queue:`` namespace: it is a witness
#: freshness heartbeat, not a queue topic (AUD-003).
AUDIT_ANCHOR_HEARTBEAT_KEY = "kp:audit:last_successful_anchor_at"


class JobQueue:
    def __init__(
        self,
        redis_url: str,
        *,
        prefix: str = "kp:queue:",
        max_message_bytes: int = 1_000_000,
        default_lease_seconds: int = DEFAULT_LEASE_SECONDS,
    ) -> None:
        self._client = redis.Redis.from_url(redis_url, decode_responses=True)
        self._prefix = prefix
        self._max_message_bytes = max_message_bytes
        self._default_lease_seconds = default_lease_seconds

    def _topic(self, topic: str) -> str:
        # Every atomic transition touches multiple keys.  Azure Managed Redis
        # runs with OSS Cluster enabled, so all keys for one topic must carry
        # the same hash tag or EVAL fails with CROSSSLOT even on an otherwise
        # valid deployment.
        return self._prefix + "{" + topic + "}"

    def _processing(self, topic: str) -> str:
        return self._topic(topic) + ":processing"

    def _dlq(self, topic: str) -> str:
        return self._topic(topic) + ":dlq"

    def _delayed(self, topic: str) -> str:
        return self._topic(topic) + ":delayed"

    def _fence(self, topic: str) -> str:
        # Monotonic per-topic counter backing each claim's fencing token. Shares
        # the topic hash tag so the claim script's INCR never crosses a slot.
        return self._topic(topic) + ":fence"

    def _published(self, topic: str, idempotency_key: str) -> str:
        digest = uuid.uuid5(uuid.NAMESPACE_URL, idempotency_key).hex
        return self._topic(topic) + ":published:" + digest

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
            "published_at": time.time(),
            "payload": payload,
        }
        encoded = json.dumps(message)
        if len(encoded.encode("utf-8")) > self._max_message_bytes:
            raise ValueError("queue message exceeds maximum size")
        delayed = available_at is not None and available_at > time.time()
        published_id = self._client.eval(
            _PUBLISH_ONCE_SCRIPT,
            2,
            self._published(topic, message["idempotency_key"]),
            self._delayed(topic) if delayed else self._topic(topic),
            encoded,
            90 * 24 * 60 * 60,
            "delayed" if delayed else "ready",
            available_at or 0,
            job_id,
        )
        # Pre-upgrade dedup keys held the whole encoded envelope. Accept those
        # during their bounded TTL while new keys retain only the non-secret ID.
        published = self._as_str(cast(bytes | str, published_id))
        if published.startswith("{"):
            existing = json.loads(published)
            return str(existing["id"])
        return published

    def _promote_due(self, topic: str) -> None:
        """Move due delayed jobs into the ready list before a blocking pop."""
        self._client.eval(
            _PROMOTE_DUE_SCRIPT,
            2,
            self._delayed(topic),
            self._topic(topic),
            time.time(),
            100,
        )

    def pop(
        self,
        topic: str,
        *,
        timeout: int = 5,
        owner: str | None = None,
        lease_seconds: float | None = None,
    ) -> dict[str, Any] | None:
        """Claim the next ready message, stamping an owner + fencing token + lease.

        ``lease_seconds`` is the window the claim is protected from recovery; the
        supervisor passes the role's enforced handler deadline so a slow but
        healthy handler is never recovered early. ``owner`` defaults to a fresh
        UUID per claim and is what fences a stale handler out of ack/reject/renew.
        """
        wait_seconds = max(0, timeout)
        deadline = time.monotonic() + wait_seconds
        owner_token = owner or str(uuid.uuid4())
        lease = self._default_lease_seconds if lease_seconds is None else lease_seconds
        while True:
            try:
                self._promote_due(topic)
                raw = self._client.eval(
                    _CLAIM_SCRIPT,
                    4,
                    self._topic(topic),
                    self._processing(topic),
                    self._dlq(topic),
                    self._fence(topic),
                    time.time(),
                    owner_token,
                    lease,
                )
            except redis.TimeoutError:
                # A client-side Redis deadline while idle is a normal poll.
                return None
            if raw is not None:
                raw_str = self._as_str(cast(bytes | str, raw))
                message = cast(dict[str, Any], json.loads(raw_str))
                message["_raw"] = raw_str
                return message
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            time.sleep(min(_POLL_INTERVAL_SECONDS, remaining))

    def renew_lease(self, topic: str, message: dict[str, Any], *, lease_seconds: float) -> bool:
        """Extend an in-flight claim's lease for its current owner only.

        Returns ``True`` when the lease was extended. Returns ``False`` when the
        claim is no longer owned by this caller (already recovered/re-owned, or
        acked), which is the fence that stops a zombie handler from holding a
        message another worker now owns. On success the passed ``message`` dict
        is updated in place so a subsequent ``ack``/``reject`` matches.
        """
        job_id = message.get("id")
        owner = message.get("owner")
        if not isinstance(job_id, str) or not isinstance(owner, str):
            return False
        new_deadline = time.time() + float(lease_seconds)
        raw = self._client.eval(
            _RENEW_LEASE_SCRIPT,
            1,
            self._processing(topic),
            job_id,
            owner,
            new_deadline,
        )
        if raw is None:
            return False
        raw_str = self._as_str(cast(bytes | str, raw))
        message["_raw"] = raw_str
        message["lease_deadline"] = new_deadline
        return True

    def ack(self, topic: str, message: dict[str, Any]) -> None:
        raw = message.get("_raw")
        if raw is not None:
            self._client.lrem(self._processing(topic), 1, self._as_str(raw))

    def reject(self, topic: str, message: dict[str, Any], *, max_retries: int = 3) -> None:
        raw = message.get("_raw")
        if raw is None:
            logger.warning("cannot reject unclaimed message %s", message.get("id"))
            return
        queued_message = {key: value for key, value in message.items() if key != "_raw"}
        retries = int(queued_message.get("retry", 0)) + 1
        queued_message["retry"] = retries
        # Drop per-claim lease state so the next claim re-stamps a fresh owner,
        # fencing token and lease deadline.
        for lease_field in ("started_at", "owner", "fence", "lease_deadline"):
            queued_message.pop(lease_field, None)
        destination = self._topic(topic) if retries < max_retries else self._dlq(topic)
        if retries >= max_retries:
            queued_message["dead_lettered_at"] = time.time()
        moved = self._client.eval(
            _MOVE_IF_PRESENT_SCRIPT,
            2,
            self._processing(topic),
            destination,
            self._as_str(cast(bytes | str, raw)),
            json.dumps(queued_message),
        )
        if moved and retries >= max_retries:
            # The destination envelope is constructed before the move so the
            # timestamp must be included in the atomically inserted value.
            logger.error("message %s exhausted %d retries; moving to DLQ", message.get("id"), max_retries)

    @staticmethod
    def _claim_expired(message: dict[str, Any], *, now: float, visibility_seconds: int) -> bool:
        """Whether a processing claim's lease has genuinely expired.

        Authoritative signal is ``lease_deadline``. ``started_at`` + visibility is
        only a fallback for pre-upgrade envelopes with no lease. A missing or
        unparseable timestamp fails safe to expired (an un-leasable claim must be
        recoverable), while a live lease short-circuits recovery.
        """
        deadline = message.get("lease_deadline")
        if deadline is not None:
            try:
                return now > float(deadline)
            except (TypeError, ValueError):
                return True
        started = message.get("started_at")
        try:
            return started is None or now - float(started) > visibility_seconds
        except (TypeError, ValueError):
            return True

    def job_published(self, topic: str, idempotency_key: str) -> bool:
        """Whether Redis still holds the publish marker for an idempotency key.

        The ``:published:`` dedup key is written at publish with a bounded TTL and
        survives acknowledgement, so its presence means Redis has not lost its
        memory of this job (it is either still queued or was consumed). Its
        absence after a durable outbox row was marked ``dispatched`` means Redis
        lost the job (data loss) — the exact signal the KP-AUD-007 reconciliation
        acts on. This performs no claim and mutates nothing.
        """
        return bool(self._client.exists(self._published(topic, idempotency_key)))

    def recover_stale(self, topic: str, *, visibility_seconds: int = 60, max_retries: int = 3) -> int:
        """Re-queue ONLY genuinely-expired claims left in :processing.

        A claim is expired when its ``lease_deadline`` (stamped at ``pop`` and
        extended by ``renew_lease`` heartbeats) is in the past. A slow but
        healthy handler whose lease is being renewed is therefore never
        recovered, which is what closes the KP-AUD-006 early-recovery /
        double-processing gap. ``visibility_seconds`` is only a backward-compat
        fallback for pre-upgrade envelopes that carry ``started_at`` but no
        ``lease_deadline``. Handles a worker that died between pop and ack.
        Returns the number of messages recovered.
        """
        now = time.time()
        recovered = 0
        for raw in self._client.lrange(self._processing(topic), 0, -1):
            raw_str = self._as_str(raw)
            try:
                decoded = json.loads(raw_str)
                if not isinstance(decoded, dict):
                    raise ValueError("queue message must be an object")
                message = cast(dict[str, Any], decoded)
            except (json.JSONDecodeError, ValueError):
                # Preserve corrupt queue data for operator inspection.
                self._client.eval(
                    _MOVE_IF_PRESENT_SCRIPT,
                    2,
                    self._processing(topic),
                    self._dlq(topic),
                    raw_str,
                    raw_str,
                )
                continue
            if not self._claim_expired(message, now=now, visibility_seconds=visibility_seconds):
                continue
            retries = int(message.get("retry", 0)) + 1
            message["retry"] = retries
            for lease_field in ("started_at", "owner", "fence", "lease_deadline"):
                message.pop(lease_field, None)
            destination = self._topic(topic) if retries < max_retries else self._dlq(topic)
            if retries >= max_retries:
                message["dead_lettered_at"] = now
            moved = self._client.eval(
                _MOVE_IF_PRESENT_SCRIPT,
                2,
                self._processing(topic),
                destination,
                raw_str,
                json.dumps(message),
            )
            if moved and retries >= max_retries:
                logger.error("stale message %s exhausted retries; moving to DLQ", message.get("id"))
            recovered += int(moved)
        return recovered

    @staticmethod
    def _dead_letter_reference(raw: str, message: dict[str, Any] | None) -> str:
        job_id = message.get("id") if message is not None else None
        if isinstance(job_id, str) and job_id:
            return job_id
        return "malformed-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]

    def _decode_dead_letter(self, topic: str, raw: bytes | str) -> dict[str, Any]:
        raw_str = self._as_str(raw)
        message: dict[str, Any] | None = None
        try:
            candidate = json.loads(raw_str)
            if isinstance(candidate, dict):
                message = cast(dict[str, Any], candidate)
        except json.JSONDecodeError:
            pass
        valid = bool(
            message is not None
            and isinstance(message.get("id"), str)
            and isinstance(message.get("idempotency_key"), str)
            and isinstance(message.get("retry"), int | float)
            and isinstance(message.get("payload"), dict)
        )
        valid_message = message if valid else None
        reference = self._dead_letter_reference(raw_str, valid_message)
        return {
            "topic": topic,
            "reference": reference,
            "malformed": not valid,
            "message": valid_message,
        }

    def list_dead_letters(self, topic: str, *, offset: int = 0, limit: int = 100) -> list[dict[str, Any]]:
        """Return a bounded DLQ page; callers must redact message payloads."""
        if offset < 0 or limit < 1 or limit > 500:
            raise ValueError("DLQ pagination is out of range")
        stop = offset + limit - 1
        return [self._decode_dead_letter(topic, raw) for raw in self._client.lrange(self._dlq(topic), offset, stop)]

    def dead_letter_count(self, topic: str) -> int:
        return int(self._client.llen(self._dlq(topic)))

    def get_dead_letter(self, topic: str, reference: str) -> dict[str, Any] | None:
        """Find a bounded DLQ item by stable job ID or malformed-data digest."""
        for raw in self._client.lrange(self._dlq(topic), 0, _MAX_DLQ_SCAN - 1):
            decoded = self._decode_dead_letter(topic, raw)
            if decoded["reference"] == reference:
                return decoded
        return None

    def replay_dead_letter(self, topic: str, reference: str) -> dict[str, Any] | None:
        """Atomically move one valid DLQ envelope back to the ready queue.

        Concurrent duplicate replay requests are idempotent: only the request
        that removes the exact DLQ value can enqueue it. Corrupt values remain
        quarantined because replaying one would immediately poison the topic.
        """
        if reference.startswith("malformed-"):
            raise ValueError("malformed dead-letter messages cannot be replayed")
        raw = self._client.eval(
            _REPLAY_DLQ_SCRIPT,
            2,
            self._dlq(topic),
            self._topic(topic),
            reference,
            _MAX_DLQ_SCAN,
            time.time(),
        )
        if raw is None:
            return None
        message = json.loads(self._as_str(cast(bytes | str, raw)))
        return cast(dict[str, Any], message)

    def queue_stats(self, topic: str) -> dict[str, int | float | None]:
        """Return non-sensitive queue counts and oldest-ready age."""
        ready = int(self._client.llen(self._topic(topic)))
        processing = int(self._client.llen(self._processing(topic)))
        delayed = int(self._client.zcard(self._delayed(topic)))
        dead_letter = int(self._client.llen(self._dlq(topic)))
        oldest_raw = self._client.lindex(self._topic(topic), 0)
        oldest_age: float | None = None
        if oldest_raw is not None:
            try:
                oldest_message = json.loads(self._as_str(oldest_raw))
                published_at = float(oldest_message["published_at"])
                oldest_age = max(0.0, time.time() - published_at)
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                oldest_age = None
        return {
            "ready": ready,
            "processing": processing,
            "delayed": delayed,
            "dead_letter": dead_letter,
            "oldest_ready_age_seconds": oldest_age,
        }

    def record_audit_anchor_heartbeat(self, when: datetime) -> None:
        """Record the wall-clock time of the most recent successful audit anchor.

        This is a freshness signal only — the durable, tamper-evident witness is
        the anchor object itself (Azure Blob or local WORM). It lets the operator
        API detect a *stalled* anchor worker without any new Azure access: the
        anchor worker (SELECT-only on the audit DB) and the operator API already
        share Redis. Stored on a fixed, non-topic key as an ISO-8601 UTC string.
        """
        self._client.set(AUDIT_ANCHOR_HEARTBEAT_KEY, when.astimezone(UTC).isoformat())

    def read_audit_anchor_heartbeat(self) -> datetime | None:
        """Return the last successful anchor time, or ``None`` when never recorded.

        Returns ``None`` for an absent or unparseable/naive value (callers fail
        OPEN on absence — a fresh or just-restarted stack must not be blocked).
        Redis connectivity errors propagate so callers can distinguish a blip
        (fail open) from a genuinely stale timestamp (fail closed).
        """
        raw = self._client.get(AUDIT_ANCHOR_HEARTBEAT_KEY)
        if raw is None:
            return None
        try:
            parsed = datetime.fromisoformat(self._as_str(raw))
        except (ValueError, TypeError):
            return None
        if parsed.tzinfo is None:
            return None
        return parsed

    def close(self) -> None:
        self._client.close()
