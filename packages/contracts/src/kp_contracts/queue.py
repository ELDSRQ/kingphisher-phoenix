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
- ``ack`` removes a successfully processed message from ``:processing`` by its
  stable job, owner and fence identity. A lost lease-renewal reply cannot prevent
  completion, while an ack issued by a stale owner/fence removes nothing.
- ``reject`` returns a failed message to the queue with an incremented retry
  counter; messages that exhaust their retries land on ``kp:queue:dlq:<topic>``.
  It uses the same claim identity as ``ack`` and the current stored envelope.
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

_RENEW_LEASE_SCRIPT = """-- kp_queue_renew_lease_v2
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
        and message['fence'] == tonumber(ARGV[3])
    then
        message['lease_deadline'] = tonumber(ARGV[4])
        local encoded = cjson.encode(message)
        redis.call('LREM', KEYS[1], 1, raw)
        redis.call('LPUSH', KEYS[1], encoded)
        return encoded
    end
end
return nil
"""

_ACK_CLAIM_SCRIPT = """-- kp_queue_ack_claim_v1
for _, raw in ipairs(redis.call('LRANGE', KEYS[1], 0, -1)) do
    local ok, message = pcall(cjson.decode, raw)
    if ok and type(message) == 'table'
        and message['id'] == ARGV[1]
        and message['owner'] == ARGV[2]
        and message['fence'] == tonumber(ARGV[3])
    then
        return redis.call('LREM', KEYS[1], 1, raw)
    end
end
return 0
"""

_REJECT_CLAIM_SCRIPT = """-- kp_queue_reject_claim_v1
for _, raw in ipairs(redis.call('LRANGE', KEYS[1], 0, -1)) do
    local ok, message = pcall(cjson.decode, raw)
    if ok and type(message) == 'table'
        and message['id'] == ARGV[1]
        and message['owner'] == ARGV[2]
        and message['fence'] == tonumber(ARGV[3])
    then
        -- Read retry/payload from Redis, not a possibly stale caller envelope.
        local retries = tonumber(message['retry']) + 1
        message['retry'] = retries
        message['started_at'] = nil
        message['owner'] = nil
        message['fence'] = nil
        message['lease_deadline'] = nil
        local exhausted = retries >= tonumber(ARGV[4])
        if exhausted then message['dead_lettered_at'] = tonumber(ARGV[5]) end
        -- Redis does not roll back earlier script writes on an encoding error.
        -- Encode first so failure leaves the original claim recoverable.
        local encoded_ok, encoded = pcall(cjson.encode, message)
        if not encoded_ok then return 0 end
        if redis.call('LREM', KEYS[1], 1, raw) == 0 then return 0 end
        redis.call('RPUSH', exhausted and KEYS[3] or KEYS[2], encoded)
        return exhausted and 2 or 1
    end
end
return 0
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

#: Redis remembers consumed job IDs for this long after initial publication.
#: Reconciliation must search a strictly shorter window, or an expired marker
#: could be mistaken for Redis data loss and cause a completed job to run again.
QUEUE_PUBLISH_DEDUP_TTL_SECONDS = 90 * 24 * 60 * 60
MAX_QUEUE_RECONCILE_WINDOW_HOURS = 89 * 24

#: Explicitly audited replay-safe handlers. Unknown/future topics fail closed.
#: Reminders persist their no-retry follow-up claim before transport; alerts
#: have no equivalent durable send claim and therefore require human review.
QUEUE_REPLAY_SAFE_TOPICS = frozenset(
    {"audit-anchor", "ingest", "generate", "retention", "mailbox", "remind", "directory", "curate"}
)
#: Retained for consumers presenting the known review-only topics. Automatic
#: replay authority comes ONLY from membership in QUEUE_REPLAY_SAFE_TOPICS.
QUEUE_REPLAY_REVIEW_ONLY_TOPICS = frozenset({"deliver", "reply-mailbox", "alert"})

#: Default per-topic READY-depth budget for NON-critical topics (KP-AUD-024
#: producer backpressure). When a topic's ready list already holds this many
#: messages, ``publish`` fails fast with ``QueueOverflowError`` instead of
#: growing the queue without bound. Deliberately generous and opinionated: it
#: exists to stop a runaway producer, not to pace normal load, and adds no
#: autoscaling or new infrastructure (the audit's explicit scope caution).
#: Override per deployment via the ``ready_depth_budget`` constructor argument;
#: ``None`` disables the budget (unbounded) and is a development-only relaxation.
DEFAULT_READY_DEPTH_BUDGET = 10_000

#: Default age (seconds) at which a topic's oldest ready job is REPORTED
#: unhealthy by ``queue_stats`` so the existing health surface can alert. Age is
#: observable, never enforced — nothing is shed because a job is old; only depth
#: applies backpressure. Mirrors the operator health dashboard's warn threshold.
DEFAULT_OLDEST_READY_AGE_BUDGET_SECONDS = 15 * 60.0

#: Topics whose work must never be shed by producer backpressure (KP-AUD-024
#: critical-role isolation): a flooded non-critical topic (``generate`` /
#: ``ingest`` / ...) can never fail-fast a retention, delivery, or audit-anchor
#: publish. These carry their own budget (``critical_ready_depth_budget``,
#: unbounded by default), so retention/delivery/audit work is isolated from a
#: non-critical flood. Keep this set explicit and aligned with the audit finding.
CRITICAL_QUEUE_TOPICS = frozenset({"deliver", "retention", "audit-anchor"})


class QueueOverflowError(RuntimeError):
    """Producer backpressure: a topic's ready depth is at/over its budget.

    Raised by ``publish`` so a runaway producer fails fast — its durable outbox
    row stays pending and is retried later (``TransactionalOutbox`` catches this
    and re-schedules the row) — instead of growing the ready list without bound.
    Never raised for a critical topic, whose work must not be shed. Lives in the
    queue module (which already raises plain errors for a rejected publish)
    rather than ``kp_telemetry`` so ``kp_contracts`` gains no new dependency.
    """

    def __init__(self, topic: str, *, depth: int, budget: int) -> None:
        self.topic = topic
        self.depth = depth
        self.budget = budget
        super().__init__(
            f"queue topic {topic!r} is at capacity: ready depth {depth} >= budget {budget}; publish refused"
        )


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
        ready_depth_budget: int | None = DEFAULT_READY_DEPTH_BUDGET,
        critical_ready_depth_budget: int | None = None,
        oldest_ready_age_budget_seconds: float | None = DEFAULT_OLDEST_READY_AGE_BUDGET_SECONDS,
        critical_topics: frozenset[str] = CRITICAL_QUEUE_TOPICS,
    ) -> None:
        self._client = redis.Redis.from_url(redis_url, decode_responses=True)
        self._prefix = prefix
        self._max_message_bytes = max_message_bytes
        self._default_lease_seconds = default_lease_seconds
        # KP-AUD-024 bounded overload budgets. ``None`` means unbounded (no
        # backpressure); critical topics default to unbounded so a non-critical
        # flood can never shed their work. These are opinionated application
        # defaults, overridable by the caller / managed config.
        self._ready_depth_budget = ready_depth_budget
        self._critical_ready_depth_budget = critical_ready_depth_budget
        self._oldest_ready_age_budget_seconds = oldest_ready_age_budget_seconds
        self._critical_topics = critical_topics

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

    def _depth_budget(self, topic: str) -> int | None:
        """Resolve a topic's READY-depth budget (``None`` = unbounded).

        Critical topics (delivery / retention / audit-anchor) use their own
        budget — unbounded by default — so a flooded non-critical topic can
        never fail-fast their work (KP-AUD-024 critical-role isolation). Every
        other topic uses the shared non-critical budget.
        """
        if topic in self._critical_topics:
            return self._critical_ready_depth_budget
        return self._ready_depth_budget

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
        # KP-AUD-024 producer backpressure: refuse an immediate enqueue when the
        # topic's ready list is already at/over its depth budget, instead of
        # growing it without bound. Read the depth cheaply with LLEN (no scan).
        # Delayed publishes target the scheduled ZSET, not the ready list, so
        # they do not add to ready depth and are not subject to this check; the
        # per-pop promotion LIMIT already bounds how fast they become ready.
        # (N7: the operator API builds its own JobQueue on these safe defaults
        # and only ever publishes to the critical/unbounded "deliver" topic, so
        # it never fails fast and needs no explicit budget wiring.)
        budget = None if delayed else self._depth_budget(topic)
        # N5: only a genuinely NEW job can grow the ready list. An idempotent
        # re-publish whose dedup marker already exists (e.g. an outbox retry of a
        # job that is already enqueued) adds no depth — the dedup script below
        # returns its existing id — so it must NOT be failed fast, otherwise the
        # outbox would re-try it every cycle while depth stays high. Skip the
        # backpressure check when the marker is present. The LLEN/push gap is
        # accepted: minor over-admission under concurrent producers is fine for
        # backpressure.
        if budget is not None and not self._client.exists(self._published(topic, message["idempotency_key"])):
            ready_depth = int(self._client.llen(self._topic(topic)))
            if ready_depth >= budget:
                raise QueueOverflowError(topic, depth=ready_depth, budget=budget)
        published_id = self._client.eval(
            _PUBLISH_ONCE_SCRIPT,
            2,
            self._published(topic, message["idempotency_key"]),
            self._delayed(topic) if delayed else self._topic(topic),
            encoded,
            QUEUE_PUBLISH_DEDUP_TTL_SECONDS,
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
        receives refreshed lease metadata. Finalization uses the stable claim
        identity even when this renewal reply is lost after Redis applied it.
        """
        identity = self._claim_identity(message)
        if identity is None:
            return False
        new_deadline = time.time() + float(lease_seconds)
        raw = self._client.eval(
            _RENEW_LEASE_SCRIPT,
            1,
            self._processing(topic),
            *identity,
            new_deadline,
        )
        if raw is None:
            return False
        raw_str = self._as_str(cast(bytes | str, raw))
        message["_raw"] = raw_str
        message["lease_deadline"] = new_deadline
        return True

    @staticmethod
    def _claim_identity(message: dict[str, Any]) -> tuple[str, str, int] | None:
        job_id, owner, fence = (message.get(key) for key in ("id", "owner", "fence"))
        if not isinstance(job_id, str) or not job_id or not isinstance(owner, str) or not owner:
            return None
        if type(fence) is not int or fence < 1:
            return None
        return job_id, owner, fence

    def ack(self, topic: str, message: dict[str, Any]) -> None:
        identity = self._claim_identity(message)
        if identity is not None:
            self._client.eval(_ACK_CLAIM_SCRIPT, 1, self._processing(topic), *identity)

    def reject(self, topic: str, message: dict[str, Any], *, max_retries: int = 3) -> None:
        identity = self._claim_identity(message)
        if identity is None:
            logger.warning("cannot reject unclaimed message %s", message.get("id"))
            return
        moved = self._client.eval(
            _REJECT_CLAIM_SCRIPT,
            3,
            self._processing(topic),
            self._topic(topic),
            self._dlq(topic),
            *identity,
            max_retries,
            time.time(),
        )
        if moved == 2:
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

    def queue_stats(self, topic: str) -> dict[str, int | float | bool | None]:
        """Return non-sensitive queue counts, oldest-ready age, and budget health.

        Beyond the raw counts and oldest-ready age, the stats carry each topic's
        depth and age budgets and whether it is currently over either of them
        (KP-AUD-024 actionable health). A topic with ``healthy`` false is
        over-budget and alertable through the existing health/readiness surface
        that already consumes this contract — no new UI is introduced. Budgets
        are reported as ``None`` when unbounded (e.g. a critical topic's depth).
        """
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
        depth_budget = self._depth_budget(topic)
        age_budget = self._oldest_ready_age_budget_seconds
        over_depth_budget = depth_budget is not None and ready >= depth_budget
        over_age_budget = age_budget is not None and oldest_age is not None and oldest_age > age_budget
        return {
            "ready": ready,
            "processing": processing,
            "delayed": delayed,
            "dead_letter": dead_letter,
            "oldest_ready_age_seconds": oldest_age,
            "ready_depth_budget": depth_budget,
            "oldest_ready_age_budget_seconds": age_budget,
            "critical": topic in self._critical_topics,
            "over_depth_budget": over_depth_budget,
            "over_age_budget": over_age_budget,
            "healthy": not (over_depth_budget or over_age_budget),
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
