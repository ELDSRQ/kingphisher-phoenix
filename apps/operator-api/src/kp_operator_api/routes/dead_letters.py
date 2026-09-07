"""Queue dead-letter inspection and replay routes."""

from __future__ import annotations

import re
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Query, Request, status
from kp_authorization.rbac import Capability, Principal
from kp_contracts.queue import DEFAULT_QUEUE_TOPICS
from kp_database.audit_store import AuditStore
from kp_telemetry.errors import (
    NotFoundError,
    ValidationError_,
)
from pydantic import BaseModel

from kp_operator_api.auth import require_capability
from kp_operator_api.deps import get_audit_store
from kp_operator_api.routes.shared import (
    _allowlisted_validation_message,
)

router = APIRouter(prefix="/api/v1")


class DeadLetterReplay(BaseModel):
    confirm: bool = False


def _queue_topic(topic: str) -> str:
    if topic not in DEFAULT_QUEUE_TOPICS:
        raise ValidationError_("unknown queue topic")
    return topic


_SAFE_QUEUE_PAYLOAD_FIELDS = frozenset(
    {
        "action",
        "campaign_id",
        "pattern_id",
        "preview_id",
        "source_id",
        "retention_policy_id",
    }
)


def _safe_queue_payload(value: Any, *, field: str | None = None) -> Any:
    """Expose enough envelope structure to diagnose a job, never its PII."""
    if isinstance(value, dict):
        safe: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items(), start=1):
            key_text = str(key)
            safe_key = key_text if re.fullmatch(r"[a-z_][a-z0-9_]{0,63}", key_text) else f"redacted_field_{index}"
            safe[safe_key] = _safe_queue_payload(item, field=key_text)
        return safe
    if isinstance(value, list):
        return {"type": "list", "count": len(value)}
    if field in _SAFE_QUEUE_PAYLOAD_FIELDS and isinstance(value, str | int | float | bool | type(None)):
        return value
    return "[redacted]"


def _dead_letter_summary(item: dict[str, Any]) -> dict[str, Any]:
    message = item.get("message")
    if not isinstance(message, dict):
        return {
            "topic": item["topic"],
            "reference": item["reference"],
            "malformed": True,
            "replayable": False,
            "retry": None,
            "dead_lettered_at": None,
            "payload_field_count": 0,
        }
    payload = message.get("payload")
    return {
        "topic": item["topic"],
        "reference": item["reference"],
        "malformed": False,
        "replayable": True,
        "retry": message.get("retry"),
        "dead_lettered_at": message.get("dead_lettered_at"),
        "replay_count": message.get("replay_count", 0),
        "payload_field_count": len(payload) if isinstance(payload, dict) else 0,
    }


def _queue_reference(reference: str) -> str:
    if len(reference) > 128 or re.fullmatch(r"[A-Za-z0-9-]+", reference) is None:
        raise ValidationError_("invalid dead-letter reference")
    return reference


@router.get("/queues/dead-letters", status_code=status.HTTP_200_OK)
def list_dead_letters(
    request: Request,
    topic: str | None = Query(default=None),
    offset: int = Query(default=0, ge=0, le=100_000),
    limit: int = Query(default=100, ge=1, le=500),
    principal: Principal = Depends(require_capability(Capability.MANAGE_QUEUE)),
) -> dict[str, Any]:
    """List bounded, non-sensitive DLQ summaries for the operator console."""
    del principal
    topics = (_queue_topic(topic),) if topic is not None else DEFAULT_QUEUE_TOPICS
    counts = {candidate: request.app.state.queue.dead_letter_count(candidate) for candidate in topics}
    remaining_offset = offset
    remaining_limit = limit
    items: list[dict[str, Any]] = []
    for candidate in topics:
        topic_count = counts[candidate]
        if remaining_offset >= topic_count:
            remaining_offset -= topic_count
            continue
        page = request.app.state.queue.list_dead_letters(
            candidate,
            offset=remaining_offset,
            limit=remaining_limit,
        )
        items.extend(_dead_letter_summary(item) for item in page)
        remaining_limit -= len(page)
        remaining_offset = 0
        if remaining_limit <= 0:
            break
    return {
        "items": items,
        "total": sum(counts.values()),
        "offset": offset,
        "limit": limit,
        "topic_counts": counts,
    }


@router.get("/queues/dead-letters/{topic}/{reference}", status_code=status.HTTP_200_OK)
def inspect_dead_letter(
    topic: str,
    reference: str,
    request: Request,
    principal: Principal = Depends(require_capability(Capability.MANAGE_QUEUE)),
) -> dict[str, Any]:
    """Inspect a DLQ envelope through a PII/secret-redacting projection."""
    del principal
    candidate = request.app.state.queue.get_dead_letter(_queue_topic(topic), _queue_reference(reference))
    if candidate is None:
        raise NotFoundError("dead-letter message not found")
    summary = _dead_letter_summary(candidate)
    message = candidate.get("message")
    if not isinstance(message, dict):
        return {**summary, "payload": None}
    return {
        **summary,
        "published_at": message.get("published_at"),
        "replayed_at": message.get("replayed_at"),
        "payload": _safe_queue_payload(message.get("payload", {})),
    }


@router.post("/queues/dead-letters/{topic}/{reference}/replay", status_code=status.HTTP_202_ACCEPTED)
def replay_dead_letter(
    topic: str,
    reference: str,
    body: DeadLetterReplay,
    request: Request,
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_QUEUE)),
) -> dict[str, Any]:
    """Audit, then atomically replay exactly one valid dead-letter envelope."""
    if not body.confirm:
        raise ValidationError_("dead-letter replay requires explicit confirmation")
    safe_topic = _queue_topic(topic)
    safe_reference = _queue_reference(reference)
    # The audit intent is durable before Redis is mutated. This can leave an
    # auditable attempted replay when another operator wins the race, but can
    # never leave an unaudited successful replay.
    audit.record(
        actor=principal.principal_id,
        action="queue.dead-letter.replay.request",
        object_type="queue_message",
        object_id=f"{safe_topic}:{safe_reference}",
        detail={"topic": safe_topic, "confirmed": True},
        idempotency_key=f"dlq-replay-request:{safe_topic}:{safe_reference}:{uuid.uuid4()}",
    )
    try:
        replayed = request.app.state.queue.replay_dead_letter(safe_topic, safe_reference)
    except ValueError as exc:
        raise ValidationError_(
            _allowlisted_validation_message(
                exc,
                allowed=frozenset({"malformed dead-letter messages cannot be replayed"}),
                fallback="dead-letter message cannot be replayed",
            )
        ) from exc
    if replayed is None:
        raise NotFoundError("dead-letter message was already replayed or is no longer available")
    return {
        "queued": True,
        "topic": safe_topic,
        "reference": safe_reference,
        "replay_count": replayed.get("replay_count", 1),
    }
