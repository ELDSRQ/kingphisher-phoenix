"""Operator DLQ workflow: bounded metadata, redacted inspect, audited replay."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest
from fastapi import Request
from kp_authorization.rbac import Capability, Principal, Role
from kp_operator_api.routers import (
    DeadLetterReplay,
    inspect_dead_letter,
    list_dead_letters,
    replay_dead_letter,
)
from kp_telemetry.errors import ValidationError_


class _Queue:
    def __init__(self) -> None:
        self.events: list[str] = []
        self.item = {
            "topic": "deliver",
            "reference": "job-1",
            "malformed": False,
            "message": {
                "id": "job-1",
                "retry": 3,
                "published_at": 10.0,
                "dead_lettered_at": 20.0,
                "payload": {
                    "campaign_id": "campaign-1",
                    "mailbox": "target@example.com",
                    "tracking_token": "super-secret",
                    "target@example.com": "dynamic-key-secret",
                    "assignment_ids": ["personal-1", "personal-2"],
                },
            },
        }
        self.available = True

    def dead_letter_count(self, topic: str) -> int:
        return 1 if topic == "deliver" and self.available else 0

    def list_dead_letters(self, topic: str, *, offset: int, limit: int) -> list[dict[str, Any]]:
        if topic == "deliver" and self.available and offset == 0 and limit:
            return [self.item]
        return []

    def get_dead_letter(self, topic: str, reference: str) -> dict[str, Any] | None:
        if topic == "deliver" and reference == "job-1" and self.available:
            return self.item
        return None

    def replay_dead_letter(self, topic: str, reference: str) -> dict[str, Any] | None:
        self.events.append("queue")
        if topic != "deliver" or reference != "job-1" or not self.available:
            return None
        self.available = False
        return {"id": reference, "replay_count": 1}


class _Audit:
    def __init__(self, queue: _Queue) -> None:
        self.queue = queue
        self.calls: list[dict[str, Any]] = []

    def record(self, **kwargs: Any) -> None:
        self.queue.events.append("audit")
        self.calls.append(kwargs)


def _request(queue: _Queue) -> Request:
    return cast(Request, SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(queue=queue))))


def _operator() -> Principal:
    return Principal("operator-1", {Role.CAMPAIGN_OPERATOR})


def test_queue_management_is_not_granted_to_read_only_roles() -> None:
    assert _operator().can(Capability.MANAGE_QUEUE)
    assert Principal("admin-1", {Role.ADMINISTRATOR}).can(Capability.MANAGE_QUEUE)
    assert not Principal("auditor-1", {Role.AUDITOR}).can(Capability.MANAGE_QUEUE)
    assert not Principal("author-1", {Role.CAMPAIGN_AUTHOR}).can(Capability.MANAGE_QUEUE)


def test_list_exposes_only_non_sensitive_summary() -> None:
    queue = _Queue()
    result = list_dead_letters(_request(queue), topic=None, offset=0, limit=100, principal=_operator())
    assert result["total"] == 1
    assert result["items"] == [
        {
            "topic": "deliver",
            "reference": "job-1",
            "malformed": False,
            "replayable": True,
            "retry": 3,
            "dead_lettered_at": 20.0,
            "replay_count": 0,
            "payload_field_count": 5,
        }
    ]
    rendered = repr(result)
    assert "target@example.com" not in rendered
    assert "super-secret" not in rendered


def test_inspect_redacts_pii_secrets_lists_and_dynamic_keys() -> None:
    queue = _Queue()
    result = inspect_dead_letter("deliver", "job-1", _request(queue), principal=_operator())
    assert result["payload"]["campaign_id"] == "campaign-1"
    assert result["payload"]["mailbox"] == "[redacted]"
    assert result["payload"]["tracking_token"] == "[redacted]"
    assert result["payload"]["assignment_ids"] == {"type": "list", "count": 2}
    rendered = repr(result)
    assert "target@example.com" not in rendered
    assert "super-secret" not in rendered
    assert "dynamic-key-secret" not in rendered


def test_replay_requires_confirmation_and_audits_before_atomic_move() -> None:
    queue = _Queue()
    audit = _Audit(queue)
    with pytest.raises(ValidationError_, match="explicit confirmation"):
        replay_dead_letter(
            "deliver",
            "job-1",
            DeadLetterReplay(confirm=False),
            _request(queue),
            audit=cast(Any, audit),
            principal=_operator(),
        )
    assert queue.events == []

    result = replay_dead_letter(
        "deliver",
        "job-1",
        DeadLetterReplay(confirm=True),
        _request(queue),
        audit=cast(Any, audit),
        principal=_operator(),
    )
    assert result == {"queued": True, "topic": "deliver", "reference": "job-1", "replay_count": 1}
    assert queue.events == ["audit", "queue"]
    assert audit.calls[0]["action"] == "queue.dead-letter.replay.request"
    assert "payload" not in audit.calls[0]["detail"]


@pytest.mark.parametrize(
    ("backend_message", "public_message"),
    [
        ("malformed dead-letter messages cannot be replayed", "malformed dead-letter messages cannot be replayed"),
        ("password=must-not-log rediss://internal/private key=secret", "dead-letter message cannot be replayed"),
    ],
)
def test_replay_validation_uses_only_allowlisted_feedback(
    backend_message: str,
    public_message: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    class _FailingQueue(_Queue):
        def replay_dead_letter(self, topic: str, reference: str) -> dict[str, Any] | None:
            del topic, reference
            raise ValueError(backend_message)

    queue = _FailingQueue()
    with pytest.raises(ValidationError_) as captured:
        replay_dead_letter(
            "deliver",
            "job-1",
            DeadLetterReplay(confirm=True),
            _request(queue),
            audit=cast(Any, _Audit(queue)),
            principal=_operator(),
        )

    assert captured.value.message == public_message
    rendered = f"{captured.value.message}\n{caplog.text}"
    assert "password=must-not-log" not in rendered
    assert "rediss://" not in rendered
    assert "key=secret" not in rendered
    assert "Traceback" not in rendered


@pytest.mark.parametrize("topic", ["../../other", "unknown", "deliver"])
def test_invalid_topic_or_reference_fails_closed(topic: str) -> None:
    queue = _Queue()
    if topic == "deliver":
        with pytest.raises(ValidationError_, match="reference"):
            inspect_dead_letter(topic, "bad/reference", _request(queue), principal=_operator())
    else:
        with pytest.raises(ValidationError_, match="topic"):
            inspect_dead_letter(topic, "job-1", _request(queue), principal=_operator())
