from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from kp_authorization.rbac import Principal, Role
from kp_domain_models import models as dm
from kp_operator_api.routers import _campaign_report, queue_training_reminders
from kp_telemetry.errors import ConflictError


class _SequenceSession:
    def __init__(self, *, campaign: object | None = None, scalar_sets: list[list[Any]] | None = None) -> None:
        self.campaign = campaign
        self.scalar_sets = scalar_sets or []
        self.executions: list[tuple[object, dict[str, Any]]] = []
        self.committed = False

    def get(self, model: object, identifier: object) -> object | None:
        return self.campaign

    def scalars(self, statement: object) -> list[Any]:
        return self.scalar_sets.pop(0)

    def scalar(self, statement: object) -> object | None:
        return None

    def execute(self, statement: object, parameters: dict[str, Any]) -> None:
        self.executions.append((statement, parameters))

    def commit(self) -> None:
        self.committed = True


class _Queue:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any], str]] = []

    def publish(self, topic: str, payload: dict[str, Any], *, idempotency_key: str) -> str:
        self.calls.append((topic, payload, idempotency_key))
        return "job-id"


class _Audit:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def record(self, **kwargs: Any) -> None:
        self.records.append(kwargs)


def _campaign(state: dm.CampaignState = dm.CampaignState.ACTIVE) -> SimpleNamespace:
    return SimpleNamespace(
        campaign_id=uuid.uuid4(),
        title="Awareness",
        state=state,
        schedule_start=None,
        schedule_end=None,
        sender_mailbox="security@example.com",
        sender_display_name="Security",
    )


def test_campaign_report_exposes_all_derived_training_states() -> None:
    campaign = _campaign()
    now = datetime.now(UTC)

    def training(*, opened: bool = False, completed: bool = False, overdue: bool = False) -> SimpleNamespace:
        assigned = now - timedelta(days=4 if overdue else 1)
        return SimpleNamespace(
            assigned_at=assigned,
            due_at=assigned + timedelta(days=3),
            opened_at=assigned + timedelta(hours=1) if opened or completed else None,
            completed_at=assigned + timedelta(hours=2) if completed else None,
        )

    session = _SequenceSession(
        scalar_sets=[
            [],
            [],
            [training(), training(opened=True), training(overdue=True), training(completed=True)],
            [],
        ]
    )

    report = _campaign_report(session, campaign)  # type: ignore[arg-type]

    assert report["training"] == {"total": 4, "assigned": 1, "opened": 1, "completed": 1, "overdue": 1}
    assert report["rates"]["training_completed"] == 0.25


def test_operator_can_queue_due_training_reminders_without_pii() -> None:
    campaign = _campaign()
    session = _SequenceSession(campaign=campaign, scalar_sets=[[uuid.uuid4(), uuid.uuid4()]])
    queue = _Queue()
    audit = _Audit()
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(queue=queue)))
    principal = Principal("operator-1", {Role.CAMPAIGN_OPERATOR})

    result = queue_training_reminders(
        str(campaign.campaign_id),
        request,  # type: ignore[arg-type]
        session=session,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        principal=principal,
    )

    assert result["queued"] is True
    assert result["due"] == 2
    assert queue.calls == []  # queue I/O happens only after the DB commit
    queue_intent = session.executions[0][1]
    assert queue_intent["topic"] == "remind"
    assert str(campaign.campaign_id) in queue_intent["payload"]
    assert "recipient" not in queue_intent["payload"].lower()
    assert session.committed is True
    assert audit.records[0]["detail"]["due"] == 2


def test_stopped_campaign_cannot_queue_training_reminders() -> None:
    campaign = _campaign(dm.CampaignState.STOPPED)
    with pytest.raises(ConflictError, match="stopped or recalled"):
        queue_training_reminders(
            str(campaign.campaign_id),
            SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(queue=_Queue()))),  # type: ignore[arg-type]
            session=_SequenceSession(campaign=campaign),  # type: ignore[arg-type]
            audit=_Audit(),  # type: ignore[arg-type]
            principal=Principal("operator-1", {Role.CAMPAIGN_OPERATOR}),
        )
