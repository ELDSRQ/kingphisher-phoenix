from __future__ import annotations

import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from kp_domain_models import models as dm
from kp_workers.config import WorkerSettings
from kp_workers.jobs import WorkerContext, process_mailbox, process_reminder
from kp_workers.providers.mailpit import ReportedMessage


class _Audit:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def record(self, **kwargs: Any) -> None:
        self.records.append(kwargs)


class _Session:
    def __init__(self, *, scalars_result: list[Any] | None = None) -> None:
        self.scalar_results: list[Any] = []
        self.scalars_result = scalars_result or []
        self.get_results: dict[object, Any] = {}
        self.added: list[Any] = []
        self.commits = 0

    def scalar(self, statement: object) -> Any:
        return self.scalar_results.pop(0)

    def scalars(self, statement: object) -> list[Any]:
        return self.scalars_result

    def get(self, model: object, identifier: object) -> Any:
        return self.get_results.get(identifier)

    def add(self, value: Any) -> None:
        self.added.append(value)

    def commit(self) -> None:
        self.commits += 1


def _context(session: _Session) -> tuple[WorkerContext, _Audit]:
    @contextmanager
    def factory() -> Any:
        yield session

    audit = _Audit()
    settings = WorkerSettings(_env_file=None, reported_mailbox_url="http://localhost:8025")
    context = WorkerContext(settings, factory, audit, SimpleNamespace())  # type: ignore[arg-type]
    return context, audit


def test_mailbox_job_records_report_once(monkeypatch: pytest.MonkeyPatch) -> None:
    token_id = uuid.uuid4()
    assignment_id = uuid.uuid4()
    recipient_id = uuid.uuid4()
    token = SimpleNamespace(token_id=token_id, recipient_assignment_id=assignment_id, campaign_id=uuid.uuid4())
    session = _Session()
    session.scalar_results = [token, None]
    session.get_results[assignment_id] = SimpleNamespace(recipient_id=recipient_id)
    context, audit = _context(session)
    provider = SimpleNamespace(
        poll=lambda: [ReportedMessage(external_id="mail-1", token_hash="ab" * 32, reported_at=datetime.now(UTC))]
    )
    monkeypatch.setattr("kp_workers.jobs._mailbox_provider", lambda _: provider)
    process_mailbox(context, {"payload": {}})
    assert len(session.added) == 1
    assert session.added[0].event_type == dm.EventType.MESSAGE_REPORTED
    assert session.added[0].recipient_id == recipient_id
    assert audit.records[0]["detail"] == {"polled": 1, "recorded": 1, "unknown_tokens": 0}


def test_reminder_job_sends_only_due_active_assignment(monkeypatch: pytest.MonkeyPatch) -> None:
    recipient_id = uuid.uuid4()
    assignment = SimpleNamespace(
        recipient_id=recipient_id,
        status=dm.TrainingAssignmentStatus.ASSIGNED,
        assigned_at=datetime.now(UTC) - timedelta(days=5),
        completed_at=None,
        followup_sent_at=None,
    )
    session = _Session(scalars_result=[assignment])
    session.get_results[recipient_id] = SimpleNamespace(
        recipient_id=recipient_id, status=dm.RecipientStatus.ACTIVE, mailbox="learner@example.com"
    )
    context, audit = _context(session)
    sent: list[Any] = []
    monkeypatch.setattr("kp_workers.jobs._reminder_sender", lambda _: SimpleNamespace(send=sent.append))
    process_reminder(context, {"payload": {}})
    assert sent[0].recipient == "learner@example.com"
    assert assignment.status == dm.TrainingAssignmentStatus.REMINDED
    assert assignment.followup_sent_at is not None
    assert audit.records[0]["detail"] == {"sent": 1, "skipped": 0}
