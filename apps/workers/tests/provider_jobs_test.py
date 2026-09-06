from __future__ import annotations

import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from kp_database.models import RetentionPolicy
from kp_database.training import TrainingBearerPurpose, training_bearer, training_bearer_verifier
from kp_domain_models import models as dm
from kp_domain_models.policy import ApprovalPolicy
from kp_telemetry.errors import SafetyRejectionError
from kp_workers.config import WorkerSettings
from kp_workers.jobs import (
    RetentionPolicyConfigurationError,
    WorkerContext,
    _delivery_assignment_ids,
    _resolve_retention_policy,
    maybe_publish_retention,
    process_mailbox,
    process_reminder,
    process_retention,
)


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
    # PLT-002 made ENFORCE the default approval policy, which also fail-closes the
    # empty-allowlist reminder path (followup_jobs.py: unrestricted requires
    # SINGLE_ADMIN). These provider-job tests exercise the historical single-admin
    # offline send behavior, so keep that posture behind the explicit dev marker.
    settings = WorkerSettings(
        _env_file=None,
        reported_mailbox_url="http://localhost:8025",
        training_token_hmac_key=("33" * 32),
        tracking_base_url="http://localhost:8001",
        runtime_mode="development",
        approval_policy="single-admin",
        dev_stack=True,
    )
    context = WorkerContext(settings, factory, audit, SimpleNamespace())  # type: ignore[arg-type]
    return context, audit


@pytest.mark.parametrize("retention_days", [0, 366])
def test_retention_policy_days_fail_closed_outside_governed_bounds(retention_days: int) -> None:
    policy = RetentionPolicy(
        retention_policy_id=uuid.uuid4(),
        name="Invalid default",
        data_category="recipient_assignments",
        retention_days=retention_days,
        is_default=True,
    )
    session = _Session(scalars_result=[policy])

    with pytest.raises(
        RetentionPolicyConfigurationError,
        match="^retention policy configuration is invalid$",
    ):
        _resolve_retention_policy(session, "default")  # type: ignore[arg-type]


def test_multiple_default_retention_policies_fail_closed_without_selecting_first() -> None:
    policies = [
        RetentionPolicy(
            retention_policy_id=uuid.uuid4(),
            name=f"Default {index}",
            data_category="recipient_assignments",
            retention_days=365,
            is_default=True,
        )
        for index in range(2)
    ]
    session = _Session(scalars_result=policies)

    with pytest.raises(
        RetentionPolicyConfigurationError,
        match="^retention policy configuration is invalid$",
    ):
        _resolve_retention_policy(session, "default")  # type: ignore[arg-type]


def _add_due_assignment(session: _Session, *, mailbox: str) -> SimpleNamespace:
    now = datetime.now(UTC)
    recipient_id = uuid.uuid4()
    recipient_assignment_id = uuid.uuid4()
    token_id = uuid.uuid4()
    assignment = SimpleNamespace(
        training_assignment_id=uuid.uuid4(),
        recipient_assignment_id=recipient_assignment_id,
        recipient_id=recipient_id,
        campaign_id=uuid.uuid4(),
        due_at=now - timedelta(hours=1),
        access_expires_at=now + timedelta(days=10),
        completed_at=None,
        followup_sent_at=None,
    )
    open_bearer = training_bearer(
        assignment.training_assignment_id,
        assignment.access_expires_at,
        b"3" * 32,
        purpose=TrainingBearerPurpose.OPEN,
    )
    completion_bearer = training_bearer(
        assignment.training_assignment_id,
        assignment.access_expires_at,
        b"3" * 32,
        purpose=TrainingBearerPurpose.COMPLETE,
    )
    assignment.training_token_hash = training_bearer_verifier(
        open_bearer,
        b"3" * 32,
        purpose=TrainingBearerPurpose.OPEN,
    )
    assignment.training_completion_token_hash = training_bearer_verifier(
        completion_bearer,
        b"3" * 32,
        purpose=TrainingBearerPurpose.COMPLETE,
    )
    session.get_results[recipient_id] = SimpleNamespace(
        status=dm.RecipientStatus.ACTIVE,
        mailbox=mailbox,
        deleted_at=None,
    )
    session.get_results[recipient_assignment_id] = SimpleNamespace(token_id=token_id)
    session.get_results[token_id] = SimpleNamespace(status=dm.TokenStatus.ACTIVE)
    _seed_reminder_send_gate(session, assignment.campaign_id)
    return assignment


def _seed_reminder_send_gate(session: _Session, campaign_id: uuid.UUID) -> None:
    """Seed the safety state, campaign, and active RoE the reminder gate reads."""
    now = datetime.now(UTC)
    session.get_results[1] = SimpleNamespace(emergency_stop_engaged=False, generation=0)
    roe_id = uuid.uuid4()
    session.get_results[campaign_id] = SimpleNamespace(campaign_id=campaign_id, roe_id=roe_id)
    session.get_results[roe_id] = SimpleNamespace(
        revoked_at=None,
        window_start=now - timedelta(days=1),
        window_end=now + timedelta(days=30),
    )


def test_mailbox_job_delegates_to_durable_provider_flow(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _Session()
    context, _ = _context(session)
    calls: list[tuple[object, dict[str, Any]]] = []
    monkeypatch.setattr(
        "kp_workers.reported_mail_jobs.process_mailbox",
        lambda received_context, message: calls.append((received_context, message)),
    )

    process_mailbox(context, {"payload": {"job_id": "poll-1"}})

    assert calls == [(context, {"payload": {"job_id": "poll-1"}})]


def test_retention_replay_exits_before_reapplying_mutations() -> None:
    session = _Session()
    session.scalar_results = [uuid.uuid4()]
    context, audit = _context(session)

    process_retention(context, {"payload": {}, "idempotency_key": "retention-already-complete"})

    assert session.commits == 0
    assert session.added == []
    assert audit.records == []


def test_retention_scheduler_uses_one_shared_key_per_cadence_bucket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _Session()
    context, _audit = _context(session)
    context.settings.retention_interval_seconds = 3600
    published: list[dict[str, Any]] = []

    def capture_enqueue(
        _session: object,
        *,
        topic: str,
        payload: dict[str, Any],
        idempotency_key: str,
    ) -> None:
        published.append({"topic": topic, "payload": payload, "idempotency_key": idempotency_key})

    monkeypatch.setattr("kp_workers.jobs.enqueue_queue", capture_enqueue)
    monkeypatch.setattr("kp_workers.jobs.dispatch_after_commit", lambda _session, _callback: None)
    now = datetime(2026, 8, 28, 12, 34, tzinfo=UTC)

    maybe_publish_retention(context, now)

    expected_key = f"retention-self-{int(now.timestamp()) // 3600}"
    assert published == [
        {
            "topic": "retention",
            "payload": {
                "retention_policy_id": "default",
                "scheduled_at": now.isoformat(),
                "idempotency_key": expected_key,
            },
            "idempotency_key": expected_key,
        }
    ]


def test_delivery_assignment_batch_is_uuid_bound_deduplicated_and_size_limited() -> None:
    assignment_id = uuid.uuid4()

    assert _delivery_assignment_ids(
        {"recipient_assignment_ids": [str(assignment_id).upper()]},
        limit=1,
    ) == [str(assignment_id)]
    with pytest.raises(SafetyRejectionError, match="configured limit"):
        _delivery_assignment_ids(
            {"recipient_assignment_ids": [str(uuid.uuid4()), str(uuid.uuid4())]},
            limit=1,
        )
    with pytest.raises(SafetyRejectionError, match="duplicate"):
        _delivery_assignment_ids(
            {"recipient_assignment_ids": [str(assignment_id), str(assignment_id)]},
            limit=2,
        )
    with pytest.raises(SafetyRejectionError, match="invalid identifier"):
        _delivery_assignment_ids({"recipient_assignment_ids": ["not-a-uuid"]}, limit=1)


def test_reminder_job_sends_only_due_active_assignment(monkeypatch: pytest.MonkeyPatch) -> None:
    recipient_id = uuid.uuid4()
    recipient_assignment_id = uuid.uuid4()
    token_id = uuid.uuid4()
    assigned_at = datetime.now(UTC) - timedelta(days=5)
    assignment = SimpleNamespace(
        training_assignment_id=uuid.uuid4(),
        recipient_assignment_id=recipient_assignment_id,
        recipient_id=recipient_id,
        campaign_id=uuid.uuid4(),
        status=dm.TrainingAssignmentStatus.ASSIGNED,
        assigned_at=assigned_at,
        due_at=assigned_at + timedelta(days=3),
        access_expires_at=assigned_at + timedelta(days=90),
        completed_at=None,
        followup_sent_at=None,
    )
    open_bearer = training_bearer(
        assignment.training_assignment_id,
        assignment.access_expires_at,
        b"3" * 32,
        purpose=TrainingBearerPurpose.OPEN,
    )
    completion_bearer = training_bearer(
        assignment.training_assignment_id,
        assignment.access_expires_at,
        b"3" * 32,
        purpose=TrainingBearerPurpose.COMPLETE,
    )
    assignment.training_token_hash = training_bearer_verifier(
        open_bearer,
        b"3" * 32,
        purpose=TrainingBearerPurpose.OPEN,
    )
    assignment.training_completion_token_hash = training_bearer_verifier(
        completion_bearer,
        b"3" * 32,
        purpose=TrainingBearerPurpose.COMPLETE,
    )
    session = _Session()
    session.scalar_results = [assignment, None]
    session.get_results[recipient_id] = SimpleNamespace(
        recipient_id=recipient_id,
        status=dm.RecipientStatus.ACTIVE,
        mailbox="learner@example.com",
        deleted_at=None,
    )
    session.get_results[recipient_assignment_id] = SimpleNamespace(token_id=token_id)
    session.get_results[token_id] = SimpleNamespace(status=dm.TokenStatus.ACTIVE)
    _seed_reminder_send_gate(session, assignment.campaign_id)
    monkeypatch.setattr("kp_workers.followup_jobs._excluded_recipient_ids", lambda *_a, **_k: set())
    context, audit = _context(session)
    sent: list[Any] = []

    def send(reminder: Any) -> None:
        assert assignment.followup_sent_at is not None
        assert session.commits == 1
        sent.append(reminder)

    monkeypatch.setattr("kp_workers.jobs._reminder_sender", lambda _: SimpleNamespace(send=send))
    process_reminder(context, {"payload": {}})
    assert sent[0].recipient == "learner@example.com"
    training_url = sent[0].text.rsplit(" ", 1)[-1]
    assert training_url.startswith("http://localhost:8001/v1/training/")
    assert str(assignment.training_assignment_id) not in training_url
    assert assignment.status == dm.TrainingAssignmentStatus.ASSIGNED
    assert assignment.followup_sent_at is not None
    assert audit.records[0]["detail"] == {"sent": 1, "skipped": 0}


def test_reminder_job_skips_completed_future_expired_and_revoked_assignments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(UTC)

    def assignment(**overrides: Any) -> SimpleNamespace:
        values = {
            "training_assignment_id": uuid.uuid4(),
            "recipient_assignment_id": uuid.uuid4(),
            "recipient_id": uuid.uuid4(),
            "campaign_id": uuid.uuid4(),
            "due_at": now - timedelta(hours=1),
            "access_expires_at": now + timedelta(days=10),
            "completed_at": None,
            "followup_sent_at": None,
        }
        values.update(overrides)
        return SimpleNamespace(**values)

    completed = assignment(completed_at=now - timedelta(minutes=1))
    future = assignment(due_at=now + timedelta(days=1))
    expired = assignment(access_expires_at=now - timedelta(seconds=1))
    revoked = assignment()
    session = _Session()
    session.scalar_results = [completed, future, expired, revoked, None]
    session.get_results[revoked.recipient_id] = SimpleNamespace(
        status=dm.RecipientStatus.ACTIVE,
        mailbox="learner@example.com",
        deleted_at=None,
    )
    token_id = uuid.uuid4()
    session.get_results[revoked.recipient_assignment_id] = SimpleNamespace(token_id=token_id)
    session.get_results[token_id] = SimpleNamespace(status=dm.TokenStatus.KILL_SWITCHED)
    # The send gate must not fire before these rows are individually skipped, so
    # seed a non-engaged safety state; the invalid rows are dropped upstream of
    # the RoE/allowlist/exclusion checks anyway.
    session.get_results[1] = SimpleNamespace(emergency_stop_engaged=False, generation=0)
    monkeypatch.setattr("kp_workers.followup_jobs._excluded_recipient_ids", lambda *_a, **_k: set())
    context, audit = _context(session)
    monkeypatch.setattr(
        "kp_workers.jobs._reminder_sender",
        lambda _: (_ for _ in ()).throw(AssertionError("invalid reminders must not allocate a transport")),
    )

    process_reminder(context, {"payload": {}})

    assert audit.records[0]["detail"] == {"sent": 0, "skipped": 4}


def test_reminder_job_builds_a_fresh_single_use_transport_for_each_send(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _Session()
    assignments = [
        _add_due_assignment(session, mailbox="learner-0@example.com"),
        _add_due_assignment(session, mailbox="learner-1@example.com"),
    ]
    session.scalar_results = [*assignments, None]
    monkeypatch.setattr("kp_workers.followup_jobs._excluded_recipient_ids", lambda *_a, **_k: set())
    context, audit = _context(session)
    senders_created = 0
    sent: list[Any] = []

    def sender_factory(_context: WorkerContext) -> SimpleNamespace:
        nonlocal senders_created
        senders_created += 1
        return SimpleNamespace(send=sent.append)

    monkeypatch.setattr("kp_workers.jobs._reminder_sender", sender_factory)

    process_reminder(context, {"payload": {}})

    assert senders_created == 2
    assert [reminder.recipient for reminder in sent] == [
        "learner-0@example.com",
        "learner-1@example.com",
    ]
    assert audit.records[0]["detail"] == {"sent": 2, "skipped": 0}


def test_reminder_transport_construction_failure_releases_the_pre_submission_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _Session()
    assignment = _add_due_assignment(session, mailbox="learner@example.com")
    session.scalar_results = [assignment]
    monkeypatch.setattr("kp_workers.followup_jobs._excluded_recipient_ids", lambda *_a, **_k: set())
    context, audit = _context(session)
    monkeypatch.setattr(
        "kp_workers.jobs._reminder_sender",
        lambda _context: (_ for _ in ()).throw(ConnectionError("provider unavailable")),
    )

    with pytest.raises(ConnectionError, match="provider unavailable"):
        process_reminder(context, {"payload": {}})

    assert assignment.followup_sent_at is None
    assert session.commits == 2
    assert audit.records[0]["detail"] == {"outcome": "pre_submission_failure"}


def test_reminder_job_halts_while_emergency_stop_is_engaged(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _Session()
    assignment = _add_due_assignment(session, mailbox="learner@example.com")
    session.scalar_results = [assignment, None]
    # The reminder worker previously bypassed the send gate; the global stop
    # must now halt reminders exactly as it halts campaign delivery.
    session.get_results[1] = SimpleNamespace(emergency_stop_engaged=True, generation=1)
    monkeypatch.setattr("kp_workers.followup_jobs._excluded_recipient_ids", lambda *_a, **_k: set())
    monkeypatch.setattr(
        "kp_workers.jobs._reminder_sender",
        lambda _: (_ for _ in ()).throw(AssertionError("no reminder may be sent while stopped")),
    )
    context, audit = _context(session)

    process_reminder(context, {"payload": {}})

    # The follow-up is never claimed, so it remains eligible once the stop lifts.
    assert assignment.followup_sent_at is None
    blocked = [record for record in audit.records if record["action"] == "training.remind.blocked"]
    assert blocked and blocked[0]["detail"] == {"reason": "global_emergency_stop"}


def test_reminder_job_retires_follow_up_when_roe_is_inactive(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _Session()
    assignment = _add_due_assignment(session, mailbox="learner@example.com")
    campaign = session.get_results[assignment.campaign_id]
    now = datetime.now(UTC)
    session.get_results[campaign.roe_id] = SimpleNamespace(
        revoked_at=now,
        window_start=now - timedelta(days=1),
        window_end=now + timedelta(days=30),
    )
    session.scalar_results = [assignment, None]
    monkeypatch.setattr("kp_workers.followup_jobs._excluded_recipient_ids", lambda *_a, **_k: set())
    monkeypatch.setattr(
        "kp_workers.jobs._reminder_sender",
        lambda _: (_ for _ in ()).throw(AssertionError("no reminder outside an active RoE window")),
    )
    context, audit = _context(session)

    process_reminder(context, {"payload": {}})

    assert assignment.followup_sent_at is not None
    assert audit.records[-1]["detail"] == {"sent": 0, "skipped": 1}


def test_reminder_job_skips_an_excluded_recipient(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _Session()
    assignment = _add_due_assignment(session, mailbox="learner@example.com")
    session.scalar_results = [assignment, None]
    monkeypatch.setattr(
        "kp_workers.followup_jobs._excluded_recipient_ids",
        lambda *_a, **_k: {assignment.recipient_id},
    )
    monkeypatch.setattr(
        "kp_workers.jobs._reminder_sender",
        lambda _: (_ for _ in ()).throw(AssertionError("no reminder to an excluded recipient")),
    )
    context, audit = _context(session)

    process_reminder(context, {"payload": {}})

    assert assignment.followup_sent_at is not None
    assert audit.records[-1]["detail"] == {"sent": 0, "skipped": 1}


def test_reminder_job_skips_recipient_outside_the_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _Session()
    assignment = _add_due_assignment(session, mailbox="learner@example.com")
    session.scalar_results = [assignment, None]
    monkeypatch.setattr("kp_workers.followup_jobs._excluded_recipient_ids", lambda *_a, **_k: set())
    monkeypatch.setattr(
        "kp_workers.jobs._reminder_sender",
        lambda _: (_ for _ in ()).throw(AssertionError("no reminder outside the recipient allowlist")),
    )

    @contextmanager
    def factory() -> Any:
        yield session

    audit = _Audit()
    # A non-empty allowlist that excludes example.com makes the send fail closed.
    settings = WorkerSettings(
        _env_file=None,
        reported_mailbox_url="http://localhost:8025",
        training_token_hmac_key=("33" * 32),
        tracking_base_url="http://localhost:8001",
        allowed_recipient_domains="allowed.example.net",
    )
    context = WorkerContext(settings, factory, audit, SimpleNamespace())  # type: ignore[arg-type]

    process_reminder(context, {"payload": {}})

    assert assignment.followup_sent_at is not None
    assert audit.records[-1]["detail"] == {"sent": 0, "skipped": 1}


def test_reminder_job_fails_closed_on_empty_allowlist_under_enforce_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # TST-002 coverage gap: an EMPTY recipient allowlist is allow-all ONLY for the
    # marked single-admin offline stack (unrestricted = not allowlist and
    # approval_policy is SINGLE_ADMIN, followup_jobs.py). Under the hardened
    # default (PLT-002 made ENFORCE the default, and no KP_DEV_STACK marker here),
    # an unset allowlist must fail CLOSED for reminders just as it does for
    # delivery — a reminder is a real outbound message.
    session = _Session()
    assignment = _add_due_assignment(session, mailbox="learner@example.com")
    session.scalar_results = [assignment, None]
    monkeypatch.setattr("kp_workers.followup_jobs._excluded_recipient_ids", lambda *_a, **_k: set())
    monkeypatch.setattr(
        "kp_workers.jobs._reminder_sender",
        lambda _: (_ for _ in ()).throw(AssertionError("no reminder under a fail-closed empty allowlist")),
    )

    @contextmanager
    def factory() -> Any:
        yield session

    audit = _Audit()
    # No allowed_recipient_domains, no approval_policy override, no dev_stack:
    # the default ENFORCE posture with an empty allowlist must not allow-all.
    settings = WorkerSettings(
        _env_file=None,
        reported_mailbox_url="http://localhost:8025",
        training_token_hmac_key=("33" * 32),
        tracking_base_url="http://localhost:8001",
    )
    assert settings.approval_policy is ApprovalPolicy.ENFORCE
    context = WorkerContext(settings, factory, audit, SimpleNamespace())  # type: ignore[arg-type]

    process_reminder(context, {"payload": {}})

    assert assignment.followup_sent_at is not None
    assert audit.records[-1]["detail"] == {"sent": 0, "skipped": 1}
