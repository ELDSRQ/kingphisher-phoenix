from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

from kp_database.models import (
    DeliveryPacingState,
    DeliveryProviderEvent,
    DeliveryReportCorrelation,
    RecipientAssignment,
    RecipientDeliverySuppression,
)
from kp_domain_models import models as dm
from kp_workers.config import WorkerSettings
from kp_workers.jobs import (
    WorkerContext,
    _apply_acs_delivery_state,
    _reserve_acs_delivery_capacity,
    process_acs_delivery_receipt,
)
from kp_workers.providers.acs_events import AcsDeliveryEvent

KEY_HEX = "12" * 32
KEY = bytes.fromhex(KEY_HEX)
NOW = datetime.now(UTC)


class _Session:
    def __init__(self, correlation: DeliveryReportCorrelation, assignment: RecipientAssignment) -> None:
        self.scalar_results = [None, correlation]
        self.correlation = correlation
        self.assignment = assignment
        self.added: list[object] = []
        self.commits = 0
        self.assignment_get_options: list[dict[str, object]] = []

    def scalar(self, _statement: object) -> object:
        return self.scalar_results.pop(0)

    def get(self, model: object, identifier: object, **kwargs: object) -> object | None:
        if model is RecipientAssignment and identifier == self.assignment.recipient_assignment_id:
            self.assignment_get_options.append(kwargs)
            return self.assignment
        if model is RecipientDeliverySuppression and identifier == self.assignment.recipient_id:
            return None
        return None

    def add(self, row: object) -> None:
        self.added.append(row)

    def flush(self) -> None:
        return None

    def rollback(self) -> None:
        return None

    def commit(self) -> None:
        self.commits += 1


class _Audit:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def record(self, **record: Any) -> None:
        self.records.append(record)


def _queued_event(status: str) -> tuple[dict[str, object], str]:
    event: dict[str, object] = {
        "id": "event-123",
        "eventType": "Microsoft.Communication.EmailDeliveryReportReceived",
        "eventTime": NOW.isoformat(),
        "dataVersion": "1.0",
        "metadataVersion": "1",
        "data": {"messageId": "acs-operation-1", "status": status, "deliveryStatusDetailsHash": None},
    }
    canonical = json.dumps(event, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return event, hmac.new(KEY, canonical, hashlib.sha256).hexdigest()


def test_bounce_receipt_is_terminal_and_creates_durable_suppression() -> None:
    attempt_id = uuid.uuid4()
    assignment = RecipientAssignment(
        recipient_assignment_id=uuid.uuid4(),
        recipient_id=uuid.uuid4(),
        campaign_id=uuid.uuid4(),
        delivery_attempt_id=attempt_id,
        send_state=dm.SendState.ACCEPTED,
        idempotency_key="assignment-1",
    )
    correlation = DeliveryReportCorrelation(
        delivery_attempt_id=attempt_id,
        recipient_assignment_id=assignment.recipient_assignment_id,
        report_verifier="rpt1_" + "A" * 43,
        verifier_hash="a" * 64,
        message_id="<message@example.com>",
        provider_id="acs-operation-1",
    )
    session = _Session(correlation, assignment)
    audit = _Audit()

    @contextmanager
    def factory() -> Any:
        yield session

    event, signature = _queued_event("Bounced")
    settings = WorkerSettings(_env_file=None, acs_receipt_signing_key=KEY_HEX)
    ctx = WorkerContext(settings, factory, audit, SimpleNamespace())  # type: ignore[arg-type]

    process_acs_delivery_receipt(
        ctx,
        {"payload": {"job_type": "acs_delivery_receipt", "event": event, "signature": signature}},
    )

    assert assignment.send_state == dm.SendState.FAILED
    assert assignment.failure_reason == "provider_bounced"
    assert correlation.provider_status == "bounced"
    assert any(isinstance(row, DeliveryProviderEvent) for row in session.added)
    suppression = next(row for row in session.added if isinstance(row, RecipientDeliverySuppression))
    assert suppression.recipient_id == assignment.recipient_id
    assert suppression.reason == "bounced"
    assert session.assignment_get_options == [{"with_for_update": True, "populate_existing": True}]
    assert audit.records[0]["detail"] == {"provider": "acs", "status": "bounced", "outcome": "failed"}


def test_delivered_truth_cannot_be_downgraded_by_later_failure_event() -> None:
    assignment = RecipientAssignment(
        recipient_assignment_id=uuid.uuid4(),
        recipient_id=uuid.uuid4(),
        campaign_id=uuid.uuid4(),
        send_state=dm.SendState.ACCEPTED,
        idempotency_key="assignment-2",
    )
    delivered = AcsDeliveryEvent("a" * 64, "provider", "delivered", None, NOW)
    bounced = AcsDeliveryEvent("b" * 64, "provider", "bounced", None, NOW)

    assert _apply_acs_delivery_state(assignment, delivered) == "delivered"
    assert assignment.send_state == dm.SendState.DELIVERED
    assert assignment.delivery_confirmed_at == NOW
    assert _apply_acs_delivery_state(assignment, bounced) == "ignored_after_delivered"
    assert assignment.send_state == dm.SendState.DELIVERED
    assert assignment.failure_reason is None


def test_durable_pacing_reserves_only_one_bounded_ramp_batch() -> None:
    state = DeliveryPacingState(
        provider="acs",
        minute_window_started_at=NOW.replace(second=0, microsecond=0),
        minute_count=0,
        day_started_at=NOW.replace(hour=0, minute=0, second=0, microsecond=0),
        daily_count=0,
        next_batch_at=NOW,
    )

    class _PacingSession:
        def execute(self, _statement: object) -> None:
            return None

        def get(self, model: object, identifier: object, **_kwargs: object) -> object | None:
            if model is DeliveryPacingState and identifier == "acs":
                return state
            return None

    settings = WorkerSettings(
        _env_file=None,
        worker_name="delivery",
        email_provider="azure_communication_services",
        acs_email_endpoint="https://mailer.communication.azure.com",
        smtp_sender="awareness@mail.example.com",
        acs_sending_domain="mail.example.com",
        acs_sender_local_part="awareness",
        acs_sender_display_name="Security Awareness",
        acs_domain_verification_status="verified",
        acs_spf_verification_status="verified",
        acs_dkim_verification_status="verified",
        acs_dkim2_verification_status="verified",
        acs_sender_username_status="verified",
        acs_readiness_checked_at=NOW.isoformat(),
        acs_daily_message_limit=100,
        acs_messages_per_minute=10,
        acs_ramp_batch_size=3,
        acs_ramp_interval_seconds=30,
    )

    reserved, next_at = _reserve_acs_delivery_capacity(  # type: ignore[arg-type]
        _PacingSession(), settings, requested=20, now=NOW
    )
    blocked, same_next = _reserve_acs_delivery_capacity(  # type: ignore[arg-type]
        _PacingSession(), settings, requested=20, now=NOW
    )

    assert reserved == 3
    assert state.minute_count == 3
    assert state.daily_count == 3
    assert next_at == NOW.replace(microsecond=NOW.microsecond) + timedelta(seconds=30)
    assert blocked == 0
    assert same_next == next_at
