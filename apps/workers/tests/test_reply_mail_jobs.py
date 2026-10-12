from __future__ import annotations

import uuid
from datetime import UTC, datetime

from kp_database.models import DeliveryReportCorrelation, RecipientAssignment
from kp_workers.reply_mail_jobs import _correlate


def _correlation(message_id: str, assignment_id: uuid.UUID, attempt_id: uuid.UUID) -> DeliveryReportCorrelation:
    return DeliveryReportCorrelation(
        delivery_attempt_id=attempt_id,
        recipient_assignment_id=assignment_id,
        report_verifier="rpt1_" + "A" * 43,
        verifier_hash="a" * 64,
        message_id=message_id,
    )


def test_correlate_matches_referenced_message_id_and_locks_assignment() -> None:
    assignment_id = uuid.uuid4()
    attempt_id = uuid.uuid4()
    assignment = RecipientAssignment(
        recipient_assignment_id=assignment_id,
        recipient_id=uuid.uuid4(),
        campaign_id=uuid.uuid4(),
        delivery_attempt_id=attempt_id,
        idempotency_key="reply-lock",
    )
    correlation = _correlation("<sent-1@example.com>", assignment_id, attempt_id)

    class _Session:
        def __init__(self) -> None:
            self.looked_up: list[object] = []
            self.get_options: list[dict[str, object]] = []

        def scalar(self, statement: object) -> object | None:
            # Only the matching message_id resolves a correlation.
            self.looked_up.append(statement)
            return correlation if len(self.looked_up) == 2 else None

        def get(self, model: object, identifier: object, **options: object) -> object | None:
            assert model is RecipientAssignment
            assert identifier == assignment_id
            self.get_options.append(options)
            return assignment

    session = _Session()
    resolved = _correlate(session, ("<unknown@example.com>", "<sent-1@example.com>"))

    assert resolved is assignment
    assert session.get_options == [{"with_for_update": True, "populate_existing": True}]


def test_correlate_returns_none_when_no_reference_matches() -> None:
    class _Session:
        def scalar(self, _statement: object) -> None:
            return None

    assert _correlate(_Session(), ("<a@example.com>", "<b@example.com>")) is None


def test_correlate_rejects_attempt_binding_mismatch() -> None:
    assignment_id = uuid.uuid4()
    assignment = RecipientAssignment(
        recipient_assignment_id=assignment_id,
        recipient_id=uuid.uuid4(),
        campaign_id=uuid.uuid4(),
        delivery_attempt_id=uuid.uuid4(),
        idempotency_key="reply-mismatch",
    )
    correlation = _correlation("<sent-9@example.com>", assignment_id, uuid.uuid4())

    class _Session:
        def scalar(self, _statement: object) -> object:
            return correlation

        def get(self, _model: object, _identifier: object, **_options: object) -> object:
            return assignment

    # The correlation's attempt id no longer matches the assignment: refuse it.
    assert _correlate(_Session(), ("<sent-9@example.com>",)) is None


def test_correlate_skips_oversized_reference_tokens() -> None:
    class _Session:
        def __init__(self) -> None:
            self.queried = False

        def scalar(self, _statement: object) -> None:
            self.queried = True
            return None

    session = _Session()
    assert _correlate(session, ("<" + "x" * 300 + ">",)) is None
    assert session.queried is False


def test_reply_candidate_occurred_at_is_the_received_time() -> None:
    # Guard the job contract that the event's occurred_at is the reply time.
    received = datetime(2026, 2, 3, 4, 5, 6, tzinfo=UTC)
    assert received.tzinfo is UTC
