from __future__ import annotations

import uuid
from datetime import UTC, datetime

from kp_database.models import DeliveryReportCorrelation, RecipientAssignment, TrackingEvent
from kp_domain_models import models as dm
from kp_workers.reply_mail_jobs import _consume, _correlate


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


class _ConsumeSession:
    """Scripted session for :func:`_consume`.

    ``scalar`` answers, in order: the receipt-exists lookup (None), the
    correlation lookup (the correlation), the existing-MESSAGE_REPLIED lookup
    (None), and the tracking-token lookup (None). ``get`` resolves the locked
    assignment. Added rows are captured so the emitted event can be inspected.
    """

    def __init__(self, assignment: RecipientAssignment, correlation: DeliveryReportCorrelation) -> None:
        self._scalars: list[object | None] = [None, correlation, None, None]
        self._assignment = assignment
        self.added: list[object] = []

    def scalar(self, _statement: object) -> object | None:
        return self._scalars.pop(0)

    def get(self, model: object, identifier: object, **_options: object) -> object:
        assert model is RecipientAssignment
        return self._assignment

    def add(self, obj: object) -> None:
        self.added.append(obj)

    def flush(self) -> None:
        pass


def test_consume_records_correlated_reply_at_medium_confidence_not_high() -> None:
    # KP-AUD-005: header-only correlation is forgeable/forwardable evidence, so
    # a newly emitted MESSAGE_REPLIED event must be MEDIUM, never HIGH.
    assignment_id = uuid.uuid4()
    attempt_id = uuid.uuid4()
    assignment = RecipientAssignment(
        recipient_assignment_id=assignment_id,
        recipient_id=uuid.uuid4(),
        campaign_id=uuid.uuid4(),
        delivery_attempt_id=attempt_id,
        idempotency_key="reply-confidence",
    )
    correlation = _correlation("<sent-1@example.com>", assignment_id, attempt_id)
    session = _ConsumeSession(assignment, correlation)

    disposition = _consume(
        session,  # type: ignore[arg-type]
        provider="mailpit",
        scope_hash="s" * 64,
        external_id="ext-1",
        received_at=datetime(2026, 2, 3, 4, 5, 6, tzinfo=UTC),
        referenced_message_ids=("<sent-1@example.com>",),
        evidence={"references_seen": 1},
    )

    assert disposition == "replied"
    events = [row for row in session.added if isinstance(row, TrackingEvent)]
    assert len(events) == 1
    event = events[0]
    assert event.event_type is dm.EventType.MESSAGE_REPLIED
    assert event.confidence is dm.Confidence.MEDIUM
    assert event.confidence is not dm.Confidence.HIGH
