from __future__ import annotations

import uuid
from datetime import UTC, datetime
from email.message import EmailMessage
from types import SimpleNamespace
from typing import Any

from kp_database.models import CipherText, DeliveryReportCorrelation, RecipientAssignment, TrackingToken
from kp_workers.directory_jobs import _accepted_user, _object_hash, _scope
from kp_workers.jobs import _durable_delivery_correlation
from kp_workers.providers.graph import DirectoryUser
from kp_workers.providers.microsoft365 import ReportedMailboxMessage
from kp_workers.providers.reported_mime import ReportedMimeParser
from kp_workers.reported_mail_jobs import _m365_candidate, _record_validated_candidate


def _user(**overrides: object) -> DirectoryUser:
    values = {
        "employee_key": "stable-object-id",
        "mailbox": "learner@example.com",
        "display_name": "Learner",
        "department": "Security",
        "account_enabled": True,
        "user_type": "Member",
        "mail": "learner@example.com",
        "user_principal_name": "learner@example.com",
    }
    values.update(overrides)
    return DirectoryUser(**values)  # type: ignore[arg-type]


def test_directory_policy_explicitly_rejects_unsafe_user_shapes() -> None:
    allowed = frozenset({"example.com"})
    assert _accepted_user(_user(), allowed) is None
    assert _accepted_user(_user(account_enabled=False), allowed) == "disabled"
    assert _accepted_user(_user(user_type="Guest"), allowed) == "guest"
    assert _accepted_user(_user(user_type=None), allowed) == "service_or_unknown"
    assert _accepted_user(_user(mail=None), allowed) == "mail_null"
    assert _accepted_user(_user(mailbox="learner@outside.test", mail="learner@outside.test"), allowed) == (
        "domain_not_allowed"
    )


def test_directory_object_hash_is_keyed_and_source_domain_separated() -> None:
    first = _object_hash("stable-object-id", b"a" * 32, "m365:scope-a")
    assert first == _object_hash("stable-object-id", b"a" * 32, "m365:scope-a")
    assert first != _object_hash("stable-object-id", b"b" * 32, "m365:scope-a")
    assert first != _object_hash("stable-object-id", b"a" * 32, "m365:scope-b")
    assert "stable-object-id" not in first


def test_directory_source_is_stable_when_reviewed_group_selection_changes() -> None:
    def context(groups: tuple[str, ...]) -> SimpleNamespace:
        settings = SimpleNamespace(
            graph_group_id_set=lambda: groups,
            microsoft_tenant_id="11111111-1111-1111-1111-111111111111",
            effective_graph_base_url="https://graph.microsoft.com/v1.0",
            recipient_domain_allowlist=lambda: frozenset({"example.com"}),
        )
        return SimpleNamespace(settings=settings)

    first_scope, first_config, first_source, _ = _scope(context(("group-a",)))
    second_scope, second_config, second_source, _ = _scope(context(("group-b",)))

    assert first_scope == second_scope
    assert first_config != second_config
    assert first_source == second_source
    assert "11111111" not in first_source


def test_reported_mime_candidate_requires_attached_original_and_evidence_excludes_secret() -> None:
    candidate = "rpt1_" + "A" * 43
    original = EmailMessage()
    original["X-KP-Report-Correlation"] = candidate
    original.set_content("original")
    wrapper = EmailMessage()
    wrapper.set_content("reported")
    wrapper.add_attachment(original.as_bytes(), maintype="application", subtype="octet-stream", filename="x.eml")
    parsed = ReportedMimeParser().parse(wrapper.as_bytes())
    message = ReportedMailboxMessage(
        external_id="external-1",
        received_at=datetime.now(UTC),
        internet_message_id=None,
        mime=parsed,
    )

    extracted, disposition, evidence = _m365_candidate(message)

    assert extracted == candidate
    assert disposition == "candidate"
    assert candidate not in repr(evidence)
    assert evidence["sources"] == ["attached_original"]


def test_reported_mail_locks_assignment_before_recording_outcome() -> None:
    assignment_id = uuid.uuid4()
    attempt_id = uuid.uuid4()
    candidate = "rpt1_" + "A" * 43
    correlation = DeliveryReportCorrelation(
        delivery_attempt_id=attempt_id,
        recipient_assignment_id=assignment_id,
        report_verifier=candidate,
        verifier_hash="a" * 64,
        message_id="<message@example.com>",
    )
    assignment = RecipientAssignment(
        recipient_assignment_id=assignment_id,
        recipient_id=uuid.uuid4(),
        campaign_id=uuid.uuid4(),
        delivery_attempt_id=attempt_id,
        idempotency_key="reported-mail-lock",
    )
    token = TrackingToken(
        token_id=uuid.uuid4(),
        token_hash="b" * 64,
        recipient_assignment_id=assignment_id,
        campaign_id=assignment.campaign_id,
        expires_at=datetime.now(UTC),
    )

    class _Session:
        def __init__(self) -> None:
            self.scalars = [correlation, token]
            self.get_options: list[dict[str, object]] = []

        def scalar(self, _statement: object) -> object:
            return self.scalars.pop(0)

        def get(self, model: object, identifier: object, **options: object) -> object | None:
            assert model is RecipientAssignment
            assert identifier == assignment_id
            self.get_options.append(options)
            return assignment

    session = _Session()
    resolved_assignment, resolved_token = _record_validated_candidate(
        session,  # type: ignore[arg-type]
        candidate=candidate,
        provider="microsoft365",
    )

    assert resolved_assignment is assignment
    assert resolved_token is token
    assert session.get_options == [{"with_for_update": True, "populate_existing": True}]


def test_ciphertext_raw_storage_never_contains_cursor_external_id_or_verifier() -> None:
    CipherText.configure_key(b"k" * 32)
    codec = CipherText()
    for secret in (
        "https://graph.microsoft.com/opaque-delta-cursor",
        "external-mailbox-message-id",
        "rpt1_" + "B" * 43,
    ):
        raw = codec.process_bind_param(secret, object())
        assert raw is not None and secret not in raw
        assert codec.process_result_value(raw, object()) == secret


def test_delivery_attempt_reuses_one_stable_encrypted_report_correlation() -> None:
    attempt_id = uuid.uuid4()
    assignment = SimpleNamespace(
        delivery_attempt_id=attempt_id,
        recipient_assignment_id=uuid.uuid4(),
    )

    class _Session:
        def __init__(self) -> None:
            self.row = None
            self.commits = 0

        def get(self, _model: object, _identifier: object) -> Any:
            return self.row

        def add(self, row: object) -> None:
            self.row = row

        def commit(self) -> None:
            self.commits += 1

    session = _Session()
    row, first = _durable_delivery_correlation(session, assignment, message_id_domain="example.com")  # type: ignore[arg-type]
    same_row, second = _durable_delivery_correlation(session, assignment, message_id_domain="example.com")  # type: ignore[arg-type]

    assert same_row is row
    assert first.message_id == second.message_id
    assert first.report_verifier == second.report_verifier
    assert session.commits == 1
    assert first.report_verifier not in repr(row)
