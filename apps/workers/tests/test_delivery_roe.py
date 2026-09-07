"""Delivery worker: signed Rules-of-Engagement enforcement.

Every failure mode of the RoE gate is tested as a hard stop: no RoE, no key,
bad signature, inactive/revoked RoE, and recipients outside the verified
target-domain boundary. The send path itself is stubbed — these tests are
about the gate, not the transport.
"""

from __future__ import annotations

import hashlib
import smtplib
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from kp_contracts.generation import TRAINING_URL_PLACEHOLDER
from kp_database.models import (
    Campaign,
    CampaignPattern,
    Recipient,
    RecipientAssignment,
    RecipientDeliverySuppression,
    RulesOfEngagement,
    SystemSafetyState,
    TemplateVersion,
)
from kp_domain_models import models as dm
from kp_domain_models.roe import roe_signature_hex
from kp_telemetry.errors import SafetyRejectionError
from kp_workers.config import WorkerSettings
from kp_workers.jobs import WorkerContext, process_delivery
from kp_workers.providers.smtp import DeliveryReceipt

_KEY_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
_KEY = bytes.fromhex(_KEY_HEX)
_NOW = datetime.now(UTC)


class _Audit:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def record(self, **kwargs: Any) -> None:
        self.records.append(kwargs)


class _Session:
    def __init__(self) -> None:
        self.get_results: dict[tuple[Any, Any], Any] = {}
        self.added: list[Any] = []
        self.commits = 0
        self.tokens: list[Any] = []

    def get(self, model: Any, identifier: Any, **_kwargs: Any) -> Any:
        return self.get_results.get((model, identifier))

    def scalar(self, statement: Any) -> Any:
        # The only scalar() used on this path is the per-assignment tracking
        # token lookup; hand back a valid token.
        return self.tokens.pop(0)

    def add(self, value: Any) -> None:
        self.added.append(value)

    def commit(self) -> None:
        self.commits += 1


def _make_roe(
    *,
    signature: str | None = None,
    revoked: bool = False,
    window_days_ago: int = 1,
    window_days_ahead: int = 30,
    target_domains: list[str] | None = None,
) -> RulesOfEngagement:
    signed_at = _NOW - timedelta(days=window_days_ago)
    terms_hash = "t" * 64
    window_start = _NOW - timedelta(days=window_days_ago)
    window_end = _NOW + timedelta(days=window_days_ahead)
    domains = target_domains or ["example.com"]
    authorizing_party = "Example Corp"
    return RulesOfEngagement(
        roe_id=uuid.uuid4(),
        signer="operator@example.com",
        authorizing_party=authorizing_party,
        terms_text="Engagement authorized for the verified target domains only.",
        terms_hash=terms_hash,
        signature=signature
        or roe_signature_hex(
            terms_hash,
            "operator@example.com",
            signed_at,
            authorizing_party=authorizing_party,
            target_domains=domains,
            window_start=window_start,
            window_end=window_end,
            signing_key=_KEY,
        ),
        signature_version=2,
        signed_at=signed_at,
        window_start=window_start,
        window_end=window_end,
        target_domains=domains,
        revoked_at=_NOW if revoked else None,
    )


def _make_campaign(roe: RulesOfEngagement | None) -> Campaign:
    manifest = "m" * 64
    return Campaign(
        campaign_id=uuid.uuid4(),
        pattern_id=uuid.uuid4(),
        current_template_id=uuid.uuid4(),
        title="test",
        state=dm.CampaignState.SCHEDULED,
        sender_mailbox="sender@example.com",
        training_domain="example.com",
        max_recipients=100,
        manifest_hash=manifest,
        roe_id=roe.roe_id if roe else None,
        expires_at=_NOW + timedelta(days=30),
    )


def _make_template() -> TemplateVersion:
    return TemplateVersion(
        template_version_id=uuid.uuid4(),
        generator_version="0.1.0",
        prompt_template_version="0.1.0",
        model_id="mock",
        input_hash="i" * 64,
        subject="subject",
        plain_text=f"body {TRAINING_URL_PLACEHOLDER}",
        approval_state=dm.TemplateApprovalState.APPROVED,
    )


def _make_assignment(campaign: Campaign, recipient_id: uuid.UUID) -> RecipientAssignment:
    return RecipientAssignment(
        recipient_assignment_id=uuid.uuid4(),
        campaign_id=campaign.campaign_id,
        recipient_id=recipient_id,
        send_state=dm.SendState.QUEUED,
        idempotency_key=f"{campaign.campaign_id}:{recipient_id}:1",
    )


def _make_recipient(mailbox: str) -> Recipient:
    return Recipient(
        recipient_id=uuid.uuid4(),
        employee_key="ek",
        mailbox=mailbox,
        status=dm.RecipientStatus.ACTIVE,
    )


def _run(
    monkeypatch: pytest.MonkeyPatch,
    *,
    campaign: Campaign,
    roe: RulesOfEngagement | None,
    template: TemplateVersion,
    assignments: list[RecipientAssignment],
    recipients: list[Recipient],
    roe_key: str = _KEY_HEX,
    send_error: Exception | None = None,
    stop_engaged: bool = False,
    suppressed: bool = False,
    excluded: set[uuid.UUID] | None = None,
    test_send: bool = False,
    launch_gate_reasons: list[str | None] | None = None,
    launch_gate_batches: list[list[str]] | None = None,
) -> tuple[WorkerContext, _Audit, list[bool]]:
    session = _Session()
    session.get_results[(SystemSafetyState, 1)] = SimpleNamespace(
        emergency_stop_engaged=stop_engaged,
        generation=1 if stop_engaged else 0,
    )
    session.get_results[(Campaign, campaign.campaign_id)] = campaign
    session.get_results[(TemplateVersion, campaign.current_template_id)] = template
    session.get_results[(CampaignPattern, campaign.pattern_id)] = CampaignPattern(
        campaign_pattern_id=campaign.pattern_id,
        lure_category=dm.LureCategory.OTHER,
        confidence=dm.Confidence.HIGH,
    )
    if roe is not None:
        session.get_results[(RulesOfEngagement, roe.roe_id)] = roe
    for assignment, recipient in zip(assignments, recipients, strict=True):
        session.get_results[(RecipientAssignment, assignment.recipient_assignment_id)] = assignment
        session.get_results[(Recipient, recipient.recipient_id)] = recipient
        if suppressed:
            session.get_results[(RecipientDeliverySuppression, recipient.recipient_id)] = SimpleNamespace(
                active=True,
                reason="bounced",
            )
        session.tokens.append(
            SimpleNamespace(
                token_hash="ab" * 32,
                recipient_assignment_id=assignment.recipient_assignment_id,
                status=dm.TokenStatus.ACTIVE,
                expires_at=_NOW + timedelta(days=30),
            )
        )

    @contextmanager
    def factory() -> Any:
        yield session

    audit = _Audit()
    # PLT-002: the default approval policy is now ENFORCE, which activates the
    # two-person approval lookup in the delivery path (jobs.py). These tests
    # isolate the RoE authorization boundary, so keep the historical single-admin
    # path (a marked dev stack) that skips that separate approval query.
    settings = WorkerSettings(
        _env_file=None,
        roe_signing_key=roe_key,
        runtime_mode="development",
        approval_policy="single-admin",
        dev_stack=True,
    )
    context = WorkerContext(settings, factory, audit, SimpleNamespace())  # type: ignore[arg-type]
    sent: list[bool] = []
    monkeypatch.setattr(
        "kp_workers.jobs.check_spf_for_mailbox",
        lambda _mailbox: SimpleNamespace(has_spf=True, domain="example.com"),
    )

    def send(*_args: Any, **_kwargs: Any) -> DeliveryReceipt:
        sent.append(True)
        if send_error is not None:
            raise send_error
        return DeliveryReceipt(message_id="<test@example.com>", provider_id="provider-test")

    monkeypatch.setattr("kp_workers.jobs._send_email", send)
    monkeypatch.setattr("kp_workers.jobs._make_batch_sender", lambda _ctx: MagicMock())
    # RoE tests isolate the authorization boundary below the independent
    # durable canary gate, which has its own focused contract suite. A test may
    # script the gate instead: `launch_gate_reasons` is consumed one entry per
    # call (the batch pre-flight first, then one call per attempted recipient)
    # and `launch_gate_batches` records the assignment ids each call was asked
    # about.
    scripted_reasons = list(launch_gate_reasons or [])

    def launch_gate(
        _session: Any,
        _campaign: Campaign,
        _payload: dict[str, Any],
        gate_assignment_ids: list[str],
        _settings: Any,
    ) -> tuple[None, str | None]:
        if launch_gate_batches is not None:
            launch_gate_batches.append(list(gate_assignment_ids))
        if not scripted_reasons:
            return None, None
        return None, scripted_reasons.pop(0)

    monkeypatch.setattr("kp_workers.jobs._launch_delivery_gate_reason", launch_gate)
    monkeypatch.setattr("kp_workers.jobs._refresh_canary_evidence", lambda *_args, **_kwargs: None)
    excluded_ids = frozenset(excluded or set())
    monkeypatch.setattr("kp_workers.jobs._excluded_recipient_ids", lambda *_args, **_kwargs: excluded_ids)

    def claim(_session: Any, assignment: RecipientAssignment, _campaign_id: uuid.UUID, *, claimed_at: datetime) -> Any:
        if assignment.send_state != dm.SendState.QUEUED or assignment.delivery_attempt_id is not None:
            return None
        attempt_id = uuid.uuid4()
        assignment.send_state = dm.SendState.SENDING
        assignment.delivery_attempt_id = attempt_id
        assignment.delivery_attempt_count = (assignment.delivery_attempt_count or 0) + 1
        assignment.delivery_claimed_at = claimed_at
        _session.commit()
        return attempt_id

    monkeypatch.setattr("kp_workers.jobs._claim_delivery", claim)
    payload = {
        "campaign_id": str(campaign.campaign_id),
        "recipient_assignment_ids": [str(a.recipient_assignment_id) for a in assignments],
        "template_hash": campaign.manifest_hash,
        "test_send": test_send,
        "tracking_bearers": {
            str(assignment.recipient_assignment_id): {
                "bearer": "A" * 43,
                "verifier": "ab" * 32,
                "checksum": hashlib.sha256(("A" * 43).encode("ascii")).hexdigest(),
            }
            for assignment in assignments
        },
    }
    process_delivery(context, {"payload": payload})
    return context, audit, sent


def test_delivery_fails_closed_while_persistent_emergency_stop_is_engaged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    roe = _make_roe()
    campaign = _make_campaign(roe=roe)
    recipient = _make_recipient("learner@example.com")
    assignment = _make_assignment(campaign, recipient.recipient_id)

    _, audit, sent = _run(
        monkeypatch,
        campaign=campaign,
        roe=roe,
        template=_make_template(),
        assignments=[assignment],
        recipients=[recipient],
        stop_engaged=True,
    )

    assert sent == []
    assert assignment.send_state == dm.SendState.QUEUED
    assert audit.records[0]["detail"] == {"reason": "global_emergency_stop"}


def test_delivery_fails_closed_without_roe(monkeypatch: pytest.MonkeyPatch) -> None:
    campaign = _make_campaign(roe=None)
    template = _make_template()
    context, audit, sent = _run(
        monkeypatch, campaign=campaign, roe=None, template=template, assignments=[], recipients=[]
    )
    assert sent == []
    assert audit.records[0]["action"] == "campaign.deliver.blocked"
    assert audit.records[0]["detail"] == {"reason": "no_roe"}


def test_delivery_fails_closed_on_invalid_roe_signature(monkeypatch: pytest.MonkeyPatch) -> None:
    roe = _make_roe(signature="0" * 64)
    campaign = _make_campaign(roe=roe)
    context, audit, sent = _run(
        monkeypatch, campaign=campaign, roe=roe, template=_make_template(), assignments=[], recipients=[]
    )
    assert sent == []
    assert audit.records[0]["detail"] == {"reason": "roe_signature_invalid"}


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("terms_hash", "f" * 64),
        ("signer", "attacker@example.com"),
        ("authorizing_party", "Other Corp"),
        ("target_domains", ["other.example"]),
        ("window_start", _NOW - timedelta(hours=1)),
        ("window_end", _NOW + timedelta(days=60)),
        ("signed_at", _NOW),
        ("signature_version", 1),
    ],
)
def test_delivery_rejects_mutation_of_any_signed_roe_field(
    monkeypatch: pytest.MonkeyPatch, field: str, value: object
) -> None:
    roe = _make_roe()
    setattr(roe, field, value)
    campaign = _make_campaign(roe=roe)
    _, audit, sent = _run(
        monkeypatch, campaign=campaign, roe=roe, template=_make_template(), assignments=[], recipients=[]
    )
    assert sent == []
    assert audit.records[0]["detail"] == {"reason": "roe_signature_invalid"}


def test_delivery_fails_closed_when_roe_key_unconfigured(monkeypatch: pytest.MonkeyPatch) -> None:
    roe = _make_roe()
    campaign = _make_campaign(roe=roe)
    context, audit, sent = _run(
        monkeypatch, campaign=campaign, roe=roe, template=_make_template(), assignments=[], recipients=[], roe_key=""
    )
    assert sent == []
    assert audit.records[0]["detail"] == {"reason": "roe_key_unconfigured"}


def test_delivery_fails_closed_when_roe_revoked(monkeypatch: pytest.MonkeyPatch) -> None:
    roe = _make_roe(revoked=True)
    campaign = _make_campaign(roe=roe)
    context, audit, sent = _run(
        monkeypatch, campaign=campaign, roe=roe, template=_make_template(), assignments=[], recipients=[]
    )
    assert sent == []
    assert audit.records[0]["detail"] == {"reason": "roe_not_active"}


def test_delivery_fails_closed_when_roe_window_passed(monkeypatch: pytest.MonkeyPatch) -> None:
    roe = _make_roe(window_days_ago=40, window_days_ahead=-10)
    campaign = _make_campaign(roe=roe)
    context, audit, sent = _run(
        monkeypatch, campaign=campaign, roe=roe, template=_make_template(), assignments=[], recipients=[]
    )
    assert sent == []
    assert audit.records[0]["detail"] == {"reason": "roe_not_active"}


def test_delivery_blocks_recipient_outside_roe_targets(monkeypatch: pytest.MonkeyPatch) -> None:
    roe = _make_roe(target_domains=["example.com"])
    campaign = _make_campaign(roe=roe)
    recipient = _make_recipient("user@elsewhere.com")
    assignment = _make_assignment(campaign, recipient.recipient_id)
    context, audit, sent = _run(
        monkeypatch,
        campaign=campaign,
        roe=roe,
        template=_make_template(),
        assignments=[assignment],
        recipients=[recipient],
    )
    assert sent == []
    assert assignment.send_state == dm.SendState.FAILED
    assert assignment.failure_reason == "target_domain_not_roe_covered"
    assert audit.records[0]["detail"]["blocked"] == 1


@pytest.mark.parametrize("recipient_status", [dm.RecipientStatus.DEPARTED, dm.RecipientStatus.EXCLUDED])
def test_delivery_blocks_directory_removed_or_disabled_recipient_even_from_frozen_assignment(
    monkeypatch: pytest.MonkeyPatch,
    recipient_status: dm.RecipientStatus,
) -> None:
    roe = _make_roe(target_domains=["example.com"])
    campaign = _make_campaign(roe=roe)
    recipient = _make_recipient("former-learner@example.com")
    recipient.status = recipient_status
    assignment = _make_assignment(campaign, recipient.recipient_id)

    _, _, sent = _run(
        monkeypatch,
        campaign=campaign,
        roe=roe,
        template=_make_template(),
        assignments=[assignment],
        recipients=[recipient],
    )

    assert sent == []
    assert assignment.send_state == dm.SendState.FAILED
    assert assignment.failure_reason == "recipient_unavailable"


def test_delivery_blocks_lookalike_target_domain_suffix(monkeypatch: pytest.MonkeyPatch) -> None:
    roe = _make_roe(target_domains=["example.com"])
    campaign = _make_campaign(roe=roe)
    recipient = _make_recipient("user@example.com.evil.test")
    assignment = _make_assignment(campaign, recipient.recipient_id)
    context, audit, sent = _run(
        monkeypatch,
        campaign=campaign,
        roe=roe,
        template=_make_template(),
        assignments=[assignment],
        recipients=[recipient],
    )
    assert sent == []
    assert assignment.failure_reason == "target_domain_not_roe_covered"


def test_delivery_sends_recipient_inside_roe_targets(monkeypatch: pytest.MonkeyPatch) -> None:
    roe = _make_roe(target_domains=["example.com"])
    campaign = _make_campaign(roe=roe)
    recipient = _make_recipient("user@mail.example.com")
    assignment = _make_assignment(campaign, recipient.recipient_id)
    context, audit, sent = _run(
        monkeypatch,
        campaign=campaign,
        roe=roe,
        template=_make_template(),
        assignments=[assignment],
        recipients=[recipient],
    )
    assert sent == [True]
    assert assignment.send_state == dm.SendState.ACCEPTED
    assert assignment.provider_accepted_at is not None
    assert assignment.delivery_confirmed_at is None
    assert audit.records[0]["action"] == "campaign.deliver"
    assert audit.records[0]["detail"]["roe_id"] == str(roe.roe_id)


def test_delivery_enforces_durable_provider_suppression_before_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    roe = _make_roe(target_domains=["example.com"])
    campaign = _make_campaign(roe=roe)
    recipient = _make_recipient("previously-bounced@example.com")
    assignment = _make_assignment(campaign, recipient.recipient_id)

    _, audit, sent = _run(
        monkeypatch,
        campaign=campaign,
        roe=roe,
        template=_make_template(),
        assignments=[assignment],
        recipients=[recipient],
        suppressed=True,
    )

    assert sent == []
    assert assignment.delivery_attempt_id is None
    assert assignment.send_state == dm.SendState.FAILED
    assert assignment.failure_reason == "recipient_suppressed"
    assert audit.records[0]["detail"]["blocked"] == 1


def test_delivery_blocks_recipient_outside_roe_even_when_allowlist_matches(monkeypatch: pytest.MonkeyPatch) -> None:
    # The RoE boundary is independent of and in addition to the configured
    # recipient allowlist: a domain on the allowlist but outside the RoE's
    # verified target set must still be refused.
    roe = _make_roe(target_domains=["example.com"])
    campaign = _make_campaign(roe=roe)
    recipient = _make_recipient("user@other.com")
    assignment = _make_assignment(campaign, recipient.recipient_id)
    context, audit, sent = _run(
        monkeypatch,
        campaign=campaign,
        roe=roe,
        template=_make_template(),
        assignments=[assignment],
        recipients=[recipient],
    )
    assert sent == []
    assert assignment.failure_reason == "target_domain_not_roe_covered"


def test_crash_after_provider_acceptance_is_not_automatically_resent(monkeypatch: pytest.MonkeyPatch) -> None:
    roe = _make_roe(target_domains=["example.com"])
    campaign = _make_campaign(roe=roe)
    recipient = _make_recipient("user@example.com")
    assignment = _make_assignment(campaign, recipient.recipient_id)

    def crash_before_result_commit(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("simulated worker loss after provider acceptance")

    monkeypatch.setattr("kp_workers.jobs._record_provider_acceptance", crash_before_result_commit)
    with pytest.raises(RuntimeError, match="simulated worker loss"):
        _run(
            monkeypatch,
            campaign=campaign,
            roe=roe,
            template=_make_template(),
            assignments=[assignment],
            recipients=[recipient],
        )
    assert assignment.send_state == dm.SendState.SENDING
    assert assignment.delivery_attempt_id is not None

    # A duplicate delivery job sees the durable claim and cannot call the
    # provider again, even though the acceptance result was never committed.
    _, _, duplicate_sends = _run(
        monkeypatch,
        campaign=campaign,
        roe=roe,
        template=_make_template(),
        assignments=[assignment],
        recipients=[recipient],
    )
    assert duplicate_sends == []


def test_transport_error_is_indeterminate_instead_of_retryable_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    roe = _make_roe(target_domains=["example.com"])
    campaign = _make_campaign(roe=roe)
    recipient = _make_recipient("user@example.com")
    assignment = _make_assignment(campaign, recipient.recipient_id)

    _, audit, sends = _run(
        monkeypatch,
        campaign=campaign,
        roe=roe,
        template=_make_template(),
        assignments=[assignment],
        recipients=[recipient],
        send_error=TimeoutError("provider response lost"),
    )

    assert sends == [True]
    assert assignment.send_state == dm.SendState.INDETERMINATE
    assert assignment.failure_reason == "provider_result_unknown"
    assert audit.records[0]["detail"]["indeterminate"] == 1


def test_permanent_5xx_refusal_is_a_definite_failure_not_indeterminate(monkeypatch: pytest.MonkeyPatch) -> None:
    # A hard 5xx means the relay accepted nothing: filing it INDETERMINATE would
    # strand the recipient forever (indeterminate is never retried).
    roe = _make_roe(target_domains=["example.com"])
    campaign = _make_campaign(roe=roe)
    recipient = _make_recipient("user@example.com")
    assignment = _make_assignment(campaign, recipient.recipient_id)

    _, audit, sends = _run(
        monkeypatch,
        campaign=campaign,
        roe=roe,
        template=_make_template(),
        assignments=[assignment],
        recipients=[recipient],
        send_error=smtplib.SMTPSenderRefused(550, b"sender rejected", "sender@example.com"),
    )

    assert sends == [True]
    assert assignment.send_state == dm.SendState.FAILED
    assert assignment.failure_reason == "provider_rejected"
    assert audit.records[0]["detail"]["failed"] == 1
    assert audit.records[0]["detail"]["indeterminate"] == 0


def test_recipients_refused_is_a_definite_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    roe = _make_roe(target_domains=["example.com"])
    campaign = _make_campaign(roe=roe)
    recipient = _make_recipient("user@example.com")
    assignment = _make_assignment(campaign, recipient.recipient_id)

    _, _audit, sends = _run(
        monkeypatch,
        campaign=campaign,
        roe=roe,
        template=_make_template(),
        assignments=[assignment],
        recipients=[recipient],
        send_error=smtplib.SMTPRecipientsRefused({"user@example.com": (550, b"no such user")}),
    )

    assert sends == [True]
    assert assignment.send_state == dm.SendState.FAILED
    assert assignment.failure_reason == "provider_rejected"


def test_transient_4xx_response_stays_indeterminate(monkeypatch: pytest.MonkeyPatch) -> None:
    # A 4xx is not a definite non-delivery, so the no-auto-retry indeterminate
    # contract is preserved rather than declaring a false FAILED.
    roe = _make_roe(target_domains=["example.com"])
    campaign = _make_campaign(roe=roe)
    recipient = _make_recipient("user@example.com")
    assignment = _make_assignment(campaign, recipient.recipient_id)

    _, _audit, sends = _run(
        monkeypatch,
        campaign=campaign,
        roe=roe,
        template=_make_template(),
        assignments=[assignment],
        recipients=[recipient],
        send_error=smtplib.SMTPResponseException(451, b"temporary local problem"),
    )

    assert sends == [True]
    assert assignment.send_state == dm.SendState.INDETERMINATE
    assert assignment.failure_reason == "provider_result_unknown"


def test_delivery_expires_a_freshly_excluded_recipient_before_send(monkeypatch: pytest.MonkeyPatch) -> None:
    # Exclusions are filtered at publish, but one added after the batch was
    # queued must still stop the send: the worker re-reads the active set.
    roe = _make_roe(target_domains=["example.com"])
    campaign = _make_campaign(roe=roe)
    recipient = _make_recipient("user@example.com")
    assignment = _make_assignment(campaign, recipient.recipient_id)

    _, audit, sends = _run(
        monkeypatch,
        campaign=campaign,
        roe=roe,
        template=_make_template(),
        assignments=[assignment],
        recipients=[recipient],
        excluded={recipient.recipient_id},
    )

    assert sends == []
    assert assignment.delivery_attempt_id is None
    assert assignment.send_state == dm.SendState.EXPIRED
    assert assignment.failure_reason == "recipient_excluded"
    assert audit.records[0]["detail"]["blocked"] == 1


def test_canary_test_send_still_requires_an_approved_template(monkeypatch: pytest.MonkeyPatch) -> None:
    # The canary (test_send=True) delivers to real reviewed mailboxes, so it may
    # not bypass template approval; an unapproved template fails closed.
    roe = _make_roe(target_domains=["example.com"])
    campaign = _make_campaign(roe=roe)
    recipient = _make_recipient("user@example.com")
    assignment = _make_assignment(campaign, recipient.recipient_id)
    template = _make_template()
    template.approval_state = dm.TemplateApprovalState.DRAFT

    with pytest.raises(SafetyRejectionError, match="approved template"):
        _run(
            monkeypatch,
            campaign=campaign,
            roe=roe,
            template=template,
            assignments=[assignment],
            recipients=[recipient],
            test_send=True,
        )


def test_canary_test_send_delivers_with_an_approved_template(monkeypatch: pytest.MonkeyPatch) -> None:
    # With approval intact, the canary still sends: removing the bypass does not
    # break the legitimate reviewed-cohort path.
    roe = _make_roe(target_domains=["example.com"])
    campaign = _make_campaign(roe=roe)
    recipient = _make_recipient("user@example.com")
    assignment = _make_assignment(campaign, recipient.recipient_id)

    _, _audit, sends = _run(
        monkeypatch,
        campaign=campaign,
        roe=roe,
        template=_make_template(),
        assignments=[assignment],
        recipients=[recipient],
        test_send=True,
    )

    assert sends == [True]
    assert assignment.send_state == dm.SendState.ACCEPTED


def test_launch_gate_is_re_evaluated_for_every_recipient_of_a_batch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ARC-002 M1-C: the in-loop launch-gate check cannot be hoisted.

    Three recipients, one batch. The gate passes the batch pre-flight and the
    first recipient, then a concurrent revocation lands (the loop commits
    between recipients, releasing the gate's row lock). The second recipient is
    refused and the batch stops before the third is ever claimed. A verdict
    computed once per run would have delivered to all three.
    """

    roe = _make_roe(target_domains=["example.com"])
    campaign = _make_campaign(roe=roe)
    recipients = [_make_recipient(f"learner{index}@example.com") for index in range(3)]
    assignments = [_make_assignment(campaign, recipient.recipient_id) for recipient in recipients]
    batches: list[list[str]] = []

    _, audit, sends = _run(
        monkeypatch,
        campaign=campaign,
        roe=roe,
        template=_make_template(),
        assignments=assignments,
        recipients=recipients,
        launch_gate_reasons=[None, None, "canary_evidence_expired"],
        launch_gate_batches=batches,
    )

    # Exactly one message reached the provider: the gated recipient set is
    # {second}, and the third is never even claimed.
    assert sends == [True]
    assert assignments[0].send_state == dm.SendState.ACCEPTED
    assert assignments[1].send_state == dm.SendState.EXPIRED
    assert assignments[1].failure_reason == "canary_evidence_expired"
    assert assignments[2].send_state == dm.SendState.QUEUED
    assert assignments[2].delivery_attempt_id is None

    # The pre-flight sees the whole batch; each in-loop call sees one id.
    assert batches[0] == [str(assignment.recipient_assignment_id) for assignment in assignments]
    assert batches[1:] == [
        [str(assignments[0].recipient_assignment_id)],
        [str(assignments[1].recipient_assignment_id)],
    ]

    blocked = [record for record in audit.records if record["action"] == "campaign.deliver.blocked"]
    assert blocked[0]["detail"] == {
        "reason": "canary_evidence_expired",
        "assignment_id": str(assignments[1].recipient_assignment_id),
    }
    summary = [record for record in audit.records if record["action"] == "campaign.deliver"][0]
    assert summary["detail"]["sent"] == 1
    assert summary["detail"]["blocked"] == 1


def test_batch_gates_and_sends_the_same_recipients_regardless_of_batch_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The gated-recipient set is a property of the recipients, not the batch.

    One recipient outside the signed RoE target domains, two inside. With the
    gate steady, the outcome per recipient is identical whether they are
    delivered as one batch of three or as three batches of one.
    """

    def outcomes(batch: list[int]) -> list[tuple[dm.SendState, str | None]]:
        roe = _make_roe(target_domains=["example.com"])
        campaign = _make_campaign(roe=roe)
        mailboxes = ["inside0@example.com", "outside@other.example", "inside1@example.com"]
        recipients = [_make_recipient(mailboxes[index]) for index in batch]
        assignments = [_make_assignment(campaign, recipient.recipient_id) for recipient in recipients]
        _run(
            monkeypatch,
            campaign=campaign,
            roe=roe,
            template=_make_template(),
            assignments=assignments,
            recipients=recipients,
        )
        return [(assignment.send_state, assignment.failure_reason) for assignment in assignments]

    together = outcomes([0, 1, 2])
    separate = [outcomes([index])[0] for index in (0, 1, 2)]

    assert together == separate
    assert together == [
        (dm.SendState.ACCEPTED, None),
        (dm.SendState.FAILED, "target_domain_not_roe_covered"),
        (dm.SendState.ACCEPTED, None),
    ]
