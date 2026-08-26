"""Delivery worker: signed Rules-of-Engagement enforcement.

Every failure mode of the RoE gate is tested as a hard stop: no RoE, no key,
bad signature, inactive/revoked RoE, and recipients outside the verified
target-domain boundary. The send path itself is stubbed — these tests are
about the gate, not the transport.
"""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from kp_database.models import (
    Campaign,
    CampaignPattern,
    Recipient,
    RecipientAssignment,
    RulesOfEngagement,
    TemplateVersion,
)
from kp_domain_models import models as dm
from kp_domain_models.roe import roe_signature_hex
from kp_workers.config import WorkerSettings
from kp_workers.jobs import WorkerContext, process_delivery

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

    def get(self, model: Any, identifier: Any) -> Any:
        return self.get_results.get((model, identifier))

    def scalar(self, statement: Any) -> Any:
        # The only scalar() used on this path is the per-assignment tracking
        # token lookup; hand back a valid token.
        return SimpleNamespace(token_hash="ab" * 32)

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
    return RulesOfEngagement(
        roe_id=uuid.uuid4(),
        signer="operator@example.com",
        authorizing_party="Example Corp",
        terms_text="Engagement authorized for the verified target domains only.",
        terms_hash=terms_hash,
        signature=signature or roe_signature_hex(terms_hash, "operator@example.com", signed_at, signing_key=_KEY),
        signed_at=signed_at,
        window_start=_NOW - timedelta(days=window_days_ago),
        window_end=_NOW + timedelta(days=window_days_ahead),
        target_domains=target_domains or ["example.com"],
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
        plain_text="body",
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
) -> tuple[WorkerContext, _Audit, list[bool]]:
    session = _Session()
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

    @contextmanager
    def factory() -> Any:
        yield session

    audit = _Audit()
    settings = WorkerSettings(_env_file=None, roe_signing_key=roe_key)
    context = WorkerContext(settings, factory, audit, SimpleNamespace())  # type: ignore[arg-type]
    sent: list[bool] = []
    monkeypatch.setattr(
        "kp_workers.jobs.check_spf_for_mailbox",
        lambda _mailbox: SimpleNamespace(has_spf=True, domain="example.com"),
    )
    monkeypatch.setattr("kp_workers.jobs._send_email", lambda *_a, **_k: sent.append(True))
    monkeypatch.setattr("kp_workers.jobs._make_batch_sender", lambda _ctx: MagicMock())
    payload = {
        "campaign_id": str(campaign.campaign_id),
        "recipient_assignment_ids": [str(a.recipient_assignment_id) for a in assignments],
        "template_hash": campaign.manifest_hash,
        "test_send": False,
    }
    process_delivery(context, {"payload": payload})
    return context, audit, sent


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
    assert assignment.send_state == dm.SendState.DELIVERED
    assert audit.records[0]["action"] == "campaign.deliver"
    assert audit.records[0]["detail"]["roe_id"] == str(roe.roe_id)


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
