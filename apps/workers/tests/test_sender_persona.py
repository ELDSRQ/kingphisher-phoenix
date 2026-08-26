"""Sender-persona resolution and From-header formatting.

The persona is display name + local part + pool domain. The pool is the
deliverability truth: a persona mailbox is honored only on a registered
sending domain, otherwise the envelope falls back to the configured sender
so mail is not sent as an unauthenticated domain.
"""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

from kp_database.models import Campaign, CampaignPattern, TemplateVersion
from kp_domain_models import models as dm
from kp_workers.config import WorkerSettings
from kp_workers.jobs import WorkerContext, _send_email, effective_sender_address


def _context(settings: WorkerSettings) -> WorkerContext:
    @contextmanager
    def factory() -> Any:
        yield SimpleNamespace()

    return WorkerContext(settings, factory, SimpleNamespace(record=lambda **_k: None), SimpleNamespace())  # type: ignore[arg-type]


def _campaign(*, mailbox: str, display_name: str | None) -> Campaign:
    now = datetime.now(UTC)
    return Campaign(
        campaign_id=uuid.uuid4(),
        pattern_id=uuid.uuid4(),
        current_template_id=uuid.uuid4(),
        title="persona test",
        state=dm.CampaignState.SCHEDULED,
        sender_mailbox=mailbox,
        sender_display_name=display_name,
        training_domain="example.com",
        max_recipients=10,
        expires_at=now + timedelta(days=1),
    )


def test_effective_sender_address_empty_pool_honors_request() -> None:
    ctx = _context(WorkerSettings(_env_file=None, smtp_sender="fallback@example.com"))
    campaign = _campaign(mailbox="alerts@corp-benefits.example", display_name=None)
    address, honored = effective_sender_address(ctx, campaign)
    assert address == "alerts@corp-benefits.example"
    assert honored is True


def test_effective_sender_address_pool_honors_registered_domain() -> None:
    settings = WorkerSettings(
        _env_file=None, smtp_sender="fallback@example.com", sending_domains="corp-benefits.example"
    )
    ctx = _context(settings)
    campaign = _campaign(mailbox="payroll@corp-benefits.example", display_name=None)
    address, honored = effective_sender_address(ctx, campaign)
    assert address == "payroll@corp-benefits.example"
    assert honored is True


def test_effective_sender_address_pool_honors_subdomain() -> None:
    settings = WorkerSettings(
        _env_file=None, smtp_sender="fallback@example.com", sending_domains="corp-training.example"
    )
    ctx = _context(settings)
    campaign = _campaign(mailbox="alerts@secure.corp-training.example", display_name=None)
    address, honored = effective_sender_address(ctx, campaign)
    assert address == "alerts@secure.corp-training.example"
    assert honored is True


def test_effective_sender_address_pool_falls_back_for_unregistered_domain() -> None:
    settings = WorkerSettings(
        _env_file=None, smtp_sender="fallback@example.com", sending_domains="corp-training.example"
    )
    ctx = _context(settings)
    campaign = _campaign(mailbox="alerts@notexample.com", display_name=None)
    address, honored = effective_sender_address(ctx, campaign)
    assert address == "fallback@example.com"
    assert honored is False


def test_effective_sender_address_pool_lookalike_suffix_is_not_honored() -> None:
    settings = WorkerSettings(
        _env_file=None, smtp_sender="fallback@example.com", sending_domains="corp-training.example"
    )
    ctx = _context(settings)
    campaign = _campaign(mailbox="alerts@corp-training.example.attacker.test", display_name=None)
    address, honored = effective_sender_address(ctx, campaign)
    assert address == "fallback@example.com"
    assert honored is False


def test_effective_sender_address_acs_overrides_persona() -> None:
    settings = WorkerSettings(
        _env_file=None,
        smtp_sender="phoenix@azurecomm.example",
        email_provider="azure_communication_services",
        acs_email_endpoint="https://example.com",
    )
    ctx = _context(settings)
    campaign = _campaign(mailbox="alerts@corp-benefits.example", display_name="Account Security")
    address, honored = effective_sender_address(ctx, campaign)
    assert address == "phoenix@azurecomm.example"
    assert honored is False


def _send(campaign: Campaign, template: TemplateVersion, *, settings: WorkerSettings) -> list[Any]:
    ctx = _context(settings)
    recipient = SimpleNamespace(
        recipient_id=uuid.uuid4(),
        mailbox="learner@example.com",
        display_name="Learner",
        department="IT",
    )
    assignment = SimpleNamespace(recipient_id=recipient.recipient_id)
    token = SimpleNamespace(token_hash="ab" * 32)
    pattern = CampaignPattern(
        campaign_pattern_id=campaign.pattern_id,
        lure_category=dm.LureCategory.OTHER,
        confidence=dm.Confidence.HIGH,
    )
    captured: list[Any] = []
    sender = MagicMock(send=lambda msg: captured.append(msg))
    _send_email(ctx, campaign, template, pattern, assignment, recipient, token, sender=sender)
    return captured


def test_from_header_includes_display_name() -> None:
    campaign = _campaign(mailbox="alerts@corp-benefits.example", display_name="Account Security")
    template = TemplateVersion(
        template_version_id=campaign.current_template_id,
        generator_version="a",
        prompt_template_version="a",
        model_id="m",
        input_hash="i" * 64,
        subject="hello",
        plain_text="hello world",
        approval_state=dm.TemplateApprovalState.APPROVED,
    )
    captured = _send(campaign, template, settings=WorkerSettings(_env_file=None))
    assert captured[0]["From"] == "Account Security <alerts@corp-benefits.example>"


def test_from_header_bare_address_without_display_name() -> None:
    campaign = _campaign(mailbox="alerts@corp-benefits.example", display_name=None)
    template = TemplateVersion(
        template_version_id=campaign.current_template_id,
        generator_version="a",
        prompt_template_version="a",
        model_id="m",
        input_hash="i" * 64,
        subject="hello",
        plain_text="hello world",
        approval_state=dm.TemplateApprovalState.APPROVED,
    )
    captured = _send(campaign, template, settings=WorkerSettings(_env_file=None))
    assert captured[0]["From"] == "alerts@corp-benefits.example"


def test_from_header_falls_back_to_default_sender_off_pool() -> None:
    campaign = _campaign(mailbox="alerts@notexample.com", display_name="Account Security")
    template = TemplateVersion(
        template_version_id=campaign.current_template_id,
        generator_version="a",
        prompt_template_version="a",
        model_id="m",
        input_hash="i" * 64,
        subject="hello",
        plain_text="hello world",
        approval_state=dm.TemplateApprovalState.APPROVED,
    )
    settings = WorkerSettings(
        _env_file=None, smtp_sender="fallback@example.com", sending_domains="corp-training.example"
    )
    captured = _send(campaign, template, settings=settings)
    assert captured[0]["From"] == "Account Security <fallback@example.com>"
