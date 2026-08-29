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

import pytest
from kp_contracts.generation import TRAINING_URL_PLACEHOLDER
from kp_database.models import Campaign, CampaignPattern, TemplateVersion
from kp_domain_models import models as dm
from kp_telemetry.errors import SafetyRejectionError
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


def _send(
    campaign: Campaign,
    template: TemplateVersion,
    *,
    settings: WorkerSettings,
    lure_category: dm.LureCategory = dm.LureCategory.OTHER,
) -> list[Any]:
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
        lure_category=lure_category,
        confidence=dm.Confidence.HIGH,
    )
    captured: list[Any] = []
    sender = MagicMock(send=lambda msg: captured.append(msg))
    _send_email(
        ctx,
        campaign,
        template,
        pattern,
        assignment,
        recipient,
        token,
        tracking_bearer="A" * 43,
        sender=sender,
    )
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
        plain_text=f"hello world {TRAINING_URL_PLACEHOLDER}",
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
        plain_text=f"hello world {TRAINING_URL_PLACEHOLDER}",
        approval_state=dm.TemplateApprovalState.APPROVED,
    )
    captured = _send(campaign, template, settings=WorkerSettings(_env_file=None))
    assert captured[0]["From"] == "alerts@corp-benefits.example"


def test_rendered_training_url_uses_recipient_click_bearer_not_static_destination_or_verifier(
    caplog: pytest.LogCaptureFixture,
) -> None:
    campaign = _campaign(mailbox="alerts@corp-benefits.example", display_name=None)
    template = TemplateVersion(
        template_version_id=campaign.current_template_id,
        generator_version="a",
        prompt_template_version="a",
        model_id="m",
        input_hash="i" * 64,
        subject="hello",
        plain_text=f"Review the awareness link: {TRAINING_URL_PLACEHOLDER}",
        safe_html=f'<a href="{TRAINING_URL_PLACEHOLDER}">Review</a>',
        approval_state=dm.TemplateApprovalState.APPROVED,
    )
    settings = WorkerSettings(_env_file=None, training_base_url="https://training.example.com/awareness")
    captured = _send(campaign, template, settings=settings)
    message = captured[0]
    plain = message.get_body(preferencelist=("plain",)).get_content()
    rendered_html = message.get_body(preferencelist=("html",)).get_content()
    expected = f"{settings.tracking_base_url.rstrip('/')}/v1/track/click/{'A' * 43}"
    assert expected in plain
    assert expected in rendered_html
    assert settings.training_base_url not in f"{plain}\n{rendered_html}"
    assert "ab" * 32 not in f"{plain}\n{rendered_html}"
    assert "A" * 43 not in caplog.text
    assert "ab" * 32 not in caplog.text


def test_calendar_invite_uses_existing_recipient_bound_click_url() -> None:
    campaign = _campaign(mailbox="alerts@corp-benefits.example", display_name=None)
    template = TemplateVersion(
        template_version_id=campaign.current_template_id,
        generator_version="a",
        prompt_template_version="a",
        model_id="m",
        input_hash="i" * 64,
        subject="Security awareness calendar exercise",
        plain_text=f"Review the awareness exercise: {TRAINING_URL_PLACEHOLDER}",
        approval_state=dm.TemplateApprovalState.APPROVED,
    )
    settings = WorkerSettings(
        _env_file=None,
        tracking_base_url="https://tracking.example",
        training_base_url="https://training.example.com/awareness",
    )

    message = _send(
        campaign,
        template,
        settings=settings,
        lure_category=dm.LureCategory.CALENDAR_INVITE,
    )[0]

    calendar_part = next(part for part in message.walk() if part.get_content_type() == "text/calendar")
    calendar_text = calendar_part.get_payload(decode=True).decode("utf-8")
    expected_url = f"{settings.tracking_base_url}/v1/track/click/{'A' * 43}"
    assert f"URL:{expected_url}\r\n" in calendar_text
    assert f"Open the tracked security-awareness exercise: {expected_url}" in calendar_text
    assert settings.training_base_url not in calendar_text
    assert "ATTACH:" not in calendar_text


@pytest.mark.parametrize(
    ("subject", "plain_text", "safe_html"),
    [
        ("   ", f"Review {TRAINING_URL_PLACEHOLDER}", ""),
        ("Approved subject", "   ", ""),
        ("Approved subject", "provider-secret-never-echo", ""),
        (
            "Approved subject",
            f"Review {TRAINING_URL_PLACEHOLDER}",
            "<p>provider-secret-never-echo</p>",
        ),
    ],
)
def test_delivery_rejects_incomplete_or_unbound_approved_content_without_echoing_it(
    subject: str,
    plain_text: str,
    safe_html: str,
) -> None:
    campaign = _campaign(mailbox="alerts@corp-benefits.example", display_name=None)
    template = TemplateVersion(
        template_version_id=campaign.current_template_id,
        generator_version="a",
        prompt_template_version="a",
        model_id="m",
        input_hash="i" * 64,
        subject=subject,
        plain_text=plain_text,
        safe_html=safe_html,
        approval_state=dm.TemplateApprovalState.APPROVED,
    )

    with pytest.raises(
        SafetyRejectionError,
        match="approved template content is incomplete or not recipient-bound",
    ) as caught:
        _send(campaign, template, settings=WorkerSettings(_env_file=None))

    assert "provider-secret-never-echo" not in str(caught.value)


@pytest.mark.parametrize(
    ("plain_text", "safe_html"),
    [
        ("Use https://training.example.com/awareness", ""),
        ("Use https://training.example.com:443/awareness?source=email", ""),
        ("Use the training page", '<a href="https&#58;//training.example.com/awareness/">Training</a>'),
        ("Use the training page", '<a href="https%3A%2F%2Ftraining.example.com%2Fawareness">Training</a>'),
    ],
)
def test_delivery_rejects_legacy_static_training_destination(plain_text: str, safe_html: str) -> None:
    campaign = _campaign(mailbox="alerts@corp-benefits.example", display_name=None)
    template = TemplateVersion(
        template_version_id=campaign.current_template_id,
        generator_version="a",
        prompt_template_version="a",
        model_id="m",
        input_hash="i" * 64,
        subject="hello",
        plain_text=f"{plain_text} {TRAINING_URL_PLACEHOLDER}",
        safe_html=f'{safe_html}<a href="{TRAINING_URL_PLACEHOLDER}">Review</a>' if safe_html else "",
        approval_state=dm.TemplateApprovalState.APPROVED,
    )
    settings = WorkerSettings(_env_file=None, training_base_url="https://training.example.com/awareness")

    with pytest.raises(SafetyRejectionError, match="static training URL"):
        _send(campaign, template, settings=settings)


def test_from_header_falls_back_to_default_sender_off_pool() -> None:
    campaign = _campaign(mailbox="alerts@notexample.com", display_name="Account Security")
    template = TemplateVersion(
        template_version_id=campaign.current_template_id,
        generator_version="a",
        prompt_template_version="a",
        model_id="m",
        input_hash="i" * 64,
        subject="hello",
        plain_text=f"hello world {TRAINING_URL_PLACEHOLDER}",
        approval_state=dm.TemplateApprovalState.APPROVED,
    )
    settings = WorkerSettings(
        _env_file=None, smtp_sender="fallback@example.com", sending_domains="corp-training.example"
    )
    captured = _send(campaign, template, settings=settings)
    assert captured[0]["From"] == "Account Security <fallback@example.com>"
