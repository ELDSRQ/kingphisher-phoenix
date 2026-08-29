"""TRN-010 tests for the deterministic campaign training-draft endpoint."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from kp_authorization import Principal, Role
from kp_database.models import Campaign, CampaignPattern, TemplateVersion, TrainingResource
from kp_domain_models import models as dm
from kp_operator_api.training_library import draft_campaign_training
from kp_telemetry.errors import ConflictError, NotFoundError


class _Session:
    def __init__(self, rows: dict[uuid.UUID, object]) -> None:
        self.rows = rows

    def get(self, model: object, identifier: uuid.UUID, **kwargs: object) -> object | None:
        del model, kwargs
        return self.rows.get(identifier)


def _approved_template(template_id: uuid.UUID) -> TemplateVersion:
    return TemplateVersion(
        template_version_id=template_id,
        campaign_id=uuid.uuid4(),
        version=3,
        idempotency_key=f"approved-template-{template_id}",
        generator_version="generator-v1",
        prompt_template_version="prompt-v2",
        model_id="model-safe",
        input_hash="a" * 64,
        raw_proposal={},
        edited_content={"subject": "Reset your password"},
        safe_html="<p>Password reset warning signs.</p>",
        plain_text="Password reset warning signs.",
        subject="Reset your password",
        synthetic_sender_display="IT Helpdesk",
        learning_objectives=["Recognize password-reset lures"],
        warning_cues=["Spoofed sender", "Urgent deadline"],
        training_explanation="Attackers send fake password-reset notices to steal credentials.",
        approval_hash="b" * 64,
        approval_state=dm.TemplateApprovalState.APPROVED,
    )


def _pattern(pattern_id: uuid.UUID) -> CampaignPattern:
    return CampaignPattern(
        campaign_pattern_id=pattern_id,
        pattern_version=1,
        lure_category=dm.LureCategory.PASSWORD_RESET,
        impersonation_category="IT Helpdesk",
        requested_action="Reset your password now",
        emotional_triggers=["Urgent deadline"],
        warning_cues=["Spoofed sender"],
        attack_mapping={"difficulty": {"score": 1}},
        confidence=dm.Confidence.HIGH,
        approval_state=dm.PatternApprovalState.APPROVED,
    )


def _campaign(campaign_id: uuid.UUID, template_id: uuid.UUID, pattern_id: uuid.UUID) -> Campaign:
    now = datetime.now(UTC)
    return Campaign(
        campaign_id=campaign_id,
        pattern_id=pattern_id,
        current_template_id=template_id,
        title="Password reset drill",
        state=dm.CampaignState.DRAFT,
        sender_mailbox="awareness@example.com",
        training_domain="training.example.com",
        timezone="UTC",
        max_recipients=10,
        expires_at=now + timedelta(days=2),
    )


def test_draft_is_deterministic_and_derived_from_approved_evidence() -> None:
    campaign_id = uuid.uuid4()
    template = _approved_template(uuid.uuid4())
    pattern = _pattern(uuid.uuid4())
    session = _Session({campaign_id: _campaign(campaign_id, template.template_version_id, pattern.campaign_pattern_id)})
    session.rows[template.template_version_id] = template
    session.rows[pattern.campaign_pattern_id] = pattern

    first = draft_campaign_training(
        campaign_id,
        session=session,  # type: ignore[arg-type]
        principal=Principal(str(uuid.uuid4()), {Role.CAMPAIGN_AUTHOR}),
    )
    second = draft_campaign_training(
        campaign_id,
        session=session,  # type: ignore[arg-type]
        principal=Principal(str(uuid.uuid4()), {Role.CAMPAIGN_AUTHOR}),
    )
    assert first == second
    assert first["content_type"] == "text/plain"
    assert first["basis"]["builder"] == "deterministic-training-builder-v1"
    assert first["basis"]["template_version_id"] == str(template.template_version_id)
    assert first["basis"]["pattern_id"] == str(pattern.campaign_pattern_id)

    check = first["knowledge_check"]
    assert "password" in check["question"]
    assert check["options"][check["answer_index"]] == "Verify the request through a trusted, independent channel"
    assert len(first["title"]) <= 160
    assert 1 <= len(first["content"]) <= 20_000


def test_draft_fails_closed_without_an_approved_template() -> None:
    campaign_id = uuid.uuid4()
    template = _approved_template(uuid.uuid4())
    template.approval_state = dm.TemplateApprovalState.DRAFT
    pattern = _pattern(uuid.uuid4())
    session = _Session({campaign_id: _campaign(campaign_id, template.template_version_id, pattern.campaign_pattern_id)})
    session.rows[template.template_version_id] = template
    session.rows[pattern.campaign_pattern_id] = pattern

    with pytest.raises(ConflictError, match="no approved template"):
        draft_campaign_training(
            campaign_id,
            session=session,  # type: ignore[arg-type]
            principal=Principal(str(uuid.uuid4()), {Role.CAMPAIGN_AUTHOR}),
        )


def test_draft_fails_closed_for_unknown_campaign_or_missing_pattern() -> None:
    with pytest.raises(NotFoundError, match="campaign not found"):
        draft_campaign_training(
            uuid.uuid4(),
            session=_Session({}),  # type: ignore[arg-type]
            principal=Principal(str(uuid.uuid4()), {Role.CAMPAIGN_AUTHOR}),
        )

    campaign_id = uuid.uuid4()
    template = _approved_template(uuid.uuid4())
    session = _Session({campaign_id: _campaign(campaign_id, template.template_version_id, uuid.uuid4())})
    session.rows[template.template_version_id] = template
    with pytest.raises(ConflictError, match="pattern is unavailable"):
        draft_campaign_training(
            campaign_id,
            session=session,  # type: ignore[arg-type]
            principal=Principal(str(uuid.uuid4()), {Role.CAMPAIGN_AUTHOR}),
        )


def test_draft_never_writes_a_resource_or_touches_approval_state() -> None:
    campaign_id = uuid.uuid4()
    template = _approved_template(uuid.uuid4())
    pattern = _pattern(uuid.uuid4())
    session = _Session({campaign_id: _campaign(campaign_id, template.template_version_id, pattern.campaign_pattern_id)})
    session.rows[template.template_version_id] = template
    session.rows[pattern.campaign_pattern_id] = pattern
    before = set(session.rows)

    draft_campaign_training(
        campaign_id,
        session=session,  # type: ignore[arg-type]
        principal=Principal(str(uuid.uuid4()), {Role.CAMPAIGN_AUTHOR}),
    )
    assert set(session.rows) == before
    assert not any(isinstance(value, TrainingResource) for value in session.rows.values())
    assert template.approval_state == dm.TemplateApprovalState.APPROVED
