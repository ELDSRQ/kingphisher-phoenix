from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from kp_authorization import Principal, Role
from kp_database.campaign_service import bind_campaign_training_resource
from kp_database.models import Campaign, TrainingResource
from kp_domain_models import models as dm
from kp_operator_api.routers import (
    CampaignCreate,
    CampaignTrainingBindingUpdate,
    _training_binding_view,
    update_campaign_training_resource,
)
from kp_telemetry.errors import ConflictError
from pydantic import ValidationError


class _Session:
    def __init__(self, campaign: Campaign, resource: TrainingResource) -> None:
        self.campaign = campaign
        self.resource = resource
        self.executed: list[object] = []
        self.committed = False

    def scalar(self, statement: object) -> Campaign:  # noqa: ARG002
        return self.campaign

    def get(self, model: object, identifier: object, **kwargs: object) -> TrainingResource | None:  # noqa: ARG002
        return self.resource if identifier == self.resource.training_resource_id else None

    def execute(self, statement: object) -> None:
        self.executed.append(statement)

    def commit(self) -> None:
        self.committed = True


class _Audit:
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    def record(self, **kwargs: object) -> None:
        self.events.append(kwargs)


def _campaign(*, state: dm.CampaignState = dm.CampaignState.DRAFT) -> Campaign:
    now = datetime.now(UTC)
    return Campaign(
        campaign_id=uuid4(),
        pattern_id=uuid4(),
        current_template_id=uuid4(),
        title="Campaign lesson route",
        state=state,
        sender_mailbox="awareness@example.com",
        training_domain="training.example.com",
        schedule_start=now + timedelta(days=1),
        schedule_end=now + timedelta(days=2),
        timezone="UTC",
        max_recipients=10,
        expires_at=now + timedelta(days=2),
    )


def _resource(*, state: dm.TemplateApprovalState = dm.TemplateApprovalState.APPROVED) -> TrainingResource:
    return TrainingResource(
        training_resource_id=uuid4(),
        title="Review urgent requests",
        kind="article",
        content="Pause and verify through a trusted channel.",
        version=2,
        requires_completion=True,
        approval_state=state,
    )


def test_campaign_create_contract_requires_explicit_training_resource_id() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValidationError) as excinfo:
        CampaignCreate.model_validate(
            {
                "pattern_id": str(uuid4()),
                "template_version_id": str(uuid4()),
                "title": "Missing lesson",
                "sender_mailbox": "awareness@example.com",
                "training_domain": "training.example.com",
                "schedule_start": now.isoformat(),
                "schedule_end": (now + timedelta(hours=1)).isoformat(),
                "max_recipients": 1,
            }
        )
    assert any(error["loc"] == ("training_resource_id",) for error in excinfo.value.errors())


def test_rebinding_reviewed_campaign_resets_approvals_and_exposes_exact_lesson() -> None:
    campaign = _campaign(state=dm.CampaignState.APPROVED)
    prior = _resource()
    bind_campaign_training_resource(campaign, prior)
    replacement = _resource()
    session = _Session(campaign, replacement)
    audit = _Audit()

    response = update_campaign_training_resource(
        campaign.campaign_id,
        CampaignTrainingBindingUpdate(training_resource_id=replacement.training_resource_id),
        session=session,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        principal=Principal(str(uuid4()), {Role.CAMPAIGN_AUTHOR}),
    )

    assert response["changed"] is True
    assert campaign.state is dm.CampaignState.DRAFT
    assert campaign.training_resource_id == replacement.training_resource_id
    assert response["training_lesson"] == _training_binding_view(campaign, replacement)
    assert response["training_lesson"]["ready"] is True
    assert session.executed and session.committed
    assert audit.events[0]["action"] == "campaign.training_resource.bind"


def test_scheduled_or_superseded_rebinding_is_rejected_without_mutation() -> None:
    scheduled = _campaign(state=dm.CampaignState.SCHEDULED)
    approved = _resource()
    session = _Session(scheduled, approved)
    with pytest.raises(ConflictError, match="create a new campaign"):
        update_campaign_training_resource(
            scheduled.campaign_id,
            CampaignTrainingBindingUpdate(training_resource_id=approved.training_resource_id),
            session=session,  # type: ignore[arg-type]
            audit=_Audit(),  # type: ignore[arg-type]
            principal=Principal(str(uuid4()), {Role.CAMPAIGN_AUTHOR}),
        )
    assert not session.committed

    draft = _campaign()
    superseded = _resource(state=dm.TemplateApprovalState.SUPERSEDED)
    session = _Session(draft, superseded)
    with pytest.raises(ConflictError, match="select an approved training lesson"):
        update_campaign_training_resource(
            draft.campaign_id,
            CampaignTrainingBindingUpdate(training_resource_id=superseded.training_resource_id),
            session=session,  # type: ignore[arg-type]
            audit=_Audit(),  # type: ignore[arg-type]
            principal=Principal(str(uuid4()), {Role.CAMPAIGN_AUTHOR}),
        )
    assert not session.committed
