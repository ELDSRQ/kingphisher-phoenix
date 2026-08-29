from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from fastapi import HTTPException
from kp_authorization.rbac import Principal, Role
from kp_database.models import Campaign, CampaignApproval, CampaignAudience, CampaignLaunchGate, CampaignPattern
from kp_domain_models import models as dm
from kp_domain_models.policy import ApprovalPolicy
from kp_operator_api.content_library import _pattern_action_flags
from kp_operator_api.routers import (
    _PRIVACY_EXPORT_RECORD_LIMIT,
    _bounded_privacy_export_rows,
    _campaign_action_flags,
)
from sqlalchemy import select


def _campaign(*, state: dm.CampaignState, creator_id: UUID, roe_bound: bool = True) -> Campaign:
    now = datetime.now(UTC)
    return Campaign(
        campaign_id=uuid4(),
        pattern_id=uuid4(),
        current_template_id=uuid4(),
        title="Authority matrix",
        state=state,
        sender_mailbox="sender@example.com",
        training_domain="training.example.com",
        schedule_start=now + timedelta(days=1),
        schedule_end=now + timedelta(days=2),
        timezone="UTC",
        max_recipients=10,
        roe_id=uuid4() if roe_bound else None,
        created_by=creator_id,
        expires_at=now + timedelta(days=2),
    )


def _audience(campaign: Campaign, *, frozen: bool = True) -> CampaignAudience:
    return CampaignAudience(
        campaign_id=campaign.campaign_id,
        version=1,
        group_ids=[],
        departments=[],
        statuses=[dm.RecipientStatus.ACTIVE.value],
        include_recipient_ids=[],
        exclude_recipient_ids=[],
        configuration_hash="a" * 64,
        manifest_hash="b" * 64,
        frozen_at=datetime.now(UTC) if frozen else None,
        legacy_requires_configuration=False,
    )


def _launch_gate(campaign: Campaign, *, state: str = "reviewed") -> CampaignLaunchGate:
    now = datetime.now(UTC)
    return CampaignLaunchGate(
        campaign_id=campaign.campaign_id,
        review_manifest_hash="c" * 64,
        content_manifest_hash="d" * 64,
        template_approval_hash="e" * 64,
        audience_manifest_hash="b" * 64,
        canary_manifest_hash="f" * 64,
        roe_id=campaign.roe_id,
        state=state,
        canary_expires_at=now + timedelta(hours=12) if state == "canary_succeeded" else None,
        canary_evidence_hash="9" * 64 if state == "canary_succeeded" else None,
        canary_succeeded_at=now if state == "canary_succeeded" else None,
        provider="smtp" if state == "canary_succeeded" else None,
        provider_config_hash="8" * 64 if state == "canary_succeeded" else None,
    )


def _approval(
    campaign: Campaign,
    approval_type: dm.ApprovalType,
    approver_id: UUID,
) -> CampaignApproval:
    return CampaignApproval(
        campaign_approval_id=uuid4(),
        campaign_id=campaign.campaign_id,
        approval_type=approval_type,
        approver_id=approver_id,
        decision=dm.ApprovalDecision.APPROVED,
        rationale="reviewed",
        decided_at=datetime.now(UTC),
        template_version_id=campaign.current_template_id,
        launch_manifest_hash="c" * 64,
    )


def test_campaign_flags_canonicalize_uuid_and_block_creator_review() -> None:
    creator_id = UUID("abcdefab-cdef-abcd-efab-cdefabcdefab")
    campaign = _campaign(state=dm.CampaignState.PENDING_APPROVAL, creator_id=creator_id)
    principal = Principal(str(creator_id).upper(), {Role.ADMINISTRATOR})

    flags = _campaign_action_flags(
        campaign,
        _audience(campaign),
        [],
        principal,
        ApprovalPolicy.ENFORCE,
        launch_gate=_launch_gate(campaign),
    )

    assert flags["can_approve_security"] is False
    assert flags["can_approve_privacy"] is False
    assert flags["can_submit"] is False
    assert flags["can_schedule"] is False


def test_campaign_flags_allow_one_independent_reviewer_to_complete_both_facets() -> None:
    creator_id = uuid4()
    reviewer_id = uuid4()
    campaign = _campaign(state=dm.CampaignState.PENDING_APPROVAL, creator_id=creator_id)
    principal = Principal(str(reviewer_id), {Role.ADMINISTRATOR})
    security = _approval(campaign, dm.ApprovalType.SECURITY, reviewer_id)

    one_lane = _campaign_action_flags(
        campaign,
        _audience(campaign),
        [security],
        principal,
        ApprovalPolicy.ENFORCE,
        launch_gate=_launch_gate(campaign),
    )
    assert one_lane["can_approve_security"] is False
    assert one_lane["can_approve_privacy"] is True

    privacy = _approval(campaign, dm.ApprovalType.PRIVACY, reviewer_id)
    campaign.state = dm.CampaignState.APPROVED
    complete = _campaign_action_flags(
        campaign,
        _audience(campaign),
        [security, privacy],
        principal,
        ApprovalPolicy.ENFORCE,
        launch_gate=_launch_gate(campaign),
    )
    assert complete["can_schedule"] is True
    assert complete["can_recall"] is True


def test_campaign_flags_allow_a_third_person_without_requiring_one() -> None:
    creator_id = uuid4()
    security_reviewer_id = uuid4()
    privacy_reviewer_id = uuid4()
    campaign = _campaign(state=dm.CampaignState.PENDING_APPROVAL, creator_id=creator_id)
    security = _approval(campaign, dm.ApprovalType.SECURITY, security_reviewer_id)
    privacy_reviewer = Principal(str(privacy_reviewer_id), {Role.ADMINISTRATOR})

    split_review = _campaign_action_flags(
        campaign,
        _audience(campaign),
        [security],
        privacy_reviewer,
        ApprovalPolicy.ENFORCE,
        launch_gate=_launch_gate(campaign),
    )
    assert split_review["can_approve_security"] is False
    assert split_review["can_approve_privacy"] is True

    privacy = _approval(campaign, dm.ApprovalType.PRIVACY, privacy_reviewer_id)
    campaign.state = dm.CampaignState.APPROVED
    complete = _campaign_action_flags(
        campaign,
        _audience(campaign),
        [security, privacy],
        privacy_reviewer,
        ApprovalPolicy.ENFORCE,
        launch_gate=_launch_gate(campaign),
    )
    assert complete["can_schedule"] is True

    campaign.state = dm.CampaignState.SCHEDULED
    publishable = _campaign_action_flags(
        campaign,
        _audience(campaign),
        [security, privacy],
        privacy_reviewer,
        ApprovalPolicy.ENFORCE,
        launch_gate=_launch_gate(campaign, state="canary_succeeded"),
    )
    assert publishable["can_schedule"] is False
    assert publishable["can_publish"] is True


def test_campaign_flags_fail_closed_on_authority_state_and_audience() -> None:
    campaign = _campaign(state=dm.CampaignState.DRAFT, creator_id=uuid4(), roe_bound=False)
    auditor = Principal(str(uuid4()), {Role.AUDITOR})
    flags = _campaign_action_flags(
        campaign,
        _audience(campaign, frozen=False),
        [],
        auditor,
        ApprovalPolicy.SINGLE_ADMIN,
    )
    assert not any(flags.values())

    author = Principal(str(uuid4()), {Role.CAMPAIGN_AUTHOR})
    frozen = _campaign_action_flags(
        campaign,
        _audience(campaign),
        [],
        author,
        ApprovalPolicy.SINGLE_ADMIN,
    )
    assert frozen["can_configure_audience"] is True
    assert frozen["can_submit"] is True
    assert frozen["can_schedule"] is False
    assert frozen["can_test_send"] is False


@pytest.mark.parametrize(
    ("state", "same_creator", "prohibited", "expected"),
    [
        (dm.PatternApprovalState.DRAFT, False, False, (True, True)),
        (dm.PatternApprovalState.DRAFT, True, False, (True, False)),
        (dm.PatternApprovalState.PENDING, False, False, (True, True)),
        (dm.PatternApprovalState.APPROVED, False, False, (True, False)),
        (dm.PatternApprovalState.REJECTED, False, False, (True, False)),
        (dm.PatternApprovalState.DRAFT, False, True, (False, False)),
    ],
)
def test_pattern_flags_cover_identity_state_and_safety_boundary(
    state: dm.PatternApprovalState,
    same_creator: bool,
    prohibited: bool,
    expected: tuple[bool, bool],
) -> None:
    creator_id = UUID("abcdefab-cdef-abcd-efab-cdefabcdefab")
    principal_id = str(creator_id).upper() if same_creator else str(uuid4())
    pattern = CampaignPattern(
        campaign_pattern_id=uuid4(),
        pattern_version=1,
        lure_category=dm.LureCategory.CONFERENCE,
        confidence=dm.Confidence.HIGH,
        supporting_evidence=[],
        prohibited_content_indicators=["blocked"] if prohibited else [],
        approval_state=state,
        created_by=creator_id,
    )
    flags = _pattern_action_flags(pattern, Principal(principal_id, {Role.ADMINISTRATOR}))
    assert (flags["can_clone"], flags["can_approve"]) == expected


class _ScalarRows:
    def __init__(self, rows: list[object]) -> None:
        self._rows = rows

    def __iter__(self):
        return iter(self._rows)


class _ExportSession:
    def __init__(self, rows: list[object]) -> None:
        self.rows = rows

    def scalars(self, statement):
        assert statement._limit_clause.value == _PRIVACY_EXPORT_RECORD_LIMIT + 1
        return _ScalarRows(self.rows)


def test_privacy_export_collection_refuses_oversized_single_response() -> None:
    session = _ExportSession([object()] * (_PRIVACY_EXPORT_RECORD_LIMIT + 1))
    with pytest.raises(HTTPException) as excinfo:
        _bounded_privacy_export_rows(session, select(Campaign), label="assignments")  # type: ignore[arg-type]
    assert excinfo.value.status_code == 413
    assert excinfo.value.detail == "privacy export assignments exceed the supported single-response boundary"
