"""UX-011 §5 — approver "needs my decision" flags and queue endpoint.

These lock the fail-closed narrowing that makes the queue match the AUT-002
two-distinct-approver rule already enforced in ``approve_campaign``: a principal
never sees a lane they already approved, submitted, or that is already decided.
No authorization is changed here — the flags only mirror the existing gate.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from kp_authorization.rbac import Principal, Role
from kp_domain_models import models as dm
from kp_domain_models.policy import ApprovalPolicy
from kp_operator_api import routers

_LAUNCH_HASH = "c" * 64


def _campaign(creator_id: UUID) -> SimpleNamespace:
    now = datetime.now(UTC)
    return SimpleNamespace(
        campaign_id=uuid4(),
        title="Quarterly awareness drill",
        state=dm.CampaignState.PENDING_APPROVAL,
        created_by=creator_id,
        schedule_start=now + timedelta(days=1),
        schedule_end=now + timedelta(days=2),
        training_resource_id=None,
        current_template_id=None,
    )


def _audience(campaign_id: UUID | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        campaign_id=campaign_id or uuid4(),
        frozen_at=datetime.now(UTC),
        legacy_requires_configuration=False,
        version=3,
    )


def _gate(*, campaign_id: UUID | None = None, submitted_by: UUID | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        campaign_id=campaign_id or uuid4(),
        review_manifest_hash=_LAUNCH_HASH,
        submitted_by=submitted_by,
        state="reviewed",
        canary_expires_at=None,
        provider=None,
        canary_evidence_hash=None,
        canary_succeeded_at=None,
        provider_config_hash=None,
    )


def _approval(approval_type: dm.ApprovalType, approver_id: UUID, campaign_id: UUID | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        campaign_id=campaign_id or uuid4(),
        approval_type=approval_type,
        decision=dm.ApprovalDecision.APPROVED,
        approver_id=approver_id,
        launch_manifest_hash=_LAUNCH_HASH,
    )


def _flags(campaign: SimpleNamespace, approvals: list[SimpleNamespace], principal: Principal) -> dict[str, bool]:
    return routers._campaign_action_flags(
        campaign,  # type: ignore[arg-type]
        _audience(),  # type: ignore[arg-type]
        approvals,  # type: ignore[arg-type]
        principal,
        ApprovalPolicy.ENFORCE,
        training_ready=True,
        launch_gate=_gate(submitted_by=getattr(campaign, "_submitted_by", None)),  # type: ignore[arg-type]
        launch_ready=True,
    )


def test_independent_approver_with_open_lanes_can_review_both() -> None:
    campaign = _campaign(uuid4())
    reviewer = Principal(str(uuid4()), {Role.SECURITY_APPROVER, Role.PRIVACY_APPROVER})
    flags = _flags(campaign, [], reviewer)
    assert flags["can_approve_security"] is True
    assert flags["can_approve_privacy"] is True


def test_principal_who_approved_one_facet_cannot_see_the_other() -> None:
    # AUT-002: one person must not complete both facets. The security lane is
    # decided (hidden for everyone) and the privacy lane must be hidden *for this
    # principal* because the server would reject their second approval.
    campaign = _campaign(uuid4())
    reviewer_id = uuid4()
    reviewer = Principal(str(reviewer_id), {Role.SECURITY_APPROVER, Role.PRIVACY_APPROVER})
    flags = _flags(campaign, [_approval(dm.ApprovalType.SECURITY, reviewer_id)], reviewer)
    assert flags["can_approve_security"] is False  # lane already decided
    assert flags["can_approve_privacy"] is False  # barred: already approved a facet


def test_a_different_approver_still_sees_the_remaining_lane() -> None:
    campaign = _campaign(uuid4())
    first_id = uuid4()
    other = Principal(str(uuid4()), {Role.PRIVACY_APPROVER})
    flags = _flags(campaign, [_approval(dm.ApprovalType.SECURITY, first_id)], other)
    assert flags["can_approve_security"] is False  # decided
    assert flags["can_approve_privacy"] is True  # open for a distinct approver


def test_submitter_for_review_never_sees_an_open_lane() -> None:
    campaign = _campaign(uuid4())
    submitter_id = uuid4()
    campaign._submitted_by = submitter_id
    submitter = Principal(str(submitter_id), {Role.SECURITY_APPROVER, Role.PRIVACY_APPROVER})
    flags = _flags(campaign, [], submitter)
    assert flags["can_approve_security"] is False
    assert flags["can_approve_privacy"] is False


def test_creator_never_sees_an_open_lane() -> None:
    creator_id = uuid4()
    campaign = _campaign(creator_id)
    creator = Principal(str(creator_id), {Role.SECURITY_APPROVER, Role.PRIVACY_APPROVER})
    flags = _flags(campaign, [], creator)
    assert flags["can_approve_security"] is False
    assert flags["can_approve_privacy"] is False


# --- endpoint projection -------------------------------------------------


class _Rows:
    def __init__(self, rows: list[object]) -> None:
        self._rows = rows

    def scalars(self) -> _Rows:
        return self

    def all(self) -> list[object]:
        return list(self._rows)

    def __iter__(self):  # noqa: ANN204 - test helper
        return iter(self._rows)


class _QueueSession:
    def __init__(self, campaigns, audiences, gates, approvals) -> None:  # noqa: ANN001
        self._by_entity = {
            "Campaign": campaigns,
            "CampaignAudience": audiences,
            "CampaignLaunchGate": gates,
            "CampaignApproval": approvals,
        }

    @staticmethod
    def _entity_name(statement: object) -> str:
        return statement.column_descriptions[0]["entity"].__name__  # type: ignore[attr-defined]

    def execute(self, statement: object) -> _Rows:
        return _Rows(self._by_entity.get(self._entity_name(statement), []))

    def scalars(self, statement: object) -> _Rows:
        return _Rows(self._by_entity.get(self._entity_name(statement), []))


def _run_queue(principal: Principal, campaigns, audiences, gates, approvals) -> list[dict]:  # noqa: ANN001
    session = _QueueSession(campaigns, audiences, gates, approvals)
    settings = SimpleNamespace(approval_policy=ApprovalPolicy.ENFORCE)
    return routers.campaigns_needing_my_decision(
        limit=100,
        offset=0,
        session=session,
        settings=settings,
        principal=principal,  # type: ignore[arg-type]
    )


def test_queue_returns_only_campaigns_with_a_lane_open_for_me(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(routers, "training_binding_error", lambda *_a: None)
    monkeypatch.setattr(routers, "campaign_launch_gate_error", lambda *_a: None)

    reviewer_id = uuid4()
    reviewer = Principal(str(reviewer_id), {Role.SECURITY_APPROVER, Role.PRIVACY_APPROVER})

    open_campaign = _campaign(uuid4())
    mine_already = _campaign(uuid4())
    submitted = _campaign(uuid4())

    audiences = [_audience(c.campaign_id) for c in (open_campaign, mine_already, submitted)]
    gates = [
        _gate(campaign_id=open_campaign.campaign_id),
        _gate(campaign_id=mine_already.campaign_id),
        _gate(campaign_id=submitted.campaign_id, submitted_by=reviewer_id),
    ]
    approvals = [_approval(dm.ApprovalType.SECURITY, reviewer_id, campaign_id=mine_already.campaign_id)]

    queue = _run_queue(reviewer, [open_campaign, mine_already, submitted], audiences, gates, approvals)

    returned = {row["campaign_id"] for row in queue}
    assert returned == {str(open_campaign.campaign_id)}
    (row,) = queue
    assert row["can_approve_security"] is True
    assert row["can_approve_privacy"] is True
    assert row["title"] == "Quarterly awareness drill"


def test_queue_is_empty_when_no_campaigns_are_pending(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(routers, "training_binding_error", lambda *_a: None)
    monkeypatch.setattr(routers, "campaign_launch_gate_error", lambda *_a: None)
    reviewer = Principal(str(uuid4()), {Role.SECURITY_APPROVER})
    assert _run_queue(reviewer, [], [], [], []) == []
