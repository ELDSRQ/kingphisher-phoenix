"""Campaign approval requires a creator plus one independent operator."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from kp_authorization.rbac import Principal, Role
from kp_database.models import Campaign, CampaignApproval, CampaignLaunchGate
from kp_domain_models import models as dm
from kp_operator_api import routers
from kp_operator_api.routes import campaigns as campaign_routes
from kp_telemetry.errors import PermissionDeniedError


class _ApprovalRows:
    def __init__(self, approvals: list[CampaignApproval]) -> None:
        self._approvals = approvals

    def scalars(self) -> _ApprovalRows:
        return self

    def all(self) -> list[CampaignApproval]:
        return list(self._approvals)


class _ApprovalSession:
    def __init__(self, campaign: Campaign, launch_gate: CampaignLaunchGate) -> None:
        self.campaign = campaign
        self.launch_gate = launch_gate
        self.approvals: list[CampaignApproval] = []
        self.commits = 0

    def scalar(self, statement: object) -> Campaign | CampaignApproval | None:
        entity = statement.column_descriptions[0]["entity"]  # type: ignore[attr-defined]
        if entity is Campaign:
            return self.campaign
        if entity is not CampaignApproval:
            raise AssertionError(f"unexpected scalar entity: {entity}")

        compiled = statement.compile()  # type: ignore[attr-defined]
        params = compiled.params
        approval_type = next(value for key, value in params.items() if key.startswith("approval_type_"))
        other_facet = "approval_type !=" in str(statement)
        approver_id = next(
            (value for key, value in params.items() if key.startswith("approver_id_")),
            None,
        )
        for approval in self.approvals:
            if other_facet:
                type_matches = approval.approval_type != approval_type
            else:
                type_matches = approval.approval_type == approval_type
            if type_matches and (approver_id is None or approval.approver_id == approver_id):
                return approval
        return None

    def get(self, model: type[object], _key: object, **_kwargs: object) -> object:
        if model is CampaignLaunchGate:
            return self.launch_gate
        return SimpleNamespace()

    def add(self, value: object) -> None:
        if isinstance(value, CampaignApproval):
            self.approvals.append(value)

    def execute(self, _statement: object) -> _ApprovalRows:
        return _ApprovalRows(self.approvals)

    def commit(self) -> None:
        self.commits += 1


class _Audit:
    def __init__(self) -> None:
        self.actions: list[str] = []

    def record(self, **kwargs: object) -> None:
        self.actions.append(str(kwargs["action"]))


def _campaign(creator_id: UUID) -> Campaign:
    now = datetime.now(UTC)
    return Campaign(
        campaign_id=uuid4(),
        pattern_id=uuid4(),
        current_template_id=uuid4(),
        title="Two-person approval",
        state=dm.CampaignState.PENDING_APPROVAL,
        sender_mailbox="drills@example.com",
        training_domain="training.example.com",
        schedule_start=now + timedelta(days=1),
        schedule_end=now + timedelta(days=2),
        timezone="UTC",
        max_recipients=10,
        manifest_hash="a" * 64,
        created_by=creator_id,
        expires_at=now + timedelta(days=3),
        training_resource_version=1,
        training_resource_digest="b" * 64,
    )


def _launch_gate(campaign: Campaign, *, submitted_by: UUID | None = None) -> CampaignLaunchGate:
    return CampaignLaunchGate(
        campaign_id=campaign.campaign_id,
        review_manifest_hash="c" * 64,
        content_manifest_hash="d" * 64,
        template_approval_hash="e" * 64,
        audience_manifest_hash="f" * 64,
        canary_manifest_hash="1" * 64,
        submitted_by=submitted_by,
        state="reviewed",
    )


def _request() -> SimpleNamespace:
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace()))


@pytest.fixture
def approval_dependencies(monkeypatch: pytest.MonkeyPatch) -> None:
    lesson = SimpleNamespace(training_resource_id=uuid4())
    monkeypatch.setattr(campaign_routes, "require_bound_training_resource", lambda *_args: lesson)
    monkeypatch.setattr(campaign_routes, "_require_current_frozen_audience", lambda *_args: None)
    monkeypatch.setattr(campaign_routes, "campaign_launch_gate_error", lambda *_args: None)


def _approve(
    session: _ApprovalSession,
    audit: _Audit,
    campaign: Campaign,
    approval_type: dm.ApprovalType,
    principal: Principal,
) -> dict[str, str]:
    return routers.approve_campaign(
        campaign_id=campaign.campaign_id,
        approval_type=approval_type,
        body=routers.ApprovalSubmit(decision=dm.ApprovalDecision.APPROVED, rationale="Checklist complete"),
        request=_request(),
        session=session,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        principal=principal,
    )


@pytest.mark.parametrize("approval_type", [dm.ApprovalType.SECURITY, dm.ApprovalType.PRIVACY])
def test_creator_cannot_approve_either_facet(
    approval_dependencies: None,
    approval_type: dm.ApprovalType,
) -> None:
    creator_id = uuid4()
    campaign = _campaign(creator_id)
    session = _ApprovalSession(campaign, _launch_gate(campaign))

    with pytest.raises(PermissionDeniedError, match="self-approval"):
        _approve(session, _Audit(), campaign, approval_type, Principal(str(creator_id), {Role.ADMINISTRATOR}))

    assert session.approvals == []
    assert session.commits == 0


def test_one_operator_cannot_complete_both_facets(approval_dependencies: None) -> None:
    # S1: a single ADMINISTRATOR holds both APPROVE_SECURITY and APPROVE_PRIVACY.
    # Two-person review means two DISTINCT people, so the second facet must be
    # refused even though the operator carries both capabilities.
    campaign = _campaign(uuid4())
    session = _ApprovalSession(campaign, _launch_gate(campaign))
    audit = _Audit()
    reviewer_id = uuid4()
    reviewer = Principal(str(reviewer_id), {Role.SECURITY_APPROVER, Role.PRIVACY_APPROVER})

    assert routers._require_campaign_approval_capability(dm.ApprovalType.SECURITY, reviewer) is reviewer
    assert routers._require_campaign_approval_capability(dm.ApprovalType.PRIVACY, reviewer) is reviewer

    security = _approve(session, audit, campaign, dm.ApprovalType.SECURITY, reviewer)
    assert security["state"] == dm.CampaignState.PENDING_APPROVAL.value

    with pytest.raises(PermissionDeniedError, match="already approved a facet"):
        _approve(session, audit, campaign, dm.ApprovalType.PRIVACY, reviewer)

    # Only the first facet was ever recorded; the campaign never reaches APPROVED.
    assert [approval.approval_type for approval in session.approvals] == [dm.ApprovalType.SECURITY]
    assert campaign.state == dm.CampaignState.PENDING_APPROVAL
    assert audit.actions == ["campaign.approve.security"]


def test_submitter_cannot_approve_even_when_not_the_creator(approval_dependencies: None) -> None:
    # The last-mutator who submitted the review is recorded on the launch gate
    # and is barred from approving, independently of the campaign's created_by.
    submitter_id = uuid4()
    campaign = _campaign(uuid4())  # created_by is a different, unrelated operator
    session = _ApprovalSession(campaign, _launch_gate(campaign, submitted_by=submitter_id))
    submitter = Principal(str(submitter_id), {Role.SECURITY_APPROVER, Role.PRIVACY_APPROVER})

    with pytest.raises(PermissionDeniedError, match="submitted this campaign for review"):
        _approve(session, _Audit(), campaign, dm.ApprovalType.SECURITY, submitter)

    assert session.approvals == []
    assert session.commits == 0


def test_a_third_person_may_complete_the_other_facet(approval_dependencies: None) -> None:
    campaign = _campaign(uuid4())
    session = _ApprovalSession(campaign, _launch_gate(campaign))
    audit = _Audit()
    security_reviewer_id = uuid4()
    privacy_reviewer_id = uuid4()

    _approve(
        session,
        audit,
        campaign,
        dm.ApprovalType.SECURITY,
        Principal(str(security_reviewer_id), {Role.SECURITY_APPROVER}),
    )
    result = _approve(
        session,
        audit,
        campaign,
        dm.ApprovalType.PRIVACY,
        Principal(str(privacy_reviewer_id), {Role.PRIVACY_APPROVER}),
    )

    assert result["state"] == dm.CampaignState.APPROVED.value
    assert {approval.approver_id for approval in session.approvals} == {
        security_reviewer_id,
        privacy_reviewer_id,
    }
