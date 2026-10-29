"""W4-01 (KP-AUD-015): route-level wiring tests for the cue-coverage gate.

These call the real route functions (not just the pure validator), so deleting
the gate call in ``_record_campaign_review``/``approve_campaign``, the drift
check at approval/send, the author!=reviewer check, or the exception
invalidation would turn one of these red. They use a small fake session like the
other hermetic campaign-route tests.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

import pytest
from kp_authorization.rbac import Principal, Role
from kp_domain_models import models as dm
from kp_domain_models.policy import ApprovalPolicy
from kp_operator_api.routes import campaigns as campaign_routes
from kp_operator_api.training_library import assess_cue_coverage
from kp_telemetry.errors import ConflictError, PermissionDeniedError
from sqlalchemy import Select
from sqlalchemy.sql.dml import Delete

_URGENCY_MANIFEST = {"cues": [{"cue_type": "urgency"}]}


def _entity_name(stmt: Any) -> str:
    return stmt.column_descriptions[0]["entity"].__name__


class _Scalars:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = list(rows)

    def scalars(self) -> _Scalars:
        return self

    def all(self) -> list[Any]:
        return list(self._rows)

    def __iter__(self) -> Any:
        return iter(self._rows)


class _RouteSession:
    """Answers the exact get/scalar/execute calls the coverage routes make."""

    def __init__(
        self,
        *,
        campaign: Any = None,
        template: Any = None,
        resource: Any = None,
        gate: Any = None,
        coverage: list[Any] | None = None,
        exceptions: list[Any] | None = None,
        approvals: list[Any] | None = None,
        invalidate_campaigns: list[Any] | None = None,
        existing_exception: Any = None,
    ) -> None:
        self._campaign = campaign
        self._template = template
        self._resource = resource
        self._gate = gate
        self._coverage = list(coverage or [])
        self._exceptions = list(exceptions or [])
        self._approvals = list(approvals or [])
        self._invalidate = list(invalidate_campaigns if invalidate_campaigns is not None else [])
        self._existing_exception = existing_exception
        self.added: list[Any] = []
        self.deletes: list[Any] = []
        self.commits = 0

    def get(self, model: Any, ident: Any = None, **_kw: Any) -> Any:
        name = model.__name__
        if name == "TemplateVersion":
            return self._template
        if name == "TrainingResource":
            return self._resource
        if name == "CampaignLaunchGate":
            return self._gate
        if name == "Campaign":
            return self._campaign
        if name == "TrainingCueCoverage":
            return next((c for c in self._coverage if getattr(c, "coverage_id", None) == ident), None)
        return SimpleNamespace()

    def scalar(self, stmt: Any) -> Any:
        name = _entity_name(stmt)
        if name == "Campaign":
            return self._campaign
        if name == "CampaignCueCoverageException":
            return self._existing_exception
        return None

    def execute(self, stmt: Any) -> _Scalars:
        if isinstance(stmt, Delete):
            self.deletes.append(stmt)
            return _Scalars([])
        assert isinstance(stmt, Select)
        name = _entity_name(stmt)
        if name == "TrainingCueCoverage":
            return _Scalars([c for c in self._coverage if getattr(c, "reviewed", False)])
        if name == "CampaignCueCoverageException":
            return _Scalars(self._exceptions)
        if name == "Campaign":
            return _Scalars(self._invalidate)
        if name == "CampaignApproval":
            return _Scalars(self._approvals)
        return _Scalars([])

    def scalars(self, stmt: Any) -> _Scalars:
        return _Scalars(self.execute(stmt).all())

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    def delete(self, obj: Any) -> None:
        self.deletes.append(obj)

    def flush(self) -> None:
        pass

    def commit(self) -> None:
        self.commits += 1


class _Audit:
    def __init__(self) -> None:
        self.actions: list[str] = []

    def record(self, **kwargs: Any) -> None:
        self.actions.append(str(kwargs.get("action")))


def _principal(principal_id: str | None = None, roles: set[Role] | None = None) -> Principal:
    return Principal(principal_id or str(uuid4()), roles or {Role.ADMINISTRATOR})


def _request(policy: ApprovalPolicy = ApprovalPolicy.ENFORCE) -> SimpleNamespace:
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(settings=SimpleNamespace(approval_policy=policy))))


def _resource() -> SimpleNamespace:
    return SimpleNamespace(training_resource_id=uuid4(), version=1, training_resource_digest="b" * 64)


def _coverage_row(resource: SimpleNamespace, cue_id: str, *, created_by: Any, reviewed: bool = True) -> SimpleNamespace:
    return SimpleNamespace(
        coverage_id=uuid4(),
        training_resource_id=resource.training_resource_id,
        resource_version=resource.version,
        cue_id=cue_id,
        lesson_section=f"section:{cue_id}",
        quiz_item=f"quiz:{cue_id}",
        reviewed=reviewed,
        created_by=created_by,
        created_at=None,
        reviewed_by=None,
        reviewed_at=None,
    )


def _hash_for(
    resource: SimpleNamespace, reviewed: list[tuple[str, str, str]], exceptions: list[tuple[str, str]]
) -> str:
    return assess_cue_coverage(
        training_resource_id=resource.training_resource_id,
        resource_version=resource.version,
        required_cues=("urgency",),
        reviewed_coverage=reviewed,
        exceptions=exceptions,
    ).coverage_hash


# --- (a) review blocks on an uncovered required cue ---------------------------


def test_record_review_blocks_when_required_cue_lacks_coverage(monkeypatch: pytest.MonkeyPatch) -> None:
    resource = _resource()
    template = SimpleNamespace(cue_manifest=_URGENCY_MANIFEST, warning_cues=[])
    campaign = SimpleNamespace(
        campaign_id=uuid4(),
        current_template_id=uuid4(),
        manifest_hash="a" * 64,
        training_resource_version=1,
        training_resource_digest="b" * 64,
        state=dm.CampaignState.DRAFT,
    )
    monkeypatch.setattr(campaign_routes, "require_bound_training_resource", lambda *a, **k: resource)
    # If the gate call were removed, bind would run and this would return a gate
    # instead of raising, so pytest.raises below would fail — catching the drop.
    monkeypatch.setattr(
        campaign_routes,
        "bind_campaign_launch_review",
        lambda *a, **k: SimpleNamespace(
            review_manifest_hash="c" * 64, canary_manifest_hash="1" * 64, cue_coverage_hash=None
        ),
    )
    session = _RouteSession(campaign=campaign, template=template, coverage=[], exceptions=[])
    with pytest.raises(ConflictError, match="reviewed training coverage"):
        campaign_routes._record_campaign_review(campaign, _request(), session, _Audit(), _principal())


# --- #2 non-empty warning_cues but no manifest labels must fail closed --------


def test_record_review_blocks_degraded_manifest_with_declared_cues(monkeypatch: pytest.MonkeyPatch) -> None:
    resource = _resource()
    template = SimpleNamespace(cue_manifest={}, warning_cues=["suspicious urgency"])
    campaign = SimpleNamespace(
        campaign_id=uuid4(),
        current_template_id=uuid4(),
        manifest_hash="a" * 64,
        training_resource_version=1,
        training_resource_digest="b" * 64,
        state=dm.CampaignState.DRAFT,
    )
    monkeypatch.setattr(campaign_routes, "require_bound_training_resource", lambda *a, **k: resource)
    monkeypatch.setattr(
        campaign_routes,
        "bind_campaign_launch_review",
        lambda *a, **k: pytest.fail("review must not bind when the manifest is degraded"),
    )
    session = _RouteSession(campaign=campaign, template=template)
    with pytest.raises(ConflictError, match="resolved none"):
        campaign_routes._record_campaign_review(campaign, _request(), session, _Audit(), _principal())


def test_cue_less_simulation_binds_with_no_coverage_hash(monkeypatch: pytest.MonkeyPatch) -> None:
    resource = _resource()
    template = SimpleNamespace(cue_manifest={}, warning_cues=[])
    campaign = SimpleNamespace(
        campaign_id=uuid4(),
        current_template_id=uuid4(),
        manifest_hash="a" * 64,
        training_resource_version=1,
        training_resource_digest="b" * 64,
        state=dm.CampaignState.DRAFT,
    )
    gate = SimpleNamespace(review_manifest_hash="c" * 64, canary_manifest_hash="1" * 64, cue_coverage_hash=None)
    monkeypatch.setattr(campaign_routes, "require_bound_training_resource", lambda *a, **k: resource)
    monkeypatch.setattr(campaign_routes, "bind_campaign_launch_review", lambda *a, **k: gate)
    session = _RouteSession(campaign=campaign, template=template)
    result = campaign_routes._record_campaign_review(campaign, _request(), session, _Audit(), _principal())
    # A genuinely cue-less simulation is allowed through and binds no fingerprint.
    assert result["cue_coverage_hash"] is None
    assert gate.cue_coverage_hash is None


# --- approve_campaign gate wiring --------------------------------------------


def _approve_setup(monkeypatch: pytest.MonkeyPatch, *, gate: SimpleNamespace, coverage: list[Any]) -> _RouteSession:
    resource = _approve_setup.resource = _resource()  # type: ignore[attr-defined]
    template = SimpleNamespace(cue_manifest=_URGENCY_MANIFEST, warning_cues=[])
    monkeypatch.setattr(campaign_routes, "require_bound_training_resource", lambda *a, **k: resource)
    monkeypatch.setattr(campaign_routes, "_require_current_frozen_audience", lambda *a, **k: None)
    monkeypatch.setattr(campaign_routes, "campaign_launch_gate_error", lambda *a, **k: None)
    return _RouteSession(template=template, resource=resource, gate=gate, coverage=coverage)


def _approve(session: _RouteSession, campaign: Any, principal: Principal, audit: _Audit) -> dict[str, str]:
    return campaign_routes.approve_campaign(
        campaign_id=campaign.campaign_id,
        approval_type=dm.ApprovalType.SECURITY,
        body=campaign_routes.ApprovalSubmit(decision=dm.ApprovalDecision.APPROVED, rationale="done"),
        request=_request(),
        session=session,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        principal=principal,
    )


def _pending_campaign(template_id: Any) -> SimpleNamespace:
    return SimpleNamespace(
        campaign_id=uuid4(),
        current_template_id=template_id,
        state=dm.CampaignState.PENDING_APPROVAL,
        created_by=uuid4(),
        manifest_hash="a" * 64,
        training_resource_version=1,
        training_resource_digest="b" * 64,
    )


def test_approve_blocked_when_coverage_withdrawn(monkeypatch: pytest.MonkeyPatch) -> None:
    gate = SimpleNamespace(
        review_manifest_hash="c" * 64, cue_coverage_hash="d" * 64, submitted_by=None, state="reviewed"
    )
    session = _approve_setup(monkeypatch, gate=gate, coverage=[])  # no reviewed coverage left
    campaign = _pending_campaign(uuid4())
    session._campaign = campaign
    with pytest.raises(ConflictError, match="reviewed training coverage"):
        _approve(session, campaign, _principal(), _Audit())
    assert session.commits == 0


def test_approve_blocked_on_null_hash_with_required_cues(monkeypatch: pytest.MonkeyPatch) -> None:
    gate = SimpleNamespace(review_manifest_hash="c" * 64, cue_coverage_hash=None, submitted_by=None, state="reviewed")
    session = _approve_setup(monkeypatch, gate=gate, coverage=None)
    resource = _approve_setup.resource  # type: ignore[attr-defined]
    session._coverage = [_coverage_row(resource, "urgency", created_by=uuid4())]  # full coverage...
    campaign = _pending_campaign(uuid4())
    session._campaign = campaign
    # ...but the legacy gate has NULL cue_coverage_hash -> treated as drift.
    with pytest.raises(ConflictError, match="coverage changed after review"):
        _approve(session, campaign, _principal(), _Audit())
    assert session.commits == 0


def test_approve_allowed_with_full_reviewed_coverage(monkeypatch: pytest.MonkeyPatch) -> None:
    resource = _resource()
    template = SimpleNamespace(cue_manifest=_URGENCY_MANIFEST, warning_cues=[])
    monkeypatch.setattr(campaign_routes, "require_bound_training_resource", lambda *a, **k: resource)
    monkeypatch.setattr(campaign_routes, "_require_current_frozen_audience", lambda *a, **k: None)
    monkeypatch.setattr(campaign_routes, "campaign_launch_gate_error", lambda *a, **k: None)
    coverage = [_coverage_row(resource, "urgency", created_by=uuid4())]
    bound_hash = _hash_for(resource, [("urgency", "section:urgency", "quiz:urgency")], [])
    gate = SimpleNamespace(
        review_manifest_hash="c" * 64, cue_coverage_hash=bound_hash, submitted_by=None, state="reviewed"
    )
    campaign = _pending_campaign(uuid4())
    session = _RouteSession(campaign=campaign, template=template, resource=resource, gate=gate, coverage=coverage)
    audit = _Audit()
    result = _approve(session, campaign, _principal(), audit)
    # Gate passed: an approval was recorded and committed (single facet stays pending).
    assert result["state"] == dm.CampaignState.PENDING_APPROVAL.value
    assert any(type(obj).__name__ == "CampaignApproval" for obj in session.added)
    assert session.commits == 1


def test_approve_allowed_with_documented_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    resource = _resource()
    template = SimpleNamespace(cue_manifest=_URGENCY_MANIFEST, warning_cues=[])
    monkeypatch.setattr(campaign_routes, "require_bound_training_resource", lambda *a, **k: resource)
    monkeypatch.setattr(campaign_routes, "_require_current_frozen_audience", lambda *a, **k: None)
    monkeypatch.setattr(campaign_routes, "campaign_launch_gate_error", lambda *a, **k: None)
    exceptions = [SimpleNamespace(cue_id="urgency", rationale="covered by onboarding")]
    bound_hash = _hash_for(resource, [], [("urgency", "covered by onboarding")])
    gate = SimpleNamespace(
        review_manifest_hash="c" * 64, cue_coverage_hash=bound_hash, submitted_by=None, state="reviewed"
    )
    campaign = _pending_campaign(uuid4())
    session = _RouteSession(campaign=campaign, template=template, resource=resource, gate=gate, exceptions=exceptions)
    result = _approve(session, campaign, _principal(), _Audit())
    assert result["state"] == dm.CampaignState.PENDING_APPROVAL.value
    assert session.commits == 1


# --- #3 send re-checks coverage ----------------------------------------------


def test_send_blocked_when_coverage_withdrawn_after_approval(monkeypatch: pytest.MonkeyPatch) -> None:
    resource = _resource()
    template = SimpleNamespace(cue_manifest=_URGENCY_MANIFEST, warning_cues=[])
    gate = SimpleNamespace(review_manifest_hash="c" * 64, cue_coverage_hash="d" * 64, state="reviewed", roe_id=uuid4())
    campaign = SimpleNamespace(
        campaign_id=uuid4(),
        current_template_id=uuid4(),
        delivery_mode="reviewed_direct",
        state=dm.CampaignState.APPROVED,
        training_resource_id=resource.training_resource_id,
        training_resource_version=1,
    )
    monkeypatch.setattr(campaign_routes, "require_program_active_for_schedule", lambda *a, **k: None)
    monkeypatch.setattr(
        campaign_routes, "_system_safety_state", lambda *a, **k: SimpleNamespace(emergency_stop_engaged=False)
    )
    monkeypatch.setattr(campaign_routes, "require_bound_training_resource", lambda *a, **k: resource)
    monkeypatch.setattr(campaign_routes, "_require_current_frozen_audience", lambda *a, **k: None)
    monkeypatch.setattr(campaign_routes, "_missing_campaign_approvals", lambda *a, **k: set())
    monkeypatch.setattr(campaign_routes, "campaign_launch_gate_error", lambda *a, **k: None)
    monkeypatch.setattr(
        campaign_routes, "prepare_campaign", lambda *a, **k: pytest.fail("send must block before preparing")
    )
    session = _RouteSession(campaign=campaign, template=template, resource=resource, gate=gate, coverage=[])
    with pytest.raises(ConflictError, match="coverage changed after review|reviewed training coverage"):
        campaign_routes.send_reviewed_campaign(
            campaign_id=campaign.campaign_id,
            request=_request(),
            session=session,  # type: ignore[arg-type]
            audit=_Audit(),  # type: ignore[arg-type]
            principal=_principal(roles={Role.CAMPAIGN_OPERATOR}),
        )


# --- author != reviewer on coverage decision ----------------------------------


def test_coverage_author_cannot_review_own_mapping() -> None:
    resource = _resource()
    reviewer = _principal()
    reviewer_id = UUID(reviewer.principal_id)
    coverage = _coverage_row(resource, "urgency", created_by=reviewer_id)
    campaign = SimpleNamespace(
        campaign_id=uuid4(),
        current_template_id=uuid4(),
        training_resource_id=resource.training_resource_id,
        training_resource_version=resource.version,
    )
    session = _RouteSession(campaign=campaign, resource=resource, coverage=[coverage])
    with pytest.raises(PermissionDeniedError, match="cannot review their own"):
        campaign_routes.decide_campaign_cue_coverage(
            campaign_id=campaign.campaign_id,
            coverage_id=coverage.coverage_id,
            body=campaign_routes.CueCoverageDecision(decision="reviewed"),
            session=session,  # type: ignore[arg-type]
            audit=_Audit(),  # type: ignore[arg-type]
            principal=reviewer,
        )


def test_coverage_decision_reopens_bound_campaign_reviews() -> None:
    resource = _resource()
    author_id = uuid4()
    reviewer = _principal()
    coverage = _coverage_row(resource, "urgency", created_by=author_id, reviewed=False)
    campaign = SimpleNamespace(
        campaign_id=uuid4(),
        current_template_id=uuid4(),
        training_resource_id=resource.training_resource_id,
        training_resource_version=resource.version,
    )
    bound = SimpleNamespace(campaign_id=uuid4(), state=dm.CampaignState.APPROVED)
    session = _RouteSession(campaign=campaign, resource=resource, coverage=[coverage], invalidate_campaigns=[bound])
    campaign_routes.decide_campaign_cue_coverage(
        campaign_id=campaign.campaign_id,
        coverage_id=coverage.coverage_id,
        body=campaign_routes.CueCoverageDecision(decision="reviewed"),
        session=session,  # type: ignore[arg-type]
        audit=_Audit(),  # type: ignore[arg-type]
        principal=reviewer,
    )
    # Marking coverage reviewed re-opened the bound APPROVED campaign.
    assert coverage.reviewed is True
    assert bound.state is dm.CampaignState.DRAFT
    assert session.deletes  # launch gate + approvals cleared
    assert session.commits == 1


# --- exception route: state reset + non-required cue rejected -----------------


def _exception_campaign(template_id: Any) -> SimpleNamespace:
    return SimpleNamespace(
        campaign_id=uuid4(),
        current_template_id=template_id,
        state=dm.CampaignState.APPROVED,
    )


def test_recording_exception_resets_state_and_clears_gate_and_approvals() -> None:
    template_id = uuid4()
    template = SimpleNamespace(cue_manifest=_URGENCY_MANIFEST, warning_cues=[])
    campaign = _exception_campaign(template_id)
    session = _RouteSession(campaign=campaign, template=template, invalidate_campaigns=[campaign])
    result = campaign_routes.record_cue_coverage_exception(
        campaign_id=campaign.campaign_id,
        body=campaign_routes.CueCoverageExceptionRequest(cue_id="urgency", rationale="accepted gap"),
        session=session,  # type: ignore[arg-type]
        audit=_Audit(),  # type: ignore[arg-type]
        principal=_principal(),
    )
    assert result["review_reopened"] is True
    assert campaign.state is dm.CampaignState.DRAFT
    assert session.deletes  # invalidate_campaign_launch_review + delete approvals
    assert session.commits == 1


def test_exception_rejected_for_non_required_cue() -> None:
    template = SimpleNamespace(cue_manifest=_URGENCY_MANIFEST, warning_cues=[])
    campaign = _exception_campaign(uuid4())
    session = _RouteSession(campaign=campaign, template=template, invalidate_campaigns=[campaign])
    with pytest.raises(ConflictError, match="currently requires"):
        campaign_routes.record_cue_coverage_exception(
            campaign_id=campaign.campaign_id,
            body=campaign_routes.CueCoverageExceptionRequest(cue_id="brand_impersonation", rationale="n/a"),
            session=session,  # type: ignore[arg-type]
            audit=_Audit(),  # type: ignore[arg-type]
            principal=_principal(),
        )
    assert campaign.state is dm.CampaignState.APPROVED  # untouched
    assert session.commits == 0
