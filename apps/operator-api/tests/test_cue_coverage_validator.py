"""W4-01 (KP-AUD-015): after-click training cue-coverage validator + gate.

Proves the acceptance points deterministically:

* (a) approval is BLOCKED when a required simulation cue lacks reviewed coverage;
* (b) approval is ALLOWED when every required cue has reviewed coverage;
* (c) a documented exception permits approval despite a coverage gap;
* (d) a change to the cues or their coverage yields a different coverage
  fingerprint (the value the approval gate compares) and re-opens the review of
  every bound campaign, so a prior approval cannot survive the change.

The validator core is a pure function; the route-glue helpers are exercised with
a small fake session that returns the reviewed coverage and exception rows the
real queries would.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any

from kp_contracts.cue_ontology import build_cue_manifest
from kp_domain_models import models as dm
from kp_operator_api.training_library import (
    assess_cue_coverage,
    cue_coverage_for_campaign,
    invalidate_campaigns_for_coverage_change,
    require_cue_coverage,
    required_simulation_cues,
)
from kp_telemetry.errors import ConflictError
from sqlalchemy import Select
from sqlalchemy.sql.dml import Delete

_RESOURCE_ID = uuid.uuid4()


def _assess(
    *,
    required: tuple[str, ...],
    coverage: tuple[tuple[str, str, str], ...] = (),
    exceptions: tuple[tuple[str, str], ...] = (),
    version: int = 1,
) -> Any:
    return assess_cue_coverage(
        training_resource_id=_RESOURCE_ID,
        resource_version=version,
        required_cues=required,
        reviewed_coverage=coverage,
        exceptions=exceptions,
    )


def test_a_missing_reviewed_coverage_blocks() -> None:
    assessment = _assess(required=("urgency", "credential_request"))
    assert not assessment.satisfied
    assert assessment.missing == ("credential_request", "urgency")


def test_b_full_reviewed_coverage_is_satisfied() -> None:
    assessment = _assess(
        required=("urgency", "credential_request"),
        coverage=(
            ("urgency", "Spotting urgency", "Q1"),
            ("credential_request", "Never share credentials", "Q2"),
        ),
    )
    assert assessment.satisfied
    assert assessment.missing == ()
    assert set(assessment.covered) == {"urgency", "credential_request"}


def test_c_documented_exception_permits_despite_gap() -> None:
    assessment = _assess(
        required=("urgency", "credential_request"),
        coverage=(("urgency", "Spotting urgency", "Q1"),),
        exceptions=(("credential_request", "covered by the mandatory onboarding module"),),
    )
    assert assessment.satisfied
    assert assessment.excepted == ("credential_request",)


def test_c_exception_for_unrequired_cue_does_not_help() -> None:
    assessment = _assess(
        required=("urgency",),
        exceptions=(("brand_impersonation", "unrelated"),),
    )
    assert not assessment.satisfied
    assert assessment.missing == ("urgency",)


def test_d_hash_is_deterministic_and_order_independent() -> None:
    first = _assess(
        required=("urgency", "credential_request"),
        coverage=(
            ("urgency", "A", "Q1"),
            ("credential_request", "B", "Q2"),
        ),
    )
    second = _assess(
        required=("credential_request", "urgency"),
        coverage=(
            ("credential_request", "B", "Q2"),
            ("urgency", "A", "Q1"),
        ),
    )
    assert first.coverage_hash == second.coverage_hash


def test_d_changing_coverage_or_cues_changes_the_hash() -> None:
    base = _assess(required=("urgency",), coverage=(("urgency", "A", "Q1"),))
    changed_section = _assess(required=("urgency",), coverage=(("urgency", "A2", "Q1"),))
    changed_cues = _assess(required=("urgency", "link_lure"), coverage=(("urgency", "A", "Q1"),))
    changed_version = _assess(required=("urgency",), coverage=(("urgency", "A", "Q1"),), version=2)
    added_exception = _assess(
        required=("urgency",),
        coverage=(("urgency", "A", "Q1"),),
        exceptions=(("urgency", "waived"),),
    )
    distinct = {
        base.coverage_hash,
        changed_section.coverage_hash,
        changed_cues.coverage_hash,
        changed_version.coverage_hash,
        added_exception.coverage_hash,
    }
    assert len(distinct) == 5


def test_required_simulation_cues_from_a_real_manifest() -> None:
    manifest = build_cue_manifest(
        subject="URGENT: verify your account password now",
        body="Your Microsoft account was suspended. Click here to sign in and confirm your identity.",
        source="unit-test",
    )
    template = SimpleNamespace(cue_manifest=manifest)
    required = required_simulation_cues(template)
    # Deterministic extraction found these cue types in the lure above.
    assert "urgency" in required
    assert "credential_request" in required
    assert "brand_impersonation" in required
    # An empty / absent manifest declares no required cues (vacuously covered).
    assert required_simulation_cues(SimpleNamespace(cue_manifest={})) == ()
    assert required_simulation_cues(SimpleNamespace()) == ()


class _Result:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def scalars(self) -> _Result:
        return self

    def all(self) -> list[Any]:
        return list(self._rows)


class _CoverageSession:
    """Minimal fake: answers the validator's and invalidator's SELECTs by entity."""

    def __init__(
        self,
        *,
        coverage: list[Any] | None = None,
        exceptions: list[Any] | None = None,
        campaigns: list[Any] | None = None,
    ) -> None:
        self.coverage = coverage or []
        self.exceptions = exceptions or []
        self.campaigns = campaigns or []
        self.deletes: list[Any] = []

    def execute(self, statement: Any) -> _Result:
        if isinstance(statement, Delete):
            self.deletes.append(statement)
            return _Result([])
        assert isinstance(statement, Select)
        entity = statement.column_descriptions[0]["entity"]
        name = entity.__name__
        if name == "TrainingCueCoverage":
            # The real query filters reviewed=True; mirror that here.
            return _Result([row for row in self.coverage if getattr(row, "reviewed", False)])
        if name == "CampaignCueCoverageException":
            return _Result(self.exceptions)
        if name == "Campaign":
            return _Result(self.campaigns)
        raise AssertionError(f"unexpected select entity: {name}")


def _coverage_row(cue_id: str, *, reviewed: bool = True) -> SimpleNamespace:
    return SimpleNamespace(
        training_resource_id=_RESOURCE_ID,
        resource_version=1,
        cue_id=cue_id,
        lesson_section=f"section:{cue_id}",
        quiz_item=f"quiz:{cue_id}",
        reviewed=reviewed,
    )


def _exception_row(cue_id: str) -> SimpleNamespace:
    return SimpleNamespace(cue_id=cue_id, rationale="documented risk acceptance")


_CAMPAIGN = SimpleNamespace(campaign_id=uuid.uuid4())
_TEMPLATE = SimpleNamespace(cue_manifest={"cues": [{"cue_type": "urgency"}, {"cue_type": "credential_request"}]})
_RESOURCE = SimpleNamespace(training_resource_id=_RESOURCE_ID, version=1)


def test_require_cue_coverage_blocks_when_a_required_cue_is_uncovered() -> None:
    session = _CoverageSession(coverage=[_coverage_row("urgency")])
    try:
        require_cue_coverage(session, _CAMPAIGN, _TEMPLATE, _RESOURCE)
    except ConflictError as exc:
        assert "credential_request" in str(exc)
    else:
        raise AssertionError("expected ConflictError for the uncovered cue")


def test_require_cue_coverage_ignores_unreviewed_coverage() -> None:
    session = _CoverageSession(
        coverage=[_coverage_row("urgency"), _coverage_row("credential_request", reviewed=False)],
    )
    try:
        require_cue_coverage(session, _CAMPAIGN, _TEMPLATE, _RESOURCE)
    except ConflictError as exc:
        assert "credential_request" in str(exc)
    else:
        raise AssertionError("an unreviewed mapping must not count as coverage")


def test_require_cue_coverage_passes_with_full_reviewed_coverage() -> None:
    session = _CoverageSession(
        coverage=[_coverage_row("urgency"), _coverage_row("credential_request")],
    )
    assessment = require_cue_coverage(session, _CAMPAIGN, _TEMPLATE, _RESOURCE)
    assert assessment.satisfied


def test_require_cue_coverage_passes_with_documented_exception() -> None:
    session = _CoverageSession(
        coverage=[_coverage_row("urgency")],
        exceptions=[_exception_row("credential_request")],
    )
    assessment = require_cue_coverage(session, _CAMPAIGN, _TEMPLATE, _RESOURCE)
    assert assessment.satisfied
    assert assessment.excepted == ("credential_request",)


def test_coverage_hash_differs_after_coverage_is_withdrawn() -> None:
    full = _CoverageSession(coverage=[_coverage_row("urgency"), _coverage_row("credential_request")])
    before = cue_coverage_for_campaign(full, _CAMPAIGN, _TEMPLATE, _RESOURCE)
    withdrawn = _CoverageSession(coverage=[_coverage_row("urgency")])
    after = cue_coverage_for_campaign(withdrawn, _CAMPAIGN, _TEMPLATE, _RESOURCE)
    # The gate stores `before.coverage_hash`; a later recompute yields `after`,
    # so the hmac comparison in approve_campaign fails -> approval invalidated.
    assert before.coverage_hash != after.coverage_hash


def test_invalidate_resets_reviewed_bound_campaigns_only() -> None:
    approved = SimpleNamespace(campaign_id=uuid.uuid4(), state=dm.CampaignState.APPROVED)
    pending = SimpleNamespace(campaign_id=uuid.uuid4(), state=dm.CampaignState.PENDING_APPROVAL)
    draft = SimpleNamespace(campaign_id=uuid.uuid4(), state=dm.CampaignState.DRAFT)
    session = _CoverageSession(campaigns=[approved, pending, draft])

    reopened = invalidate_campaigns_for_coverage_change(session, _RESOURCE_ID, 1)

    assert approved.state is dm.CampaignState.DRAFT
    assert pending.state is dm.CampaignState.DRAFT
    assert draft.state is dm.CampaignState.DRAFT
    # Only the two campaigns that had advanced past DRAFT are reported reopened.
    assert set(reopened) == {approved.campaign_id, pending.campaign_id}
    # Each affected campaign discards its launch gate + approvals (two deletes).
    assert len(session.deletes) == 3 * 2
