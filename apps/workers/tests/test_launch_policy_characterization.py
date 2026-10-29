"""Characterization tests for the worker launch policy (W5-03 / KP-AUD-023).

Pins the CURRENT observable behavior of the campaign-state delivery gate and the
two-person approval rule so the policy extraction is provably
behavior-preserving. Imports from the stable public location
(``kp_workers.jobs``) so the SAME tests pass before and after extraction.

Pure, in-memory, no PostgreSQL dependency.
"""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

from kp_domain_models import models as dm
from kp_workers.jobs import (
    _DELIVERABLE_CAMPAIGN_STATES,
    _TERMINAL_CAMPAIGN_STATES,
    _TEST_SEND_CAMPAIGN_STATES,
    _campaign_state_allows_delivery,
    _two_person_approval_reason,
)


class TestCampaignStateAllowsDelivery:
    def test_deliverable_states_allowed_for_real_send(self) -> None:
        for state in _DELIVERABLE_CAMPAIGN_STATES:
            assert _campaign_state_allows_delivery(state, test_send=False) is True

    def test_review_states_blocked_for_real_send(self) -> None:
        review_states = _TEST_SEND_CAMPAIGN_STATES - _DELIVERABLE_CAMPAIGN_STATES
        assert review_states  # guard: there are review-only states
        for state in review_states:
            assert _campaign_state_allows_delivery(state, test_send=False) is False

    def test_test_send_allowed_across_review_and_launch(self) -> None:
        for state in _TEST_SEND_CAMPAIGN_STATES:
            assert _campaign_state_allows_delivery(state, test_send=True) is True

    def test_terminal_states_never_allowed(self) -> None:
        for state in _TERMINAL_CAMPAIGN_STATES:
            assert _campaign_state_allows_delivery(state, test_send=True) is False
            assert _campaign_state_allows_delivery(state, test_send=False) is False

    def test_state_partition_is_exhaustive(self) -> None:
        assert frozenset(dm.CampaignState) == _TEST_SEND_CAMPAIGN_STATES | _TERMINAL_CAMPAIGN_STATES


def _approval(approval_type: dm.ApprovalType, approver_id: object) -> SimpleNamespace:
    return SimpleNamespace(approval_type=approval_type, approver_id=approver_id)


class TestTwoPersonApprovalReason:
    def test_valid_two_distinct_approvers(self) -> None:
        a, b = uuid4(), uuid4()
        approvals = [
            _approval(dm.ApprovalType.SECURITY, a),
            _approval(dm.ApprovalType.PRIVACY, b),
        ]
        assert _two_person_approval_reason(approvals) is None

    def test_single_approver_both_facets_insufficient(self) -> None:
        a = uuid4()
        approvals = [
            _approval(dm.ApprovalType.SECURITY, a),
            _approval(dm.ApprovalType.PRIVACY, a),
        ]
        assert _two_person_approval_reason(approvals) == "insufficient_distinct_approvers"

    def test_missing_privacy_facet(self) -> None:
        approvals = [_approval(dm.ApprovalType.SECURITY, uuid4())]
        assert _two_person_approval_reason(approvals) == "missing_approvals"

    def test_empty_is_missing_approvals(self) -> None:
        assert _two_person_approval_reason([]) == "missing_approvals"
