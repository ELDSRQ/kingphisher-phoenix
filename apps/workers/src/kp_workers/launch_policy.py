"""Launch policy for worker delivery (W5-03 / KP-AUD-023).

Behavior-preserving extraction of the two small, pure launch-gate predicates:
the campaign-state delivery gate and the two-person approval rule, together with
the delivery-eligibility state sets the former reads. The logic is identical to
its former home in :mod:`kp_workers.jobs`; that module re-exports these under
their original private names so existing callers and tests are unaffected.
"""

from __future__ import annotations

from collections.abc import Sequence

from kp_database.models import CampaignApproval
from kp_domain_models import models as dm

DELIVERABLE_CAMPAIGN_STATES = frozenset(
    {
        dm.CampaignState.SCHEDULED,
        dm.CampaignState.SENDING,
        dm.CampaignState.ACTIVE,
    }
)
TEST_SEND_CAMPAIGN_STATES = (
    frozenset(
        {
            dm.CampaignState.DRAFT,
            dm.CampaignState.PATTERN_REVIEW,
            dm.CampaignState.CONTENT_REVIEW,
            dm.CampaignState.SECURITY_REVIEW,
            dm.CampaignState.PRIVACY_REVIEW,
            dm.CampaignState.PENDING_APPROVAL,
            dm.CampaignState.APPROVED,
        }
    )
    | DELIVERABLE_CAMPAIGN_STATES
)


def campaign_state_allows_delivery(state: dm.CampaignState, *, test_send: bool) -> bool:
    """Permit test sends during review, but never after a campaign has ended."""

    allowed_states = TEST_SEND_CAMPAIGN_STATES if test_send else DELIVERABLE_CAMPAIGN_STATES
    return state in allowed_states


def two_person_approval_reason(approvals: Sequence[CampaignApproval]) -> str | None:
    """Why the covering approvals fail the two-person rule, or ``None`` if valid.

    Two-person, not two-lane: the APPROVED approvals covering this review must
    span both the SECURITY and PRIVACY facets AND carry at least two DISTINCT
    approver identities. A single ADMINISTRATOR holding both APPROVE_SECURITY
    and APPROVE_PRIVACY therefore cannot satisfy the rule on their own. The
    caller fails closed (refuses launch) on any returned reason.
    """

    granted = {row.approval_type for row in approvals}
    if not {dm.ApprovalType.SECURITY, dm.ApprovalType.PRIVACY} <= granted:
        return "missing_approvals"
    if len({row.approver_id for row in approvals}) < 2:
        return "insufficient_distinct_approvers"
    return None
