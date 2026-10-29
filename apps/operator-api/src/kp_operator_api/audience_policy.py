"""Audience policy for campaign routes (W5-03 / KP-AUD-023).

Behavior-preserving extraction of the two pure audience helpers used by the
campaign routes: mapping a request body to an :class:`AudienceDefinition`, and
serializing an :class:`AudiencePreview` into the route response payload. The
logic is identical to its former home in
:mod:`kp_operator_api.routes.campaigns`; that module re-exports these under
their original private names so existing callers and tests are unaffected.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from kp_database.campaign_service import AudienceDefinition, AudiencePreview

if TYPE_CHECKING:
    from kp_operator_api.routes.campaigns import CampaignAudienceUpdate


def audience_definition_body(body: CampaignAudienceUpdate) -> AudienceDefinition:
    return AudienceDefinition(
        group_ids=tuple(body.group_ids),
        departments=tuple(body.departments),
        statuses=tuple(body.statuses),
        include_recipient_ids=tuple(body.include_recipient_ids),
        exclude_recipient_ids=tuple(body.exclude_recipient_ids),
        sample_size=body.sample_size,
        sample_seed=body.sample_seed,
    )


def audience_preview_payload(
    preview: AudiencePreview, *, test_account_ids: set[uuid.UUID] | None = None
) -> dict[str, Any]:
    return {
        "campaign_id": str(preview.campaign_id),
        "audience_version": preview.audience_version,
        "configuration_hash": preview.configuration_hash,
        "preview_hash": preview.preview_hash,
        "selected_count": preview.selected_count,
        "included_count": len(preview.included),
        "excluded_count": sum(preview.excluded_counts.values()),
        "excluded_counts": preview.excluded_counts,
        "sample_size": preview.sample_size,
        "sample_seed": preview.sample_seed,
        "roe_id": str(preview.roe_id) if preview.roe_id else None,
        "over_limit": preview.over_limit,
        "test_account_count": len(test_account_ids) if test_account_ids is not None else None,
        "diff": {
            "added": preview.added_count,
            "removed": preview.removed_count,
            "unchanged": preview.unchanged_count,
        },
        "recipients": [
            {
                "recipient_id": str(item.recipient_id),
                "recipient_hash": item.recipient_hash,
                "mailbox": item.masked_mailbox,
                "department": item.department,
                "status": item.status.value,
                **({"is_test_account": item.recipient_id in test_account_ids} if test_account_ids is not None else {}),
            }
            for item in preview.included
        ],
    }
