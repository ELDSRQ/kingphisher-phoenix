"""Characterization tests for the operator-API audience policy (W5-03).

Pins the CURRENT observable behavior of the audience-definition mapping and the
audience-preview serialization so the policy extraction in KP-AUD-023 is
provably behavior-preserving. Imports from the stable public location
(``kp_operator_api.routes.campaigns``) so the SAME tests pass before and after
the extraction.

Pure, in-memory, no PostgreSQL dependency.
"""

from __future__ import annotations

from uuid import uuid4

from kp_database.campaign_service import AudiencePreview, AudiencePreviewRecipient
from kp_domain_models import models as dm
from kp_operator_api.routes.campaigns import (
    CampaignAudienceUpdate,
    _audience_definition_body,
    _audience_preview_payload,
)


def test_audience_definition_body_maps_all_fields() -> None:
    gid = uuid4()
    inc = uuid4()
    exc = uuid4()
    body = CampaignAudienceUpdate(
        roe_id=uuid4(),
        group_ids=[gid],
        departments=["eng"],
        statuses=[dm.RecipientStatus.ACTIVE],
        include_recipient_ids=[inc],
        exclude_recipient_ids=[exc],
        sample_size=5,
        sample_seed="seed",
    )
    definition = _audience_definition_body(body)
    assert definition.group_ids == (gid,)
    assert definition.departments == ("eng",)
    assert definition.statuses == (dm.RecipientStatus.ACTIVE,)
    assert definition.include_recipient_ids == (inc,)
    assert definition.exclude_recipient_ids == (exc,)
    assert definition.sample_size == 5
    assert definition.sample_seed == "seed"


def test_audience_definition_body_defaults() -> None:
    body = CampaignAudienceUpdate()
    definition = _audience_definition_body(body)
    assert definition.group_ids == ()
    assert definition.departments == ()
    # CampaignAudienceUpdate defaults statuses to [ACTIVE]
    assert definition.statuses == (dm.RecipientStatus.ACTIVE,)
    assert definition.include_recipient_ids == ()
    assert definition.exclude_recipient_ids == ()
    assert definition.sample_size is None
    assert definition.sample_seed is None


def _preview(*, roe_id=None, included=()) -> AudiencePreview:
    return AudiencePreview(
        campaign_id=uuid4(),
        audience_version=3,
        configuration_hash="cfg",
        preview_hash="prev",
        selected_count=2,
        included=tuple(included),
        excluded_counts={"suppressed": 1, "opt_out": 2},
        sample_size=10,
        sample_seed="s",
        roe_id=roe_id,
        added_count=4,
        removed_count=1,
        unchanged_count=2,
        over_limit=False,
    )


def _recipient() -> AudiencePreviewRecipient:
    return AudiencePreviewRecipient(
        recipient_id=uuid4(),
        recipient_hash="hash",
        masked_mailbox="a***@example.com",
        department="eng",
        status=dm.RecipientStatus.ACTIVE,
    )


def test_audience_preview_payload_without_test_accounts() -> None:
    rec = _recipient()
    roe = uuid4()
    preview = _preview(roe_id=roe, included=[rec])
    payload = _audience_preview_payload(preview)

    assert payload["campaign_id"] == str(preview.campaign_id)
    assert payload["audience_version"] == 3
    assert payload["configuration_hash"] == "cfg"
    assert payload["preview_hash"] == "prev"
    assert payload["selected_count"] == 2
    assert payload["included_count"] == 1
    assert payload["excluded_count"] == 3
    assert payload["excluded_counts"] == {"suppressed": 1, "opt_out": 2}
    assert payload["sample_size"] == 10
    assert payload["sample_seed"] == "s"
    assert payload["roe_id"] == str(roe)
    assert payload["over_limit"] is False
    assert payload["test_account_count"] is None
    assert payload["diff"] == {"added": 4, "removed": 1, "unchanged": 2}
    assert payload["recipients"] == [
        {
            "recipient_id": str(rec.recipient_id),
            "recipient_hash": "hash",
            "mailbox": "a***@example.com",
            "department": "eng",
            "status": dm.RecipientStatus.ACTIVE.value,
        }
    ]


def test_audience_preview_payload_null_roe() -> None:
    payload = _audience_preview_payload(_preview(roe_id=None))
    assert payload["roe_id"] is None


def test_audience_preview_payload_with_test_accounts() -> None:
    rec = _recipient()
    preview = _preview(included=[rec])
    payload = _audience_preview_payload(preview, test_account_ids={rec.recipient_id})
    assert payload["test_account_count"] == 1
    assert payload["recipients"][0]["is_test_account"] is True

    other = _recipient()
    preview2 = _preview(included=[rec])
    payload2 = _audience_preview_payload(preview2, test_account_ids={other.recipient_id})
    assert payload2["recipients"][0]["is_test_account"] is False
