"""Contract tests for the on-prem background aggregation stage (M3)."""

from __future__ import annotations

import pytest
from kp_contracts.aggregation import (
    MAX_AGG_EXCERPT_CHARS,
    MAX_AGG_SOURCE_IDS,
    MAX_AGGREGATION_CANDIDATES,
    MAX_AGGREGATION_ITEMS,
    AggregatedCampaign,
    AggregateRequest,
    AggregateResponse,
    AggregationSourceItem,
)
from pydantic import ValidationError


def _record(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "campaign_name": "Invoice lure wave",
        "claimed_brand": "Acme Payments",
        "target_sector": "Finance",
        "target_region": "North America",
        "lure_theme": "Overdue invoice",
        "reported_subjects": ["Action required: invoice #4471"],
        "sender_characteristics": "Spoofed billing display name",
        "body_characteristics": "Urgent payment demand with link",
        "call_to_action": "Open the portal and confirm payment",
        "delivery_method": "email",
        "evidence_excerpt": "Public threat report excerpt.",
        "confidence": 0.8,
        "model_id": "onprem/analyst-model",
    }
    base.update(overrides)
    return base


def _candidate(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "rank": 1,
        "score": 0.9,
        "title": "Invoice lure wave",
        "as_of": "2026-09-10",
        "source_item_ids": ["item-1", "item-2"],
        "rationale": "Multiple current feeds report the same active lure.",
        "record": _record(),
    }
    base.update(overrides)
    return base


def test_source_item_forbids_extra_fields() -> None:
    with pytest.raises(ValidationError):
        AggregationSourceItem(item_id="a", surprise="x")  # type: ignore[call-arg]


def test_source_item_requires_item_id() -> None:
    with pytest.raises(ValidationError):
        AggregationSourceItem(item_id="")


def test_source_item_excerpt_bounded() -> None:
    with pytest.raises(ValidationError):
        AggregationSourceItem(item_id="a", excerpt="x" * (MAX_AGG_EXCERPT_CHARS + 1))


def test_request_requires_at_least_one_item() -> None:
    with pytest.raises(ValidationError):
        AggregateRequest(items=[])


def test_request_caps_item_batch() -> None:
    items = [AggregationSourceItem(item_id=f"i{n}") for n in range(MAX_AGGREGATION_ITEMS + 1)]
    with pytest.raises(ValidationError):
        AggregateRequest(items=items)


def test_request_caps_max_candidates() -> None:
    item = AggregationSourceItem(item_id="i0")
    with pytest.raises(ValidationError):
        AggregateRequest(items=[item], max_candidates=MAX_AGGREGATION_CANDIDATES + 1)
    with pytest.raises(ValidationError):
        AggregateRequest(items=[item], max_candidates=0)


def test_request_default_max_candidates() -> None:
    req = AggregateRequest(items=[AggregationSourceItem(item_id="i0")])
    assert req.max_candidates == 5


def test_candidate_score_clamped_into_unit_interval() -> None:
    assert AggregatedCampaign(**_candidate(score=1.7)).score == 1.0
    assert AggregatedCampaign(**_candidate(score=-3.0)).score == 0.0


def test_candidate_score_rejects_non_finite() -> None:
    with pytest.raises(ValidationError):
        AggregatedCampaign(**_candidate(score=float("nan")))


def test_candidate_rank_must_be_positive() -> None:
    with pytest.raises(ValidationError):
        AggregatedCampaign(**_candidate(rank=0))


def test_candidate_source_ids_bounded() -> None:
    with pytest.raises(ValidationError):
        AggregatedCampaign(**_candidate(source_item_ids=[f"i{n}" for n in range(MAX_AGG_SOURCE_IDS + 1)]))


def test_candidate_forbids_extra_fields() -> None:
    with pytest.raises(ValidationError):
        AggregatedCampaign(**_candidate(unexpected="x"))


def test_candidate_carries_full_campaign_record() -> None:
    candidate = AggregatedCampaign(**_candidate())
    assert candidate.record.campaign_name == "Invoice lure wave"
    assert candidate.record.model_id == "onprem/analyst-model"


def test_response_bounds_candidate_count() -> None:
    candidates = [AggregatedCampaign(**_candidate(rank=n + 1)) for n in range(MAX_AGGREGATION_CANDIDATES + 1)]
    with pytest.raises(ValidationError):
        AggregateResponse(model_id="onprem/analyst-model", candidates=candidates)


def test_response_requires_model_id() -> None:
    with pytest.raises(ValidationError):
        AggregateResponse(model_id="", candidates=[])


def test_response_roundtrips() -> None:
    response = AggregateResponse(
        model_id="onprem/analyst-model",
        candidates=[AggregatedCampaign(**_candidate())],
    )
    reparsed = AggregateResponse.model_validate_json(response.model_dump_json())
    assert reparsed == response
