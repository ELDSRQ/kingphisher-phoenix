"""Contract for the on-prem background threat-aggregation stage (M3).

On-prem there is no public web search (``/discover`` is Azure-only). Aggregation
instead runs a LARGE local model as a BACKGROUND job (minutes/hours, not chat
latency) over the platform's own already-ingested, neutralized threat-feed items,
to identify the most CURRENT, relevant campaigns and extract the optimal material
for a simulation — ranked candidates a human still reviews and promotes through
the existing governance path (activate -> approve -> generate).

Bounded and evidence-grounded. The input items are the platform's ingested feed
items (already sanitized public threat intel); the output carries only public
threat-intel facts and MUST NOT contain recipient or internal PII. Each
candidate's extracted facts reuse :class:`CampaignRecord` so the result folds
directly into the existing pattern/generation path.
"""

from __future__ import annotations

import math

from pydantic import BaseModel, ConfigDict, Field, field_validator

from kp_contracts.generation import (
    MAX_GENERATED_MODEL_ID_CHARS,
    CampaignRecord,
    ContextListText,
    ContextText,
)

#: A background aggregation pass reads a bounded batch of ingested feed items.
MAX_AGGREGATION_ITEMS = 50
#: …and returns at most this many ranked candidate campaigns.
MAX_AGGREGATION_CANDIDATES = 10
MAX_AGG_ITEM_ID_CHARS = 128
MAX_AGG_FIELD_CHARS = 500
MAX_AGG_EXCERPT_CHARS = 2000
MAX_AGG_SOURCE_IDS = 20
MAX_AGG_TIMESTAMP_CHARS = 64


class AggregationSourceItem(BaseModel):
    """One neutralized ingested threat-feed item offered to the analyst model."""

    model_config = ConfigDict(extra="forbid")

    item_id: str = Field(min_length=1, max_length=MAX_AGG_ITEM_ID_CHARS)
    title: str = Field(default="", max_length=MAX_AGG_FIELD_CHARS)
    #: Already-sanitized excerpt/body of the feed item (no executable content).
    excerpt: str = Field(default="", max_length=MAX_AGG_EXCERPT_CHARS)
    published_at: str = Field(default="", max_length=MAX_AGG_TIMESTAMP_CHARS)
    source_reference: str = Field(default="", max_length=MAX_AGG_FIELD_CHARS)
    claimed_actor: str = Field(default="", max_length=MAX_AGG_FIELD_CHARS)
    claimed_target_sector: str = Field(default="", max_length=MAX_AGG_FIELD_CHARS)


class AggregateRequest(BaseModel):
    """Request to the background aggregation stage: analyze these feed items."""

    model_config = ConfigDict(extra="forbid")

    items: list[AggregationSourceItem] = Field(min_length=1, max_length=MAX_AGGREGATION_ITEMS)
    #: How many ranked candidate campaigns to return.
    max_candidates: int = Field(default=5, ge=1, le=MAX_AGGREGATION_CANDIDATES)


class AggregatedCampaign(BaseModel):
    """One ranked current-campaign candidate identified by the analyst model.

    ``record`` is the same :class:`CampaignRecord` the extract stage produces, so
    an approved candidate folds into the existing generation path unchanged.
    ``source_item_ids`` are the provenance (which input items support it) so a
    human reviewer can trace the claim; scanner-style relevance still gets human
    review before anything is promoted.
    """

    model_config = ConfigDict(extra="forbid")

    rank: int = Field(ge=1)
    #: Model's relevance/optimality score in [0, 1]; clamped, never a hard gate.
    score: float
    title: ContextText
    #: Recency anchor for "current" (the model's read of the campaign's as-of).
    as_of: str = Field(default="", max_length=MAX_AGG_TIMESTAMP_CHARS)
    #: Provenance: input item_ids this candidate is derived from.
    source_item_ids: list[ContextListText] = Field(max_length=MAX_AGG_SOURCE_IDS)
    #: Why the model judged this a current, high-value simulation candidate.
    rationale: ContextText
    #: Extracted, generation-ready facts (reused from the P1 extraction contract).
    record: CampaignRecord

    @field_validator("score")
    @classmethod
    def clamp_finite_score(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("score must be finite")
        return max(0.0, min(1.0, value))


class AggregateResponse(BaseModel):
    """Ranked candidate campaigns from one background aggregation pass."""

    model_config = ConfigDict(extra="forbid")

    #: Pinned analyst-model identity (set by the gateway, not the model).
    model_id: str = Field(min_length=1, max_length=MAX_GENERATED_MODEL_ID_CHARS)
    candidates: list[AggregatedCampaign] = Field(max_length=MAX_AGGREGATION_CANDIDATES)
