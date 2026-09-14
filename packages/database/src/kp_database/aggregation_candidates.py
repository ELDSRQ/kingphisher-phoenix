"""Persistence + read helpers for M3 aggregation candidates.

The single place that reads and writes the ``aggregation_candidates`` store. Kept
contract-free (primitive inputs, ORM outputs) so it needs no ``kp_contracts``
dependency; the caller (operator-api) maps the ``AggregatedCampaign`` contract
onto ``insert_candidates`` and reads the ORM rows back out. Every write records a
verdict transition explicitly — nothing here promotes or dismisses on its own.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from kp_domain_models import models as dm
from sqlalchemy import select
from sqlalchemy.orm import Session

from kp_database.models import AggregationCandidate

#: Hard ceiling on a single list read, so a large store cannot return unbounded.
MAX_CANDIDATE_PAGE = 200


def insert_candidates(
    session: Session,
    *,
    run_id: UUID,
    created_at: datetime,
    candidates: Iterable[Mapping[str, Any]],
) -> list[AggregationCandidate]:
    """Insert one aggregation pass's ranked candidates under ``run_id``.

    Each mapping supplies ``rank``, ``score``, ``title``, ``as_of``,
    ``rationale``, ``model_id``, ``record`` (the serialized CampaignRecord), and
    ``source_item_ids``. Rows land ``pending`` for operator review. Returns the
    added ORM rows (flushed so ids are assigned); the caller commits.
    """

    rows: list[AggregationCandidate] = []
    for candidate in candidates:
        row = AggregationCandidate(
            aggregation_candidate_id=uuid4(),
            run_id=run_id,
            created_at=created_at,
            rank=int(candidate["rank"]),
            score=float(candidate["score"]),
            title=str(candidate["title"]),
            as_of=str(candidate.get("as_of", "")),
            rationale=str(candidate.get("rationale", "")),
            model_id=str(candidate["model_id"]),
            record=dict(candidate.get("record", {})),
            source_item_ids=[str(item) for item in candidate.get("source_item_ids", [])],
            review_state=dm.AggregationReviewState.PENDING,
        )
        session.add(row)
        rows.append(row)
    session.flush()
    return rows


def get_candidate(session: Session, candidate_id: UUID) -> AggregationCandidate | None:
    """Return one candidate by id, or ``None``."""

    return session.get(AggregationCandidate, candidate_id)


def list_candidates(
    session: Session,
    *,
    review_state: dm.AggregationReviewState | None = None,
    run_id: UUID | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[AggregationCandidate]:
    """List candidates, newest run first then rank, optionally filtered.

    ``limit`` is clamped to ``MAX_CANDIDATE_PAGE`` so a caller cannot request an
    unbounded page.
    """

    bounded_limit = max(1, min(int(limit), MAX_CANDIDATE_PAGE))
    bounded_offset = max(0, int(offset))
    conditions = []
    if review_state is not None:
        conditions.append(AggregationCandidate.review_state == review_state)
    if run_id is not None:
        conditions.append(AggregationCandidate.run_id == run_id)
    statement = (
        select(AggregationCandidate)
        .where(*conditions)
        .order_by(
            AggregationCandidate.created_at.desc(),
            AggregationCandidate.run_id,
            AggregationCandidate.rank,
        )
        .offset(bounded_offset)
        .limit(bounded_limit)
    )
    return list(session.execute(statement).scalars().all())


def set_review_state(
    session: Session,
    candidate_id: UUID,
    state: dm.AggregationReviewState,
    *,
    reviewed_at: datetime,
    reviewed_by: str,
    promoted_pattern_id: UUID | None = None,
) -> AggregationCandidate | None:
    """Record an operator verdict on a candidate.

    Only a ``pending`` candidate may transition (idempotency + no double-promote):
    a candidate already ``promoted`` or ``dismissed`` returns ``None`` so the
    caller can report a conflict rather than silently re-acting. ``pending`` is
    not a valid target state. Returns the updated row, or ``None`` if the
    candidate is missing or already decided. The caller commits.
    """

    if state == dm.AggregationReviewState.PENDING:
        raise ValueError("cannot transition a candidate back to pending")
    row = session.get(AggregationCandidate, candidate_id)
    if row is None or row.review_state != dm.AggregationReviewState.PENDING:
        return None
    row.review_state = state
    row.reviewed_at = reviewed_at
    row.reviewed_by = reviewed_by
    row.promoted_pattern_id = promoted_pattern_id
    session.flush()
    return row
