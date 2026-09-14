from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast
from uuid import uuid4

import pytest
from kp_database.aggregation_candidates import (
    MAX_CANDIDATE_PAGE,
    get_candidate,
    insert_candidates,
    list_candidates,
    set_review_state,
)
from kp_database.models import AggregationCandidate
from kp_domain_models import models as dm
from sqlalchemy import Engine, Table, create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

NOW = datetime(2026, 9, 14, tzinfo=UTC)


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(_type: JSONB, _compiler: Any, **_kwargs: Any) -> str:
    return "JSON"


def _engine() -> Engine:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    cast(Table, AggregationCandidate.__table__).create(engine)
    return engine


def _candidate(rank: int = 1, **overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "rank": rank,
        "score": 0.9,
        "title": f"Campaign {rank}",
        "as_of": NOW.isoformat(),
        "rationale": "Recent and finance-targeting.",
        "model_id": "onprem/analyst",
        "record": {"campaign_name": f"Campaign {rank}", "confidence": 0.8},
        "source_item_ids": ["item-1", "item-2"],
    }
    base.update(overrides)
    return base


def test_insert_and_list_roundtrip() -> None:
    engine = _engine()
    run_id = uuid4()
    with Session(engine) as session:
        rows = insert_candidates(session, run_id=run_id, created_at=NOW, candidates=[_candidate(1), _candidate(2)])
        session.commit()
        assert len(rows) == 2
        assert all(r.review_state == dm.AggregationReviewState.PENDING for r in rows)
        listed = list_candidates(session)
        assert {r.title for r in listed} == {"Campaign 1", "Campaign 2"}
        assert listed[0].record["campaign_name"].startswith("Campaign")
        assert listed[0].source_item_ids == ["item-1", "item-2"]


def test_list_filters_by_review_state_and_run() -> None:
    engine = _engine()
    run_a, run_b = uuid4(), uuid4()
    with Session(engine) as session:
        insert_candidates(session, run_id=run_a, created_at=NOW, candidates=[_candidate(1)])
        insert_candidates(session, run_id=run_b, created_at=NOW, candidates=[_candidate(1)])
        session.commit()
        assert len(list_candidates(session, run_id=run_a)) == 1
        assert len(list_candidates(session, review_state=dm.AggregationReviewState.PENDING)) == 2
        assert len(list_candidates(session, review_state=dm.AggregationReviewState.PROMOTED)) == 0


def test_list_limit_is_clamped() -> None:
    engine = _engine()
    with Session(engine) as session:
        insert_candidates(session, run_id=uuid4(), created_at=NOW, candidates=[_candidate(n) for n in range(1, 6)])
        session.commit()
        assert len(list_candidates(session, limit=2)) == 2
        assert len(list_candidates(session, limit=MAX_CANDIDATE_PAGE + 1000)) == 5


def test_promote_records_verdict_and_pattern_link() -> None:
    engine = _engine()
    pattern_id = uuid4()
    with Session(engine) as session:
        (row,) = insert_candidates(session, run_id=uuid4(), created_at=NOW, candidates=[_candidate(1)])
        session.commit()
        updated = set_review_state(
            session,
            row.aggregation_candidate_id,
            dm.AggregationReviewState.PROMOTED,
            reviewed_at=NOW,
            reviewed_by="operator@example.com",
            promoted_pattern_id=pattern_id,
        )
        session.commit()
        assert updated is not None
        assert updated.review_state == dm.AggregationReviewState.PROMOTED
        assert updated.promoted_pattern_id == pattern_id
        assert updated.reviewed_by == "operator@example.com"


def test_second_verdict_is_rejected_no_double_promote() -> None:
    engine = _engine()
    with Session(engine) as session:
        (row,) = insert_candidates(session, run_id=uuid4(), created_at=NOW, candidates=[_candidate(1)])
        session.commit()
        first = set_review_state(
            session,
            row.aggregation_candidate_id,
            dm.AggregationReviewState.DISMISSED,
            reviewed_at=NOW,
            reviewed_by="op",
        )
        session.commit()
        assert first is not None
        # A second verdict on an already-decided candidate is refused (returns None).
        second = set_review_state(
            session, row.aggregation_candidate_id, dm.AggregationReviewState.PROMOTED, reviewed_at=NOW, reviewed_by="op"
        )
        assert second is None
        assert get_candidate(session, row.aggregation_candidate_id).review_state == dm.AggregationReviewState.DISMISSED


def test_missing_candidate_returns_none() -> None:
    engine = _engine()
    with Session(engine) as session:
        assert get_candidate(session, uuid4()) is None
        assert (
            set_review_state(session, uuid4(), dm.AggregationReviewState.DISMISSED, reviewed_at=NOW, reviewed_by="op")
            is None
        )


def test_cannot_transition_back_to_pending() -> None:
    engine = _engine()
    with Session(engine) as session:
        (row,) = insert_candidates(session, run_id=uuid4(), created_at=NOW, candidates=[_candidate(1)])
        session.commit()
        with pytest.raises(ValueError, match="pending"):
            set_review_state(
                session,
                row.aggregation_candidate_id,
                dm.AggregationReviewState.PENDING,
                reviewed_at=NOW,
                reviewed_by="op",
            )
