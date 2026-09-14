"""M3 ingestion bridge: SourceItem -> AggregationSourceItem read-adapter + pass.

These tests pin the two governance rules that make the bridge safe to feed a
model — source terms must be CURRENT (fail-closed) and REJECTED items are never
read — plus recency ordering, contract-bound clipping, and the pass's
fail-closed composition with the gateway call.

The DB is an in-memory SQLite built from the real table metadata (the same
approach as ``test_source_scheduler``); the gateway HTTP call in the pass
happy-path is stubbed by monkeypatching ``httpx.stream`` (as ``test_aggregation_jobs``).
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, cast

import httpx
import pytest
from kp_contracts.aggregation import MAX_AGG_EXCERPT_CHARS, MAX_AGGREGATION_ITEMS
from kp_database.models import Source, SourceItem, SourceTerms
from kp_domain_models import models as dm
from kp_workers import aggregation_source
from sqlalchemy import Engine, Table, create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

NOW = datetime(2026, 9, 14, tzinfo=UTC)


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(_type: JSONB, _compiler: Any, **_kwargs: Any) -> str:
    # source_items.extracted_indicators is JSONB (Postgres); render it as JSON on
    # the in-memory SQLite test engine, mirroring test_threat_routes.
    return "JSON"


# --- DB fixtures -------------------------------------------------------------


def _engine() -> Engine:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    cast(Table, Source.__table__).create(engine)
    cast(Table, SourceTerms.__table__).create(engine)
    cast(Table, SourceItem.__table__).create(engine)
    return engine


def _source_and_terms(
    index: int,
    *,
    enabled: bool = True,
    terms_enabled: bool = True,
    complete: bool = True,
    current: bool = True,
) -> tuple[Source, SourceTerms]:
    source_id = uuid.UUID(f"00000000-0000-4000-8000-{index:011x}f")
    terms_id = uuid.UUID(f"10000000-0000-4000-8000-{index:011x}e")
    source = Source(
        source_id=source_id,
        source_key=f"source-{index}",
        name=f"Source {index}",
        source_type=dm.SourceType.RSS,
        base_domain=f"feed-{index}.example.com",
        fetch_path="/feed.xml",
        license_state_id=terms_id,
        enabled=enabled,
        consecutive_failures=0,
    )
    terms = SourceTerms(
        source_terms_id=terms_id,
        source_id=source_id,
        terms_reference=f"https://feed-{index}.example.com/terms",
        terms_hash=f"{index:x}".rjust(64, "a")[-64:],
        commercial_use_ok=complete,
        automation_ok=complete,
        redistribution_ok=complete,
        retention_ok=complete,
        terms_reviewed_at=NOW - timedelta(days=30),
        next_review_at=NOW + timedelta(days=30) if current else NOW - timedelta(seconds=1),
        enabled=terms_enabled,
    )
    return source, terms


def _item(
    source: Source,
    *,
    index: int,
    published: datetime,
    sanitized_text: str = "A finance-sector campaign spoofing a brand's document notices.",
    quarantine: dm.QuarantineState = dm.QuarantineState.ACTIVE,
    duplicate_of: uuid.UUID | None = None,
    license_state_id: uuid.UUID | None = None,
    claimed_actor: str | None = "unattributed",
) -> SourceItem:
    return SourceItem(
        source_item_id=uuid.UUID(f"20000000-0000-4000-8000-{index:011x}d"),
        source_id=source.source_id,
        publisher=source.name,
        title=f"Campaign {index}",
        published_at=published,
        retrieved_at=published + timedelta(hours=1),
        sanitized_text=sanitized_text,
        content_hash=f"{index:x}".rjust(64, "b")[-64:],
        source_reference=f"https://feed.example.com/item/{index}",
        license_state_id=source.license_state_id if license_state_id is None else license_state_id,
        confidence=dm.Confidence.MEDIUM,
        claimed_actor=claimed_actor,
        claimed_target_sector="finance",
        quarantine_state=quarantine,
        duplicate_of=duplicate_of,
    )


@contextmanager
def _seeded(*objs: Any) -> Iterator[Engine]:
    engine = _engine()
    # expire_on_commit=False so a test can still read attributes (e.g. the id it
    # asserts on) off the seed objects after this session closes.
    with Session(engine, expire_on_commit=False) as session:
        session.add_all(objs)
        session.commit()
    yield engine


def _load(engine: Engine, **kwargs: Any) -> list[Any]:
    with Session(engine) as session:
        return aggregation_source.load_aggregation_items(session, as_of=NOW, **kwargs)


# --- load_aggregation_items: governance + filtering --------------------------


def test_current_active_item_is_loaded_and_mapped() -> None:
    source, terms = _source_and_terms(1)
    item = _item(source, index=1, published=NOW - timedelta(days=1))
    with _seeded(source, terms, item) as engine:
        loaded = _load(engine)
    assert len(loaded) == 1
    got = loaded[0]
    assert got.item_id == str(item.source_item_id)
    assert got.title == "Campaign 1"
    assert got.excerpt == item.sanitized_text  # the neutralized sanitized_text
    assert got.claimed_target_sector == "finance"
    assert got.published_at == (NOW - timedelta(days=1)).isoformat()


def test_quarantined_item_is_eligible() -> None:
    source, terms = _source_and_terms(1)
    item = _item(source, index=1, published=NOW, quarantine=dm.QuarantineState.QUARANTINED)
    with _seeded(source, terms, item) as engine:
        assert len(_load(engine)) == 1


def test_rejected_item_is_never_loaded() -> None:
    source, terms = _source_and_terms(1)
    item = _item(source, index=1, published=NOW, quarantine=dm.QuarantineState.REJECTED)
    with _seeded(source, terms, item) as engine:
        assert _load(engine) == []


def test_duplicate_item_is_skipped() -> None:
    source, terms = _source_and_terms(1)
    item = _item(source, index=1, published=NOW, duplicate_of=uuid.uuid4())
    with _seeded(source, terms, item) as engine:
        assert _load(engine) == []


def test_disabled_source_excludes_its_items() -> None:
    source, terms = _source_and_terms(1, enabled=False)
    item = _item(source, index=1, published=NOW)
    with _seeded(source, terms, item) as engine:
        assert _load(engine) == []


def test_lapsed_terms_excludes_items_fail_closed() -> None:
    source, terms = _source_and_terms(1, current=False)
    item = _item(source, index=1, published=NOW)
    with _seeded(source, terms, item) as engine:
        assert _load(engine) == []


def test_incomplete_terms_booleans_exclude_items() -> None:
    source, terms = _source_and_terms(1, complete=False)
    item = _item(source, index=1, published=NOW)
    with _seeded(source, terms, item) as engine:
        assert _load(engine) == []


def test_unbound_license_state_excludes_item() -> None:
    # Item whose license_state_id no longer matches the source's current terms.
    source, terms = _source_and_terms(1)
    item = _item(source, index=1, published=NOW, license_state_id=uuid.uuid4())
    with _seeded(source, terms, item) as engine:
        assert _load(engine) == []


# --- load_aggregation_items: ordering, bounds, clipping ----------------------


def test_items_are_ordered_most_recent_first() -> None:
    source, terms = _source_and_terms(1)
    old = _item(source, index=1, published=NOW - timedelta(days=10))
    new = _item(source, index=2, published=NOW - timedelta(days=1))
    with _seeded(source, terms, old, new) as engine:
        loaded = _load(engine)
    assert [i.title for i in loaded] == ["Campaign 2", "Campaign 1"]


def test_limit_is_capped_at_contract_ceiling() -> None:
    source, terms = _source_and_terms(1)
    items = [_item(source, index=n, published=NOW - timedelta(hours=n)) for n in range(1, 6)]
    with _seeded(source, terms, *items) as engine:
        # Request more than the contract ceiling; the cap holds, and a small
        # explicit limit is honoured.
        assert len(_load(engine, limit=MAX_AGGREGATION_ITEMS + 100)) == 5
        assert len(_load(engine, limit=2)) == 2
        assert _load(engine, limit=0) == []


def test_excerpt_is_clipped_to_contract_bound() -> None:
    source, terms = _source_and_terms(1)
    item = _item(source, index=1, published=NOW, sanitized_text="x" * (MAX_AGG_EXCERPT_CHARS + 500))
    with _seeded(source, terms, item) as engine:
        loaded = _load(engine)
    assert len(loaded[0].excerpt) == MAX_AGG_EXCERPT_CHARS


def test_null_claimed_actor_becomes_empty_string() -> None:
    source, terms = _source_and_terms(1)
    item = _item(source, index=1, published=NOW, claimed_actor=None)
    with _seeded(source, terms, item) as engine:
        assert _load(engine)[0].claimed_actor == ""


# --- run_campaign_aggregation_pass -------------------------------------------


class _ChunkStream(httpx.SyncByteStream):
    def __init__(self, *chunks: bytes) -> None:
        self.chunks = chunks

    def __iter__(self) -> Iterator[bytes]:
        yield from self.chunks


def _response(body: bytes) -> httpx.Response:
    return httpx.Response(
        200,
        stream=_ChunkStream(body),
        request=httpx.Request("POST", "https://ai.example/aggregate"),
    )


def _pass_ctx(engine: Engine | None, *, model_id: str | None = "aggregate-model") -> SimpleNamespace:
    @contextmanager
    def factory() -> Iterator[Session]:
        assert engine is not None
        with Session(engine) as session:
            yield session

    settings = SimpleNamespace(
        effective_ai_base_url="https://ai.example",
        ai_bearer_token="",
        ai_api_key="",
        ai_aggregate_model_id=model_id,
        aggregate_timeout_seconds=1800.0,
    )
    return SimpleNamespace(settings=settings, session_factory=factory)


def _aggregate_body(model_id: str = "aggregate-model") -> bytes:
    return json.dumps(
        {
            "model_id": model_id,
            "candidates": [
                {
                    "rank": 1,
                    "score": 0.9,
                    "title": "Campaign 1",
                    "as_of": NOW.isoformat(),
                    "source_item_ids": ["feed-1"],
                    "rationale": "Recent and finance-targeting.",
                    "record": {
                        "campaign_name": "Campaign 1",
                        "claimed_brand": "Brand",
                        "target_sector": "finance",
                        "target_region": "",
                        "lure_theme": "invoice",
                        "reported_subjects": ["Invoice ready"],
                        "sender_characteristics": "spoofed",
                        "body_characteristics": "portal link",
                        "call_to_action": "review",
                        "delivery_method": "email",
                        "evidence_excerpt": "campaign evidence",
                        "confidence": 0.8,
                        "model_id": "aggregate-model",
                    },
                }
            ],
        }
    ).encode()


def test_pass_feature_off_does_no_db_or_http(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_a: object, **_k: object) -> None:
        raise AssertionError("must not open a socket when the feature is off")

    monkeypatch.setattr(httpx, "stream", _boom)
    # engine=None would blow up if a session were opened; feature-off must return first.
    assert aggregation_source.run_campaign_aggregation_pass(_pass_ctx(None, model_id=None)) == []


def test_pass_empty_pool_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_a: object, **_k: object) -> None:
        raise AssertionError("must not call the gateway with no items")

    monkeypatch.setattr(httpx, "stream", _boom)
    with _seeded() as engine:  # no sources/items
        assert aggregation_source.run_campaign_aggregation_pass(_pass_ctx(engine)) == []


def test_pass_happy_path_returns_ranked_candidates(monkeypatch: pytest.MonkeyPatch) -> None:
    source, terms = _source_and_terms(1)
    item = _item(source, index=1, published=NOW)

    @contextmanager
    def _stream(*_a: object, **_k: object) -> Iterator[httpx.Response]:
        yield _response(_aggregate_body())

    monkeypatch.setattr(httpx, "stream", _stream)
    with _seeded(source, terms, item) as engine:
        candidates = aggregation_source.run_campaign_aggregation_pass(_pass_ctx(engine))
    assert len(candidates) == 1
    assert candidates[0].record.campaign_name == "Campaign 1"


def test_pass_load_failure_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_a: object, **_k: object) -> None:
        raise AssertionError("gateway must not be reached if the load failed")

    monkeypatch.setattr(httpx, "stream", _boom)

    class _BadCtx:
        settings = SimpleNamespace(ai_aggregate_model_id="aggregate-model")

        def session_factory(self) -> Any:
            raise RuntimeError("db down")

    assert aggregation_source.run_campaign_aggregation_pass(_BadCtx()) == []  # type: ignore[arg-type]
