"""M3 ingestion bridge: already-ingested ``SourceItem`` rows -> aggregation input.

The heavy lifting — fetching feeds behind the SSRF-hardened ``SecureFetcher``,
stripping HTML, and neutralizing prompt-injection — already happens in the
existing source-ingestion pipeline, which lands each item in ``source_items``
with a clean ``sanitized_text`` body (see ``jobs.process_ingestion``). This
module is therefore a thin, READ-ONLY adapter: it selects the eligible ingested
items and maps them onto the ``AggregationSourceItem`` contract so the background
aggregation stage can rank the most current campaigns. It fetches nothing and
writes nothing.

Two governance rules are non-negotiable here and both fail closed:

* **Source terms must be current.** Every candidate row is re-checked with the
  shared ``source_governance_is_current`` predicate (the same fail-closed rule
  the fetch path uses), so an item whose source is disabled or whose license
  terms lapsed or unbind is never fed to the model — no source, no aggregation.
* **Rejected items are never read.** An operator's ``rejected`` verdict is a hard
  exclusion. ``active`` and ``quarantined`` items ARE eligible: aggregation is a
  BACKGROUND ANALYSIS aid over the reviewable pool whose output (ranked
  candidates) a human still reviews before anything is promoted — quarantine
  gates promotion, not this advisory read, and the text was already neutralized
  at ingest. Deduplicated rows (``duplicate_of`` set) are skipped.
"""

from __future__ import annotations

from contextlib import AbstractContextManager
from datetime import UTC, datetime
from typing import Any, Protocol

from kp_contracts.aggregation import (
    MAX_AGG_EXCERPT_CHARS,
    MAX_AGG_FIELD_CHARS,
    MAX_AGG_ITEM_ID_CHARS,
    MAX_AGGREGATION_ITEMS,
    AggregatedCampaign,
    AggregationSourceItem,
)
from kp_database.models import Source, SourceItem, SourceTerms
from kp_domain_models import models as dm
from kp_domain_models.source_governance import source_governance_is_current
from kp_telemetry.logging import get_logger
from sqlalchemy import and_, select
from sqlalchemy.orm import Session

from kp_workers.aggregation_jobs import run_campaign_aggregation

logger = get_logger("kp_workers.aggregation_source")


class AggregationPassContext(Protocol):
    """What a background aggregation pass reads off a ``WorkerContext``.

    A structural view (mirroring ``aggregation_jobs.AggregationContext``, which
    it extends with the session factory) so this module needs no heavyweight
    ``jobs`` import and a test can pass any object exposing these two members.
    The real ``WorkerContext`` satisfies it. ``settings`` also carries the AI
    fields ``run_campaign_aggregation`` reads, so this context is accepted there.
    """

    settings: Any

    def session_factory(self) -> AbstractContextManager[Session]: ...


#: How many rows to pull from the DB per pass before the Python governance
#: filter. We over-fetch (a governance-lapsed or unbound item is dropped in
#: Python, not SQL) but stay hard-bounded so a huge ``source_items`` table can
#: never load an unbounded result set. Capped independently of the requested
#: item count.
_PREFETCH_CAP = 500


def _clip(text: str | None, limit: int) -> str:
    """Coerce a nullable DB text column to a bounded, contract-safe string.

    The ``AggregationSourceItem`` fields are length-bounded (``extra="forbid"``,
    ``max_length``), so an over-long excerpt would be a hard ``ValidationError``.
    Clipping here keeps a single oversized item from failing the whole batch.
    ``None`` (nullable ``claimed_actor``/``claimed_target_sector``) becomes "".
    """

    if not text:
        return ""
    return text[:limit]


def _iso_utc(value: object) -> str:
    """Render a DB timestamp as a canonical tz-aware ISO-8601 string, or "".

    ``published_at`` is stored ``timezone=True``, but a DB driver (SQLite in
    tests, some pathways) can hand back a naive datetime; treat naive as UTC so
    the emitted ``published_at`` is always offset-qualified and comparable —
    mirroring ``jobs._worker_utc``. A non-datetime (never expected) becomes "".
    """

    if not isinstance(value, datetime):
        return ""
    normalized = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return normalized.isoformat()


def _to_source_item(item: SourceItem) -> AggregationSourceItem:
    """Map one ingested ``SourceItem`` row onto the aggregation contract.

    ``excerpt`` is the already-neutralized ``sanitized_text`` — never the raw
    body — so nothing unsanitized reaches the model. Every field is clipped to
    its contract bound.
    """

    published_at = _iso_utc(item.published_at)
    return AggregationSourceItem(
        item_id=_clip(str(item.source_item_id), MAX_AGG_ITEM_ID_CHARS),
        title=_clip(item.title, MAX_AGG_FIELD_CHARS),
        excerpt=_clip(item.sanitized_text, MAX_AGG_EXCERPT_CHARS),
        published_at=published_at,
        source_reference=_clip(item.source_reference, MAX_AGG_FIELD_CHARS),
        claimed_actor=_clip(item.claimed_actor, MAX_AGG_FIELD_CHARS),
        claimed_target_sector=_clip(item.claimed_target_sector, MAX_AGG_FIELD_CHARS),
    )


def load_aggregation_items(
    session: Session,
    *,
    as_of: datetime,
    limit: int = MAX_AGGREGATION_ITEMS,
) -> list[AggregationSourceItem]:
    """Select eligible ingested items, most-current first, as aggregation input.

    Returns at most ``limit`` items (itself capped at ``MAX_AGGREGATION_ITEMS``,
    the contract's batch ceiling), ordered by recency so a pass sees the most
    current campaigns first. Every returned item comes from a source whose terms
    are current per ``source_governance_is_current`` (fail-closed) and is not
    ``rejected`` and not a duplicate. Read-only: no row is mutated.
    """

    bounded_limit = max(0, min(limit, MAX_AGGREGATION_ITEMS))
    if bounded_limit == 0:
        return []

    rows = session.execute(
        select(SourceItem, Source, SourceTerms)
        .join(Source, Source.source_id == SourceItem.source_id)
        .outerjoin(
            SourceTerms,
            and_(
                SourceTerms.source_terms_id == Source.license_state_id,
                SourceTerms.source_id == Source.source_id,
            ),
        )
        .where(
            Source.enabled.is_(True),
            SourceItem.quarantine_state != dm.QuarantineState.REJECTED,
            SourceItem.duplicate_of.is_(None),
        )
        # Recency-first: "current" campaigns are the point. published_at leads;
        # retrieved_at and the id are stable tie-breakers for deterministic paging.
        .order_by(
            SourceItem.published_at.desc(),
            SourceItem.retrieved_at.desc(),
            SourceItem.source_item_id,
        )
        .limit(_PREFETCH_CAP)
    ).all()

    items: list[AggregationSourceItem] = []
    for item, source, terms in rows:
        # Per-row, fail-closed: the same predicate the fetch path enforces, so a
        # lapsed/unbound licence drops the item here even though the fetch that
        # stored it was once permitted.
        if not source_governance_is_current(
            source,
            terms,
            evidence_license_state_id=item.license_state_id,
            as_of=as_of,
        ):
            continue
        items.append(_to_source_item(item))
        if len(items) >= bounded_limit:
            break
    return items


def run_campaign_aggregation_pass(
    ctx: AggregationPassContext,
    *,
    as_of: datetime | None = None,
    max_items: int = MAX_AGGREGATION_ITEMS,
    max_candidates: int = 5,
) -> list[AggregatedCampaign]:
    """One background aggregation pass over the current ingested-item pool.

    Loads the eligible items, then hands them to ``run_campaign_aggregation``
    (which calls the gateway ``/aggregate`` and validates the ranked candidates).
    Fail-closed to ``[]`` at every step: the feature is off unless an aggregation
    model is pinned, an empty pool is a no-op, and any load/aggregate failure
    degrades to no candidates rather than raising into a scheduler.

    Returns the ranked candidates. It does NOT persist them: durable storage,
    the periodic schedule, and the operator review surface are wired separately.
    """

    # Feature off -> no DB work at all, so an unconfigured worker is unchanged.
    if not getattr(ctx.settings, "ai_aggregate_model_id", None):
        return []

    moment = as_of or datetime.now(UTC)
    try:
        with ctx.session_factory() as session:
            items = load_aggregation_items(session, as_of=moment, limit=max_items)
    except Exception as exc:  # noqa: BLE001 - advisory pass must never crash a scheduler
        logger.info("aggregation item load failed (%s); no candidates this pass", type(exc).__name__)
        return []

    if not items:
        logger.info("aggregation pass found no eligible ingested items; nothing to rank")
        return []

    candidates = run_campaign_aggregation(ctx, items, max_candidates=max_candidates)
    logger.info("aggregation pass ranked %d candidate(s) from %d item(s)", len(candidates), len(items))
    return candidates
