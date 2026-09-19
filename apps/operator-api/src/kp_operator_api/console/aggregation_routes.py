"""M3 aggregation console: background aggregation runs + candidate review.

An operator triggers a BACKGROUND aggregation pass over the platform's own
already-ingested, neutralized threat-feed items. A LARGE local analyst model
(reached through the internal AI gateway's POST /aggregate — the same shared
bearer the discovery consumer uses, never the caller's token) ranks the most
current campaigns; the ranked candidates land in ``aggregation_candidates`` for
human review. Nothing auto-promotes: the operator reviews each candidate and
either promotes it through the EXISTING threat-activation governance path
(activate -> linked CampaignPattern) or dismisses it.

Everything here is gated on MANAGE_SOURCES. The governed read is replicated from
``kp_workers.aggregation_source.load_aggregation_items`` (operator-api cannot
import kp_workers) and reuses the single shared ``source_governance_is_current``
fail-closed predicate, so a disabled source or lapsed license is never fed to
the model. When the gateway URL is unset (on-prem/disconnected) the run route
returns 503 rather than attempting any egress.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status
from kp_authorization.rbac import Capability, Principal
from kp_contracts.aggregation import (
    MAX_AGG_EXCERPT_CHARS,
    MAX_AGG_FIELD_CHARS,
    MAX_AGG_ITEM_ID_CHARS,
    MAX_AGGREGATION_CANDIDATES,
    MAX_AGGREGATION_ITEMS,
    AggregateRequest,
    AggregateResponse,
    AggregationSourceItem,
)
from kp_database.aggregation_candidates import (
    get_candidate,
    insert_candidates,
    list_candidates,
    set_review_state,
)
from kp_database.audit_store import AuditStore
from kp_database.models import AggregationCandidate, Source, SourceItem, SourceTerms
from kp_domain_models import models as dm
from kp_domain_models.source_governance import source_governance_is_current
from kp_telemetry.errors import ConflictError, NotFoundError
from kp_telemetry.logging import get_logger
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import and_, select
from sqlalchemy.orm import Session

from kp_operator_api.auth import require_capability
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.deps import get_audit_store, get_session, get_settings
from kp_operator_api.threat_routes import (
    _activate_linked_pattern,
    _locked_linked_patterns,
    _require_locked_current_governance,
    _source_pattern_id,
)

router = APIRouter(prefix="/api/v1/console/aggregate", tags=["console", "aggregation"])

logger = get_logger("kp_operator_api.aggregation")

#: Over-fetch bound before the Python governance filter (mirrors the worker
#: adapter): a governance-lapsed row is dropped in Python, not SQL, so pull a
#: hard-capped batch even for a huge ``source_items`` table.
_PREFETCH_CAP = 500


class RunRequest(BaseModel):
    """Operator request to start one background aggregation pass."""

    model_config = ConfigDict(extra="forbid")

    max_items: int = Field(default=MAX_AGGREGATION_ITEMS, ge=1, le=MAX_AGGREGATION_ITEMS)
    max_candidates: int = Field(default=5, ge=1, le=MAX_AGGREGATION_CANDIDATES)


def _clip(text: str | None, limit: int) -> str:
    """Coerce a nullable DB text column to a bounded, contract-safe string."""

    if not text:
        return ""
    return text[:limit]


def _iso_utc(value: object) -> str:
    """Render a DB timestamp as a canonical tz-aware ISO-8601 string, or ""."""

    if not isinstance(value, datetime):
        return ""
    normalized = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return normalized.isoformat()


def _to_source_item(item: SourceItem) -> AggregationSourceItem:
    """Map one ingested ``SourceItem`` row onto the aggregation contract.

    ``excerpt`` is the already-neutralized ``sanitized_text`` — never the raw
    body. Every field is clipped to its contract bound so a single oversized
    item cannot fail the whole batch.
    """

    return AggregationSourceItem(
        item_id=_clip(str(item.source_item_id), MAX_AGG_ITEM_ID_CHARS),
        title=_clip(item.title, MAX_AGG_FIELD_CHARS),
        excerpt=_clip(item.sanitized_text, MAX_AGG_EXCERPT_CHARS),
        published_at=_iso_utc(item.published_at),
        source_reference=_clip(item.source_reference, MAX_AGG_FIELD_CHARS),
        claimed_actor=_clip(item.claimed_actor, MAX_AGG_FIELD_CHARS),
        claimed_target_sector=_clip(item.claimed_target_sector, MAX_AGG_FIELD_CHARS),
    )


def _load_governed_items(
    session: Session,
    *,
    as_of: datetime,
    limit: int = MAX_AGGREGATION_ITEMS,
) -> list[AggregationSourceItem]:
    """Select eligible ingested items, most-current first, as aggregation input.

    Replicates ``kp_workers.aggregation_source.load_aggregation_items`` (which
    operator-api cannot import): SELECT SourceItem JOIN Source OUTERJOIN
    SourceTerms WHERE the source is enabled, the item is not rejected and not a
    duplicate; recency-ordered; hard-bounded prefetch; then a per-row,
    fail-closed ``source_governance_is_current`` check so a disabled source or a
    lapsed/unbound license drops the item. Read-only: no row is mutated.
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
        .order_by(
            SourceItem.published_at.desc(),
            SourceItem.retrieved_at.desc(),
            SourceItem.source_item_id,
        )
        .limit(_PREFETCH_CAP)
    ).all()

    items: list[AggregationSourceItem] = []
    for item, source, terms in rows:
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


def _execute_run(
    settings: OperatorApiSettings,
    session_factory: Any,
    run_id: uuid.UUID,
    items: list[AggregationSourceItem],
    max_candidates: int,
) -> None:
    """Background body: call the gateway ``/aggregate`` then persist candidates.

    Fail-closed: any error (transport, non-2xx, parse, validation, persist) is
    logged and swallowed — a background task must never raise. The DB session is
    kept CLOSED during the (long) gateway call; a fresh one is opened only to
    persist the validated candidates.
    """

    endpoint = settings.ai_gateway_url.strip().rstrip("/") + "/aggregate"
    headers = {"Content-Type": "application/json"}
    if settings.ai_gateway_api_key:
        headers["Authorization"] = f"Bearer {settings.ai_gateway_api_key}"
    payload = AggregateRequest(items=items, max_candidates=max_candidates).model_dump(mode="json")

    try:
        with httpx.Client(timeout=settings.ai_aggregate_timeout_seconds) as client:
            response = client.post(endpoint, json=payload, headers=headers)
        if response.status_code >= 400:
            logger.info("aggregation run %s: gateway returned %d; no candidates", run_id, response.status_code)
            return
        resp = AggregateResponse.model_validate(response.json())
    except Exception as exc:  # noqa: BLE001 - a background pass must never raise
        logger.info("aggregation run %s: gateway call failed (%s); no candidates", run_id, type(exc).__name__)
        return

    try:
        with session_factory() as persist_session:
            insert_candidates(
                persist_session,
                run_id=run_id,
                created_at=datetime.now(UTC),
                candidates=[
                    {
                        "rank": candidate.rank,
                        "score": candidate.score,
                        "title": candidate.title,
                        "as_of": candidate.as_of,
                        "rationale": candidate.rationale,
                        "model_id": resp.model_id,
                        "record": candidate.record.model_dump(mode="json"),
                        "source_item_ids": candidate.source_item_ids,
                    }
                    for candidate in resp.candidates
                ],
            )
            persist_session.commit()
    except Exception as exc:  # noqa: BLE001 - a background pass must never raise
        logger.info("aggregation run %s: persist failed (%s); no candidates stored", run_id, type(exc).__name__)
        return
    logger.info("aggregation run %s: stored %d candidate(s)", run_id, len(resp.candidates))


class AggregationScheduler:
    """Periodically run the background aggregation pass (M3).

    The operator-triggered ``POST /runs`` path exists, but a human must remember
    to trigger it. This scheduler runs the SAME ``_execute_run`` body on a fixed
    interval so the current-campaign ranking refreshes unattended. It only
    INSERTS pending candidates for review; it NEVER promotes — promotion stays
    the operator's explicit MANAGE_SOURCES action through
    ``/candidates/{id}/promote``, so the approval/canary/allowlist governance
    path is untouched. Errors never escape the loop; a failed pass is logged and
    skipped.
    """

    def __init__(
        self,
        settings: OperatorApiSettings,
        session_factory: Any,
        *,
        enabled: bool,
        interval_seconds: float,
        max_items: int,
        max_candidates: int,
        logger: Any | None = None,
    ) -> None:
        self._settings = settings
        self._session_factory = session_factory
        self._enabled = enabled
        self._interval_seconds = max(0.0, float(interval_seconds))
        self._max_items = max(1, int(max_items))
        self._max_candidates = max(1, int(max_candidates))
        self._logger = logger if logger is not None else get_logger("kp_operator_api.aggregation.scheduler")
        self.status = "disabled" if not enabled else "pending"  # disabled | pending | ok | error

    def _run_once_blocking(self) -> None:
        """One aggregation pass. Never raises (a background pass must not)."""
        if not self._settings.ai_gateway_url.strip():
            return
        try:
            with self._session_factory() as session:
                items = _load_governed_items(session, as_of=datetime.now(UTC), limit=self._max_items)
        except Exception as exc:  # noqa: BLE001 - a background pass must never raise
            self._logger.info("aggregation scheduler: item load failed (%s); skipping", type(exc).__name__)
            return
        if not items:
            return
        run_id = uuid.uuid4()
        _execute_run(self._settings, self._session_factory, run_id, items, self._max_candidates)

    async def run(self) -> None:
        if not self._enabled:
            return
        while True:
            try:
                await asyncio.to_thread(self._run_once_blocking)
                self.status = "ok"
            except Exception as exc:  # noqa: BLE001 - keep the loop alive
                self.status = "error"
                self._logger.info("aggregation scheduler: run failed (%s)", type(exc).__name__)
            await asyncio.sleep(self._interval_seconds)


def _candidate_view(row: AggregationCandidate) -> dict[str, Any]:
    """Serialize one candidate row: ids as strings, timestamps as ISO-8601."""

    return {
        "aggregation_candidate_id": str(row.aggregation_candidate_id),
        "run_id": str(row.run_id),
        "rank": row.rank,
        "score": row.score,
        "title": row.title,
        "as_of": row.as_of,
        "rationale": row.rationale,
        "model_id": row.model_id,
        "record": row.record,
        "source_item_ids": row.source_item_ids,
        "created_at": _iso_utc(row.created_at),
        "review_state": row.review_state.value,
        "reviewed_at": _iso_utc(row.reviewed_at) or None,
        "reviewed_by": row.reviewed_by,
        "promoted_pattern_id": str(row.promoted_pattern_id) if row.promoted_pattern_id is not None else None,
    }


@router.post("/runs", status_code=status.HTTP_202_ACCEPTED)
def create_run(
    body: RunRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    session: Session = Depends(get_session),
    settings: OperatorApiSettings = Depends(get_settings),
    _principal: Principal = Depends(require_capability(Capability.MANAGE_SOURCES)),
) -> dict[str, Any]:
    """Start a background aggregation pass over the current ingested-item pool.

    Loads the governed items on the request session (fail-closed), then hands a
    fresh session factory to a background task that performs the long gateway
    call and persists the ranked candidates. Returns 202 immediately.
    """

    if not settings.ai_gateway_url.strip():
        raise HTTPException(status_code=503, detail="aggregation is not configured")

    as_of = datetime.now(UTC)
    items = _load_governed_items(session, as_of=as_of, limit=body.max_items)
    if not items:
        raise HTTPException(status_code=409, detail="no eligible ingested items to aggregate")

    run_id = uuid.uuid4()
    session_factory = request.app.state.session_factory
    background_tasks.add_task(_execute_run, settings, session_factory, run_id, items, body.max_candidates)
    return {"run_id": str(run_id), "status": "started", "items_considered": len(items)}


@router.get("/candidates", status_code=status.HTTP_200_OK)
def list_aggregation_candidates(
    review_state: dm.AggregationReviewState | None = Query(default=None),
    run_id: uuid.UUID | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(get_session),
    _principal: Principal = Depends(require_capability(Capability.MANAGE_SOURCES)),
) -> dict[str, Any]:
    """List ranked aggregation candidates for review, newest run first."""

    rows = list_candidates(
        session,
        review_state=review_state,
        run_id=run_id,
        limit=limit,
        offset=offset,
    )
    return {"candidates": [_candidate_view(row) for row in rows]}


def _resolve_primary_item(session: Session, source_item_ids: list[str]) -> SourceItem | None:
    """Return the first supporting SourceItem that resolves, locked for update."""

    for raw_id in source_item_ids:
        try:
            item_id = uuid.UUID(raw_id)
        except (ValueError, AttributeError):
            continue
        item = session.get(SourceItem, item_id, with_for_update=True)
        if item is not None:
            return item
    return None


@router.post("/candidates/{candidate_id}/promote", status_code=status.HTTP_200_OK)
def promote_candidate(
    candidate_id: uuid.UUID,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_SOURCES)),
) -> dict[str, Any]:
    """Promote a pending candidate through the existing threat-activation path.

    Resolves the candidate's primary supporting ingested item, then mirrors
    ``threat_routes.activate_threat``: require current locked governance, mark
    the item active, activate its linked CampaignPattern, and record the
    operator verdict as ``promoted`` pointing at that pattern.
    """

    candidate = get_candidate(session, candidate_id)
    if candidate is None:
        raise NotFoundError("aggregation candidate not found")
    if candidate.review_state != dm.AggregationReviewState.PENDING:
        raise ConflictError("aggregation candidate is already decided")

    item = _resolve_primary_item(session, candidate.source_item_ids)
    if item is None:
        raise HTTPException(status_code=422, detail="candidate has no resolvable supporting source item")

    as_of = datetime.now(UTC)
    _require_locked_current_governance(session, item, as_of=as_of)
    item.quarantine_state = dm.QuarantineState.ACTIVE
    item.quarantine_reason = None
    item.duplicate_of = None
    _activate_linked_pattern(session, item, principal, as_of=as_of)
    # Resolve the ACTUAL linked pattern id. _activate_linked_pattern creates a
    # deterministic-id pattern only when none is linked yet; if one already
    # exists (an operator activated the item earlier, or seeded data), it keeps
    # that pattern — which may have a non-deterministic id. Assuming
    # _source_pattern_id here would point the candidate at a pattern that does
    # not exist, so read the real linked pattern instead.
    linked = _locked_linked_patterns(session, item)
    pattern_id = linked[0].campaign_pattern_id if linked else _source_pattern_id(item.source_item_id)

    updated = set_review_state(
        session,
        candidate_id,
        dm.AggregationReviewState.PROMOTED,
        reviewed_at=as_of,
        reviewed_by=principal.principal_id,
        promoted_pattern_id=pattern_id,
    )
    if updated is None:
        raise ConflictError("aggregation candidate is already decided")

    audit.record(
        session=session,
        actor=principal.principal_id,
        action="aggregation.candidate.promote",
        object_type="aggregation_candidate",
        object_id=str(candidate_id),
        detail={"campaign_pattern_id": str(pattern_id), "source_item_id": str(item.source_item_id)},
    )
    session.commit()
    return {"candidate": _candidate_view(updated), "campaign_pattern_id": str(pattern_id)}


@router.post("/candidates/{candidate_id}/dismiss", status_code=status.HTTP_200_OK)
def dismiss_candidate(
    candidate_id: uuid.UUID,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_SOURCES)),
) -> dict[str, Any]:
    """Dismiss a pending candidate without promoting it."""

    candidate = get_candidate(session, candidate_id)
    if candidate is None:
        raise NotFoundError("aggregation candidate not found")
    if candidate.review_state != dm.AggregationReviewState.PENDING:
        raise ConflictError("aggregation candidate is already decided")

    updated = set_review_state(
        session,
        candidate_id,
        dm.AggregationReviewState.DISMISSED,
        reviewed_at=datetime.now(UTC),
        reviewed_by=principal.principal_id,
    )
    if updated is None:
        raise ConflictError("aggregation candidate is already decided")

    audit.record(
        session=session,
        actor=principal.principal_id,
        action="aggregation.candidate.dismiss",
        object_type="aggregation_candidate",
        object_id=str(candidate_id),
        detail={"review_state": dm.AggregationReviewState.DISMISSED.value},
    )
    session.commit()
    return {"candidate": _candidate_view(updated)}
