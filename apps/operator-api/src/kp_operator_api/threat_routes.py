"""Bounded operator curation API for ingested threat source items."""

from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query
from kp_authorization.rbac import Capability, Principal
from kp_campaign_patterns.builder import build_pattern_candidate
from kp_database.audit_store import AuditStore
from kp_database.models import CampaignPattern, Source, SourceItem, SourceTerms
from kp_domain_models import models as dm
from kp_domain_models.source_governance import source_governance_is_current
from kp_telemetry.errors import ConflictError, NotFoundError
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from kp_operator_api.auth import require_capability
from kp_operator_api.deps import get_audit_store, get_session

router = APIRouter(prefix="/api/v1/threats", tags=["threats"])

_MAX_LIMIT = 100
_MAX_OFFSET = 10_000
_MAX_TITLE_CHARS = 255
_MAX_EXCERPT_CHARS = 500
_MAX_CITATION_CHARS = 2_048
_MAX_CONTEXT_CHARS = 255
_MAX_RATIONALE_CHARS = 256
_MAX_INDICATORS = 20
_MAX_INDICATOR_NAME_CHARS = 64
_MAX_INDICATOR_VALUE_CHARS = 256
_MAX_DUPLICATE_HOPS = 100
_MAX_LINKED_PATTERNS = 100
_FULL_FRESHNESS_DAYS = 7.0
_STALE_DAYS = 90.0
_SOURCE_PATTERN_NAMESPACE = uuid.UUID("6d9c79ba-7047-4d39-a214-c034863ac3d5")

ReviewState = Literal["active", "quarantined", "rejected", "duplicate"]
FreshnessFilter = Literal["fresh", "aging", "stale"]
HealthState = Literal["disabled", "governance_blocked", "awaiting_first_success", "degraded", "healthy"]

_PII_PATTERNS = (
    re.compile(r"\b[^\s@]+@[^\s@]+\.[^\s@]+\b", re.IGNORECASE),
    re.compile(r"\bhttps?://", re.IGNORECASE),
    re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", re.IGNORECASE),
    re.compile(r"(?<!\d)(?:\+?\d[ .()\-]*){7,}(?!\d)"),
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class IndicatorSummary(_StrictModel):
    name: str = Field(max_length=_MAX_INDICATOR_NAME_CHARS)
    value: str = Field(max_length=_MAX_INDICATOR_VALUE_CHARS)


class ThreatFreshness(_StrictModel):
    as_of: datetime
    bucket: FreshnessFilter
    published_age_days: int = Field(ge=0)
    retrieved_age_days: int = Field(ge=0)
    recency_score: float = Field(ge=0.0, le=1.0)


class SourceHealth(_StrictModel):
    source_id: uuid.UUID
    name: str = Field(max_length=_MAX_TITLE_CHARS)
    enabled: bool
    governance_ready: bool
    state: HealthState
    last_success_at: datetime | None
    last_attempt_at: datetime | None
    consecutive_failures: int = Field(ge=0)


class ThreatItem(_StrictModel):
    source_item_id: uuid.UUID
    source_id: uuid.UUID
    title: str = Field(max_length=_MAX_TITLE_CHARS)
    publisher: str = Field(max_length=_MAX_TITLE_CHARS)
    citation: str = Field(max_length=_MAX_CITATION_CHARS)
    excerpt: str = Field(max_length=_MAX_EXCERPT_CHARS)
    excerpt_is_untrusted: Literal[True] = True
    published_at: datetime
    retrieved_at: datetime
    freshness: ThreatFreshness
    claimed_actor: str | None = Field(default=None, max_length=_MAX_CONTEXT_CHARS)
    claimed_target_sector: str | None = Field(default=None, max_length=_MAX_CONTEXT_CHARS)
    ttp_indicator_summary: list[IndicatorSummary] = Field(max_length=_MAX_INDICATORS)
    confidence: dm.Confidence
    quarantine_state: dm.QuarantineState
    review_state: ReviewState
    review_rationale: str | None = Field(default=None, max_length=_MAX_RATIONALE_CHARS)
    duplicate_of: uuid.UUID | None
    source_health: SourceHealth


class ThreatPage(_StrictModel):
    items: list[ThreatItem] = Field(max_length=_MAX_LIMIT)
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=_MAX_LIMIT)
    offset: int = Field(ge=0, le=_MAX_OFFSET)
    truncated: bool
    as_of: datetime


class ThreatReject(_StrictModel):
    rationale: str = Field(min_length=1, max_length=_MAX_RATIONALE_CHARS)

    @field_validator("rationale")
    @classmethod
    def require_non_pii_rationale(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or any(ord(character) < 32 or ord(character) == 127 for character in normalized):
            raise ValueError("rationale must be a single non-empty line")
        if any(pattern.search(normalized) for pattern in _PII_PATTERNS):
            raise ValueError("rationale must not contain identifying or contact data")
        return normalized


class ThreatMerge(_StrictModel):
    duplicate_of: uuid.UUID


class ThreatAction(_StrictModel):
    source_item_id: uuid.UUID
    quarantine_state: dm.QuarantineState
    review_state: ReviewState
    duplicate_of: uuid.UUID | None
    changed: bool


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _clip(value: object, limit: int) -> str:
    return str(value or "")[:limit]


def _optional_clip(value: object, limit: int) -> str | None:
    bounded = _clip(value, limit).strip()
    return bounded or None


def _review_state(item: SourceItem) -> ReviewState:
    if item.duplicate_of is not None:
        return "duplicate"
    if item.quarantine_state == dm.QuarantineState.QUARANTINED:
        return "quarantined"
    if item.quarantine_state == dm.QuarantineState.REJECTED:
        return "rejected"
    return "active"


def _safe_public_rationale(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return ThreatReject(rationale=_clip(value, _MAX_RATIONALE_CHARS)).rationale
    except ValueError:
        return "redacted"


def _summary_value(value: Any) -> str:
    if isinstance(value, str):
        rendered = value
    elif value is None or isinstance(value, bool | int | float):
        rendered = str(value)
    else:
        try:
            rendered = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
        except (TypeError, ValueError, RecursionError):
            rendered = "unsupported"
    return rendered[:_MAX_INDICATOR_VALUE_CHARS]


def _indicator_summary(value: object) -> list[IndicatorSummary]:
    if not isinstance(value, dict):
        return []
    keys = [key for key in value if isinstance(key, str) and key]

    def priority(key: str) -> tuple[int, str]:
        normalized = key.lower()
        is_ttp = any(token in normalized for token in ("ttp", "attack", "technique", "pattern", "stix"))
        return (0 if is_ttp else 1, normalized)

    return [
        IndicatorSummary(name=key[:_MAX_INDICATOR_NAME_CHARS], value=_summary_value(value[key]))
        for key in sorted(keys, key=priority)[:_MAX_INDICATORS]
    ]


def _freshness(item: SourceItem, *, as_of: datetime) -> ThreatFreshness:
    published = _as_utc(item.published_at) or as_of
    retrieved = _as_utc(item.retrieved_at) or as_of
    published_age = max(0.0, (as_of - published).total_seconds() / 86_400.0)
    retrieved_age = max(0.0, (as_of - retrieved).total_seconds() / 86_400.0)
    if published_age <= _FULL_FRESHNESS_DAYS:
        bucket: FreshnessFilter = "fresh"
        score = 1.0
    elif published_age >= _STALE_DAYS:
        bucket = "stale"
        score = 0.0
    else:
        bucket = "aging"
        score = 1.0 - (published_age - _FULL_FRESHNESS_DAYS) / (_STALE_DAYS - _FULL_FRESHNESS_DAYS)
    return ThreatFreshness(
        as_of=as_of,
        bucket=bucket,
        published_age_days=int(published_age),
        retrieved_age_days=int(retrieved_age),
        recency_score=round(score, 6),
    )


def _terms_current(source: Source, terms: SourceTerms | None, *, as_of: datetime) -> bool:
    return source_governance_is_current(
        source,
        terms,
        evidence_license_state_id=source.license_state_id,
        as_of=as_of,
    )


def _source_health(source: Source, terms: SourceTerms | None, *, as_of: datetime) -> SourceHealth:
    governance_ready = _terms_current(source, terms, as_of=as_of)
    if not source.enabled:
        state: HealthState = "disabled"
    elif not governance_ready:
        state = "governance_blocked"
    elif source.consecutive_failures > 0:
        state = "degraded"
    elif source.last_success_at is None:
        state = "awaiting_first_success"
    else:
        state = "healthy"
    return SourceHealth(
        source_id=source.source_id,
        name=_clip(source.name, _MAX_TITLE_CHARS),
        enabled=source.enabled,
        governance_ready=governance_ready,
        state=state,
        last_success_at=_as_utc(source.last_success_at),
        last_attempt_at=_as_utc(source.last_attempt_at),
        consecutive_failures=max(0, int(source.consecutive_failures)),
    )


def _threat_item(item: SourceItem, source: Source, terms: SourceTerms | None, *, as_of: datetime) -> ThreatItem:
    return ThreatItem(
        source_item_id=item.source_item_id,
        source_id=item.source_id,
        title=_clip(item.title, _MAX_TITLE_CHARS),
        publisher=_clip(item.publisher, _MAX_TITLE_CHARS),
        citation=_clip(item.source_reference, _MAX_CITATION_CHARS),
        excerpt=_clip(item.sanitized_text, _MAX_EXCERPT_CHARS),
        published_at=_as_utc(item.published_at) or as_of,
        retrieved_at=_as_utc(item.retrieved_at) or as_of,
        freshness=_freshness(item, as_of=as_of),
        claimed_actor=_optional_clip(item.claimed_actor, _MAX_CONTEXT_CHARS),
        claimed_target_sector=_optional_clip(item.claimed_target_sector, _MAX_CONTEXT_CHARS),
        ttp_indicator_summary=_indicator_summary(item.extracted_indicators),
        confidence=item.confidence,
        quarantine_state=item.quarantine_state,
        review_state=_review_state(item),
        review_rationale=_safe_public_rationale(item.quarantine_reason),
        duplicate_of=item.duplicate_of,
        source_health=_source_health(source, terms, as_of=as_of),
    )


@router.get("", response_model=ThreatPage)
def list_threats(
    review_state: ReviewState | None = Query(default=None),
    quarantine_state: dm.QuarantineState | None = Query(default=None),
    source_id: uuid.UUID | None = Query(default=None),
    confidence: dm.Confidence | None = Query(default=None),
    freshness: FreshnessFilter | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=_MAX_LIMIT),
    offset: int = Query(default=0, ge=0, le=_MAX_OFFSET),
    session: Session = Depends(get_session),
    _principal: Principal = Depends(require_capability(Capability.MANAGE_SOURCES)),
) -> ThreatPage:
    as_of = _utcnow()
    conditions: list[Any] = []
    if quarantine_state is not None:
        conditions.append(SourceItem.quarantine_state == quarantine_state)
    if source_id is not None:
        conditions.append(SourceItem.source_id == source_id)
    if confidence is not None:
        conditions.append(SourceItem.confidence == confidence)
    if review_state == "duplicate":
        conditions.append(SourceItem.duplicate_of.is_not(None))
    elif review_state is not None:
        conditions.append(SourceItem.duplicate_of.is_(None))
        conditions.append(SourceItem.quarantine_state == dm.QuarantineState(review_state))
    if freshness == "fresh":
        conditions.append(SourceItem.published_at >= as_of - timedelta(days=_FULL_FRESHNESS_DAYS))
    elif freshness == "aging":
        conditions.extend(
            (
                SourceItem.published_at < as_of - timedelta(days=_FULL_FRESHNESS_DAYS),
                SourceItem.published_at >= as_of - timedelta(days=_STALE_DAYS),
            )
        )
    elif freshness == "stale":
        conditions.append(SourceItem.published_at < as_of - timedelta(days=_STALE_DAYS))

    total = int(
        session.scalar(
            select(func.count())
            .select_from(SourceItem)
            .join(Source, Source.source_id == SourceItem.source_id)
            .where(*conditions)
        )
        or 0
    )
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
        .where(*conditions)
        .order_by(SourceItem.retrieved_at.desc(), SourceItem.published_at.desc(), SourceItem.source_item_id)
        .offset(offset)
        .limit(limit)
    ).all()
    items = [_threat_item(item, source, terms, as_of=as_of) for item, source, terms in rows]
    return ThreatPage(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        truncated=offset + len(items) < total,
        as_of=as_of,
    )


def _get_locked_item(session: Session, source_item_id: uuid.UUID) -> SourceItem:
    item = session.get(SourceItem, source_item_id, with_for_update=True)
    if item is None:
        raise NotFoundError("threat source item not found")
    return item


def _require_locked_current_governance(session: Session, item: SourceItem, *, as_of: datetime) -> None:
    source = session.get(Source, item.source_id, with_for_update=True, populate_existing=True)
    terms = (
        session.get(SourceTerms, source.license_state_id, with_for_update=True, populate_existing=True)
        if source is not None and source.license_state_id is not None
        else None
    )
    if source is None or not source_governance_is_current(
        source,
        terms,
        evidence_license_state_id=item.license_state_id,
        as_of=as_of,
    ):
        raise ConflictError("threat source governance is not current")


def _action(item: SourceItem, *, changed: bool) -> ThreatAction:
    return ThreatAction(
        source_item_id=item.source_item_id,
        quarantine_state=item.quarantine_state,
        review_state=_review_state(item),
        duplicate_of=item.duplicate_of,
        changed=changed,
    )


def _source_pattern_id(source_item_id: uuid.UUID) -> uuid.UUID:
    return uuid.uuid5(_SOURCE_PATTERN_NAMESPACE, source_item_id.hex)


def _domain_source_item(item: SourceItem) -> dm.SourceItem:
    return dm.SourceItem(
        source_item_id=item.source_item_id,
        source_id=item.source_id,
        publisher=item.publisher,
        title=item.title,
        published_at=_as_utc(item.published_at) or _utcnow(),
        retrieved_at=_as_utc(item.retrieved_at) or _utcnow(),
        sanitized_text=item.sanitized_text,
        content_hash=item.content_hash,
        source_reference=item.source_reference,
        license_state_id=item.license_state_id,
        confidence=item.confidence,
        claimed_actor=item.claimed_actor,
        claimed_target_sector=item.claimed_target_sector,
        extracted_indicators=item.extracted_indicators,
        quarantine_state=item.quarantine_state,
        quarantine_reason=item.quarantine_reason,
        duplicate_of=item.duplicate_of,
    )


def _principal_uuid_or_none(principal: Principal) -> uuid.UUID | None:
    try:
        return uuid.UUID(principal.principal_id)
    except (AttributeError, ValueError):
        return None


def _activate_linked_pattern(
    session: Session,
    item: SourceItem,
    principal: Principal,
    *,
    as_of: datetime,
) -> bool:
    patterns = _locked_linked_patterns(session, item)
    if not patterns:
        candidate = build_pattern_candidate(_domain_source_item(item), as_of=as_of)
        candidate.campaign_pattern_id = _source_pattern_id(item.source_item_id)
        candidate.created_by = _principal_uuid_or_none(principal)
        session.add(CampaignPattern(**candidate.model_dump()))
        return True
    # Source activation is a curation decision, not a content-review decision.
    # Preserve an independently human-rejected linked pattern exactly as-is.
    return False


def _locked_linked_patterns(session: Session, item: SourceItem) -> list[CampaignPattern]:
    statement = (
        select(CampaignPattern)
        .where(CampaignPattern.attack_mapping["source_item_id"].as_string() == str(item.source_item_id))
        .order_by(CampaignPattern.campaign_pattern_id)
        .limit(_MAX_LINKED_PATTERNS + 1)
        .with_for_update()
    )
    patterns = list(session.scalars(statement))
    if len(patterns) > _MAX_LINKED_PATTERNS:
        raise ConflictError("threat source item has too many linked patterns")
    deterministic = session.get(CampaignPattern, _source_pattern_id(item.source_item_id), with_for_update=True)
    if deterministic is not None and all(
        pattern.campaign_pattern_id != deterministic.campaign_pattern_id for pattern in patterns
    ):
        raise ConflictError("linked threat pattern provenance is inconsistent")
    return patterns


def _reject_linked_patterns(session: Session, item: SourceItem) -> bool:
    changed = False
    for pattern in _locked_linked_patterns(session, item):
        if pattern.approval_state == dm.PatternApprovalState.REJECTED:
            continue
        pattern.approval_state = dm.PatternApprovalState.REJECTED
        pattern.approved_by = None
        pattern.approved_at = None
        changed = True
    return changed


@router.post("/{source_item_id}/activate", response_model=ThreatAction)
def activate_threat(
    source_item_id: uuid.UUID,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_SOURCES)),
) -> ThreatAction:
    item = _get_locked_item(session, source_item_id)
    activation_as_of = _utcnow()
    _require_locked_current_governance(session, item, as_of=activation_as_of)
    state_changed = bool(
        item.quarantine_state != dm.QuarantineState.ACTIVE
        or item.quarantine_reason is not None
        or item.duplicate_of is not None
    )
    item.quarantine_state = dm.QuarantineState.ACTIVE
    item.quarantine_reason = None
    item.duplicate_of = None
    pattern_changed = _activate_linked_pattern(
        session,
        item,
        principal,
        as_of=activation_as_of,
    )
    changed = state_changed or pattern_changed
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="threat.activate" if changed else "threat.activate.noop",
        object_type="source_item",
        object_id=str(source_item_id),
        detail={"changed": changed, "state": dm.QuarantineState.ACTIVE.value},
    )
    session.commit()
    return _action(item, changed=changed)


@router.post("/{source_item_id}/reject", response_model=ThreatAction)
def reject_threat(
    source_item_id: uuid.UUID,
    body: ThreatReject,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_SOURCES)),
) -> ThreatAction:
    item = _get_locked_item(session, source_item_id)
    changed = bool(
        item.quarantine_state != dm.QuarantineState.REJECTED
        or item.quarantine_reason != body.rationale
        or item.duplicate_of is not None
    )
    item.quarantine_state = dm.QuarantineState.REJECTED
    item.quarantine_reason = body.rationale
    item.duplicate_of = None
    pattern_changed = _reject_linked_patterns(session, item)
    changed = changed or pattern_changed
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="threat.reject" if changed else "threat.reject.noop",
        object_type="source_item",
        object_id=str(source_item_id),
        detail={"changed": changed, "rationale": body.rationale},
    )
    session.commit()
    return _action(item, changed=changed)


def _duplicate_target(session: Session, item: SourceItem, duplicate_of: uuid.UUID) -> SourceItem:
    if duplicate_of == item.source_item_id:
        raise ConflictError("a threat source item cannot duplicate itself")
    target = session.get(SourceItem, duplicate_of, with_for_update=True)
    if target is None:
        raise NotFoundError("duplicate target threat source item not found")

    visited = {item.source_item_id}
    cursor = target
    for _ in range(_MAX_DUPLICATE_HOPS):
        if cursor.source_item_id in visited:
            raise ConflictError("duplicate relationship would create a cycle")
        visited.add(cursor.source_item_id)
        if cursor.duplicate_of is None:
            return target
        next_item = session.get(SourceItem, cursor.duplicate_of, with_for_update=True)
        if next_item is None:
            raise ConflictError("duplicate target chain is invalid")
        cursor = next_item
    raise ConflictError("duplicate target chain exceeds the supported boundary")


@router.post("/{source_item_id}/merge-duplicate", response_model=ThreatAction)
def merge_threat_duplicate(
    source_item_id: uuid.UUID,
    body: ThreatMerge,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_SOURCES)),
) -> ThreatAction:
    item = _get_locked_item(session, source_item_id)
    _duplicate_target(session, item, body.duplicate_of)
    changed = bool(
        item.duplicate_of != body.duplicate_of
        or item.quarantine_state != dm.QuarantineState.REJECTED
        or item.quarantine_reason != "duplicate"
    )
    item.quarantine_state = dm.QuarantineState.REJECTED
    item.quarantine_reason = "duplicate"
    item.duplicate_of = body.duplicate_of
    pattern_changed = _reject_linked_patterns(session, item)
    changed = changed or pattern_changed
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="threat.merge_duplicate" if changed else "threat.merge_duplicate.noop",
        object_type="source_item",
        object_id=str(source_item_id),
        detail={"changed": changed, "duplicate_of": str(body.duplicate_of)},
    )
    session.commit()
    return _action(item, changed=changed)
