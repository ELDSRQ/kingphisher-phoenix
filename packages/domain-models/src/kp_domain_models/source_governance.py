"""Pure source-license governance predicates shared by review boundaries."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID


class GovernedSource(Protocol):
    source_id: UUID
    license_state_id: UUID | None
    enabled: bool


class GovernedSourceTerms(Protocol):
    source_terms_id: UUID
    source_id: UUID
    commercial_use_ok: bool
    automation_ok: bool
    redistribution_ok: bool
    retention_ok: bool
    terms_reviewed_at: datetime
    next_review_at: datetime
    enabled: bool


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def source_governance_is_current(
    source: GovernedSource,
    terms: GovernedSourceTerms | None,
    *,
    evidence_license_state_id: UUID | None,
    as_of: datetime,
) -> bool:
    """Return whether source and evidence remain bound to current usable terms."""

    if (
        not source.enabled
        or terms is None
        or not terms.enabled
        or source.source_id != terms.source_id
        or source.license_state_id != terms.source_terms_id
        or evidence_license_state_id != terms.source_terms_id
        or not all(
            (
                terms.commercial_use_ok,
                terms.automation_ok,
                terms.redistribution_ok,
                terms.retention_ok,
            )
        )
    ):
        return False
    current = _as_utc(as_of)
    return _as_utc(terms.terms_reviewed_at) <= current < _as_utc(terms.next_review_at)
