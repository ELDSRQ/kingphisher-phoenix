"""Bounded projection from short-lived evidence into the awareness ledger.

The service deliberately does not select recipient PII. A caller supplies a
stable tenant-held pseudonym key and an exact, bounded set of assignments while
the same transaction still owns the raw rows. The caller may purge those rows
only after this function returns successfully.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

from kp_domain_models import models as dm
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from kp_database.models import (
    AwarenessLedgerEntry,
    Campaign,
    RecipientAssignment,
    TrackingEvent,
    TrackingToken,
    TrainingAssignment,
)
from kp_database.reporting import SINGLE_TENANT_DATABASE_SCOPE

AWARENESS_LEDGER_RETENTION_DAYS: Final = 1_826
MAX_LEDGER_PROJECTION_BATCH: Final = 500
MIN_PSEUDONYM_KEY_BYTES: Final = 32
_KEY_VERSION: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}\Z")
_ENTRY_NAMESPACE: Final = uuid.UUID("94e41132-9b1e-4bda-a9a7-522c83be828a")
AWARENESS_LEDGER_TERMINAL_CAMPAIGN_STATES: Final = frozenset(
    {
        dm.CampaignState.CANCELLED,
        dm.CampaignState.COMPLETED,
        dm.CampaignState.EXPIRED,
        dm.CampaignState.RECALLED,
        dm.CampaignState.STOPPED,
    }
)
_PROJECTED_EVENT_TYPES: Final = frozenset(
    {
        dm.EventType.OPENED,
        dm.EventType.CLICKED,
        dm.EventType.HUMAN_INTERACTION_CONFIRMED,
        dm.EventType.MESSAGE_REPORTED,
        dm.EventType.TRAINING_STARTED,
        dm.EventType.TRAINING_COMPLETED,
    }
)


class AwarenessLedgerProjectionError(RuntimeError):
    """Raw evidence could not be projected completely and must not be purged."""


@dataclass(frozen=True, slots=True)
class AwarenessLedgerProjectionResult:
    """One complete, bounded projection result."""

    requested_assignments: int
    projected_entries: int
    entry_ids: tuple[uuid.UUID, ...]


def _normalized_utc(value: datetime) -> datetime:
    # PostgreSQL returns aware timestamps. SQLite-backed unit fixtures can
    # drop the marker, so their database-compatible representation is UTC.
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _at_or_before(value: datetime | None, cutoff: datetime) -> bool:
    return value is not None and _normalized_utc(value) <= cutoff


def _recipient_pseudonym(*, tenant_scope: str, recipient_id: uuid.UUID, key: bytes) -> str:
    message = b"kingphisher-awareness-ledger-recipient\0" + tenant_scope.encode("ascii") + b"\0" + recipient_id.bytes
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _assignment_exposure_pseudonym(*, tenant_scope: str, assignment_id: uuid.UUID, key: bytes) -> str:
    message = b"kingphisher-awareness-ledger-exposure\0" + tenant_scope.encode("ascii") + b"\0" + assignment_id.bytes
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def project_awareness_ledger_batch(
    session: Session,
    *,
    tenant_scope: str,
    pseudonym_key: bytes,
    pseudonym_key_version: str,
    assignment_ids: list[uuid.UUID] | tuple[uuid.UUID, ...],
    projected_at: datetime,
) -> AwarenessLedgerProjectionResult:
    """Project an exact raw-evidence batch without committing the transaction.

    The assignment rows are locked until the caller commits. Missing rows,
    duplicate identifiers, invalid tenant/key inputs, or inconsistent delivery
    facts raise before any ledger write. The PostgreSQL upsert is idempotent and
    ignores an older projection racing with a newer one.

    ``pseudonym_key`` must remain stable for its declared version across the
    1,826-day history. Key rotation/recovery is a separate governed operation;
    this service never stores the key or recipient identifier in the ledger.
    """

    if tenant_scope != SINGLE_TENANT_DATABASE_SCOPE:
        raise ValueError("awareness projection requires the isolated single-tenant database scope")
    if not isinstance(pseudonym_key, bytes) or len(pseudonym_key) < MIN_PSEUDONYM_KEY_BYTES:
        raise ValueError("awareness pseudonym key must contain at least 32 bytes")
    if _KEY_VERSION.fullmatch(pseudonym_key_version) is None:
        raise ValueError("awareness pseudonym key version is invalid")
    if projected_at.tzinfo is None:
        raise ValueError("projected_at must include a timezone")
    projection_time = projected_at.astimezone(UTC)
    requested = tuple(assignment_ids)
    if len(requested) > MAX_LEDGER_PROJECTION_BATCH:
        raise ValueError(f"awareness projection batch cannot exceed {MAX_LEDGER_PROJECTION_BATCH} assignments")
    if any(not isinstance(assignment_id, uuid.UUID) for assignment_id in requested):
        raise TypeError("assignment_ids must contain UUIDs")
    if len(set(requested)) != len(requested):
        raise ValueError("assignment_ids must be unique")
    if not requested:
        return AwarenessLedgerProjectionResult(0, 0, ())

    # This lock is the project-before-purge boundary. The retention caller must
    # call this service and delete the same rows in one transaction.
    assignment_rows = list(
        session.execute(
            select(
                RecipientAssignment.recipient_assignment_id,
                RecipientAssignment.recipient_id,
                RecipientAssignment.campaign_id,
                RecipientAssignment.created_at,
                RecipientAssignment.provider_accepted_at,
                RecipientAssignment.delivery_confirmed_at,
                Campaign.schedule_start,
                Campaign.state,
            )
            .join(Campaign, Campaign.campaign_id == RecipientAssignment.campaign_id)
            .where(RecipientAssignment.recipient_assignment_id.in_(requested))
            .order_by(RecipientAssignment.recipient_assignment_id)
            .with_for_update(of=RecipientAssignment)
        )
    )
    found = {row[0] for row in assignment_rows}
    missing = set(requested) - found
    if missing:
        raise AwarenessLedgerProjectionError(
            f"awareness projection is incomplete; {len(missing)} assignment row(s) are missing"
        )

    assignment_for_event = func.coalesce(
        TrackingEvent.recipient_assignment_id,
        TrackingToken.recipient_assignment_id,
    )
    event_rows = list(
        session.execute(
            select(assignment_for_event, TrackingEvent.event_type)
            .select_from(TrackingEvent)
            .outerjoin(TrackingToken, TrackingToken.token_id == TrackingEvent.token_id)
            .where(
                assignment_for_event.in_(requested),
                TrackingEvent.event_type.in_(_PROJECTED_EVENT_TYPES),
                TrackingEvent.occurred_at <= projection_time,
            )
            .distinct()
        )
    )
    events_by_assignment: dict[uuid.UUID, set[dm.EventType]] = {assignment_id: set() for assignment_id in requested}
    for assignment_id, event_type in event_rows:
        if assignment_id in events_by_assignment:
            events_by_assignment[assignment_id].add(event_type)

    training_rows = list(
        session.execute(
            select(
                TrainingAssignment.recipient_assignment_id,
                TrainingAssignment.opened_at,
                TrainingAssignment.completed_at,
            ).where(TrainingAssignment.recipient_assignment_id.in_(requested))
        )
    )
    training_by_assignment = {
        assignment_id: (opened_at, completed_at) for assignment_id, opened_at, completed_at in training_rows
    }

    projections: list[dict[str, object]] = []
    entry_ids: list[uuid.UUID] = []
    for (
        assignment_id,
        recipient_id,
        campaign_id,
        assignment_created_at,
        provider_accepted_at,
        delivery_confirmed_at,
        schedule_start,
        campaign_state,
    ) in assignment_rows:
        accepted = _at_or_before(provider_accepted_at, projection_time)
        delivered = _at_or_before(delivery_confirmed_at, projection_time)
        if delivered and not accepted:
            raise AwarenessLedgerProjectionError(
                f"awareness projection found delivered-without-accepted assignment {assignment_id}"
            )
        event_types = events_by_assignment[assignment_id]
        training = training_by_assignment.get(assignment_id)
        training_opened_at = training[0] if training is not None else None
        training_completed_at = training[1] if training is not None else None
        training_assigned = training is not None or bool(
            event_types & {dm.EventType.TRAINING_STARTED, dm.EventType.TRAINING_COMPLETED}
        )
        training_completed = (
            _at_or_before(
                training_completed_at,
                projection_time,
            )
            or dm.EventType.TRAINING_COMPLETED in event_types
        )
        training_started = (
            _at_or_before(training_opened_at, projection_time)
            or training_completed
            or dm.EventType.TRAINING_STARTED in event_types
        )
        observed_open = dm.EventType.OPENED in event_types
        observed_click = dm.EventType.CLICKED in event_types
        reported = dm.EventType.MESSAGE_REPORTED in event_types
        confirmed = dm.EventType.HUMAN_INTERACTION_CONFIRMED in event_types
        human_activity = any(
            (
                observed_open,
                observed_click,
                reported,
                confirmed,
                training_started,
                training_completed,
            )
        )
        if campaign_state not in AWARENESS_LEDGER_TERMINAL_CAMPAIGN_STATES:
            raise AwarenessLedgerProjectionError(
                f"awareness projection requires a terminal campaign for assignment {assignment_id}"
            )
        campaign_closed = True
        no_activity_at_close = not human_activity if campaign_closed else None
        if schedule_start is not None:
            campaign_date = _normalized_utc(schedule_start).date()
            campaign_date_basis = "scheduled_start"
        else:
            campaign_date = _normalized_utc(assignment_created_at).date()
            campaign_date_basis = "targeted_at"
        pseudonym = _recipient_pseudonym(
            tenant_scope=tenant_scope,
            recipient_id=recipient_id,
            key=pseudonym_key,
        )
        assignment_pseudonym = _assignment_exposure_pseudonym(
            tenant_scope=tenant_scope,
            assignment_id=assignment_id,
            key=pseudonym_key,
        )
        entry_id = uuid.uuid5(_ENTRY_NAMESPACE, f"{tenant_scope}:{campaign_id}:{assignment_pseudonym}")
        entry_ids.append(entry_id)
        projections.append(
            {
                "awareness_ledger_entry_id": entry_id,
                "tenant_scope": tenant_scope,
                "pseudonym_key_version": pseudonym_key_version,
                "recipient_pseudonym": pseudonym,
                "assignment_exposure_pseudonym": assignment_pseudonym,
                "campaign_id": campaign_id,
                "campaign_date": campaign_date,
                "campaign_date_basis": campaign_date_basis,
                "targeted": True,
                "accepted": accepted,
                "delivered": delivered,
                "observed_open": observed_open,
                "observed_click": observed_click,
                "reported": reported,
                "confirmed_interaction": confirmed,
                "training_assigned": training_assigned,
                "training_started": training_started,
                "training_completed": training_completed,
                # The current completion endpoint accepts only the correct
                # knowledge-check answer, so completion is the pass fact.
                "training_passed": training_completed,
                "campaign_closed": campaign_closed,
                "no_activity_at_close": no_activity_at_close,
                "projected_at": projection_time,
                "retain_until": campaign_date + timedelta(days=AWARENESS_LEDGER_RETENTION_DAYS),
            }
        )

    statement = pg_insert(AwarenessLedgerEntry).values(projections)
    excluded = statement.excluded
    statement = statement.on_conflict_do_update(
        constraint="uq_awareness_ledger_scope_campaign_exposure",
        set_={
            "pseudonym_key_version": excluded.pseudonym_key_version,
            "campaign_date": excluded.campaign_date,
            "campaign_date_basis": excluded.campaign_date_basis,
            "targeted": excluded.targeted,
            "accepted": excluded.accepted,
            "delivered": excluded.delivered,
            "observed_open": excluded.observed_open,
            "observed_click": excluded.observed_click,
            "reported": excluded.reported,
            "confirmed_interaction": excluded.confirmed_interaction,
            "training_assigned": excluded.training_assigned,
            "training_started": excluded.training_started,
            "training_completed": excluded.training_completed,
            "training_passed": excluded.training_passed,
            "campaign_closed": excluded.campaign_closed,
            "no_activity_at_close": excluded.no_activity_at_close,
            "projected_at": excluded.projected_at,
            "retain_until": excluded.retain_until,
        },
        where=excluded.projected_at >= AwarenessLedgerEntry.projected_at,
    )
    session.execute(statement)
    return AwarenessLedgerProjectionResult(len(requested), len(projections), tuple(entry_ids))
