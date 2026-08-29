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
from datetime import UTC, date, datetime, timedelta
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
MAX_LEDGER_RECIPIENT_HISTORY: Final = 500
MIN_PSEUDONYM_KEY_BYTES: Final = 32
#: Deterministic development-only values so disposable local databases remain
#: reproducible. Both the operator API and the retention worker must fall back
#: to the SAME dev values so named drill-down resolves the pseudonyms the
#: worker projected; managed modes never fall back to these.
LOCAL_AWARENESS_PSEUDONYM_KEY: Final = "4b502d6c6f63616c2d61776172656e6573732d6c65646765722d6f6e6c792121"
LOCAL_AWARENESS_PSEUDONYM_KEY_VERSION: Final = "synthetic-local-v1"
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


def recipient_pseudonym(*, tenant_scope: str, recipient_id: uuid.UUID, key: bytes) -> str:
    message = b"kingphisher-awareness-ledger-recipient\0" + tenant_scope.encode("ascii") + b"\0" + recipient_id.bytes
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _validate_pseudonym_inputs(*, tenant_scope: str, key: bytes, key_version: str, as_of: datetime) -> None:
    """Shared guard for every ledger surface that resolves a pseudonym."""

    if tenant_scope != SINGLE_TENANT_DATABASE_SCOPE:
        raise ValueError("awareness projection requires the isolated single-tenant database scope")
    if not isinstance(key, bytes) or len(key) < MIN_PSEUDONYM_KEY_BYTES:
        raise ValueError("awareness pseudonym key must contain at least 32 bytes")
    if _KEY_VERSION.fullmatch(key_version) is None:
        raise ValueError("awareness pseudonym key version is invalid")
    if as_of.tzinfo is None:
        raise ValueError("as_of must include a timezone")


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
        pseudonym = recipient_pseudonym(
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


@dataclass(frozen=True, slots=True)
class LedgerRecipientHistoryEntry:
    """One pseudonymous ledger fact for a named recipient drill-down.

    Contains no recipient attributes: the caller already knows the recipient
    (the route is addressed by recipient id), so only campaign-date outcomes
    are returned.
    """

    campaign_id: uuid.UUID
    campaign_date: date
    campaign_date_basis: str
    delivered: bool
    observed_open: bool
    observed_click: bool
    confirmed_interaction: bool
    reported: bool
    training_started: bool
    training_completed: bool
    no_activity_at_close: bool | None


@dataclass(frozen=True, slots=True)
class LedgerRecipientHistory:
    """Bounded chronological ledger history for one resolved pseudonym.

    ``recipient_pseudonym`` is the tenant-keyed HMAC hex value, not PII; it is
    included so an audited consumer can correlate repeated calls without ever
    receiving a mailbox or recipient attribute.
    """

    recipient_pseudonym: str
    pseudonym_key_version: str
    generated_at: datetime
    truncated: bool
    entries: tuple[LedgerRecipientHistoryEntry, ...]
    exposures_total: int
    delivered_total: int
    engaged_total: int
    no_activity_at_close_total: int
    repeat_exposures: int


def ledger_recipient_history(
    session: Session,
    *,
    tenant_scope: str,
    recipient_id: uuid.UUID,
    pseudonym_key: bytes,
    pseudonym_key_version: str,
    generated_at: datetime | None = None,
) -> LedgerRecipientHistory:
    """Return the bounded ledger history for one recipient's pseudonym.

    The caller supplies the stable tenant pseudonym key; this service resolves
    ``recipient_id`` to its pseudonym and reads only the PII-free ledger, never
    recipient tables or raw evidence. The result is chronological and capped at
    ``MAX_LEDGER_RECIPIENT_HISTORY`` rows; ``truncated`` reports the cap.

    ``pseudonym_key``/``pseudonym_key_version`` must be the same governed key
    the retention worker used to project the ledger, or the resolved pseudonym
    will not match any rows. Key rotation/recovery is a separate governed
    operation; this service never stores the key or the recipient identifier.
    """

    _validate_pseudonym_inputs(
        tenant_scope=tenant_scope,
        key=pseudonym_key,
        key_version=pseudonym_key_version,
        as_of=generated_at or datetime.now(UTC),
    )
    report_time = (generated_at or datetime.now(UTC)).astimezone(UTC)
    if not isinstance(recipient_id, uuid.UUID):
        raise TypeError("recipient_id must be a UUID")
    pseudonym = recipient_pseudonym(
        tenant_scope=tenant_scope,
        recipient_id=recipient_id,
        key=pseudonym_key,
    )

    rows = list(
        session.execute(
            select(
                AwarenessLedgerEntry.campaign_id,
                AwarenessLedgerEntry.campaign_date,
                AwarenessLedgerEntry.campaign_date_basis,
                AwarenessLedgerEntry.delivered,
                AwarenessLedgerEntry.observed_open,
                AwarenessLedgerEntry.observed_click,
                AwarenessLedgerEntry.confirmed_interaction,
                AwarenessLedgerEntry.reported,
                AwarenessLedgerEntry.training_started,
                AwarenessLedgerEntry.training_completed,
                AwarenessLedgerEntry.no_activity_at_close,
            )
            .where(
                AwarenessLedgerEntry.tenant_scope == tenant_scope,
                AwarenessLedgerEntry.recipient_pseudonym == pseudonym,
            )
            .order_by(
                AwarenessLedgerEntry.campaign_date,
                AwarenessLedgerEntry.campaign_id,
            )
            .limit(MAX_LEDGER_RECIPIENT_HISTORY + 1)
        )
    )
    truncated = len(rows) > MAX_LEDGER_RECIPIENT_HISTORY
    rows = rows[:MAX_LEDGER_RECIPIENT_HISTORY]
    entries = tuple(
        LedgerRecipientHistoryEntry(
            campaign_id=campaign_id,
            campaign_date=campaign_date,
            campaign_date_basis=campaign_date_basis,
            delivered=bool(delivered),
            observed_open=bool(_observed_open),
            observed_click=bool(observed_click),
            confirmed_interaction=bool(confirmed_interaction),
            reported=bool(reported),
            training_started=bool(training_started),
            training_completed=bool(training_completed),
            no_activity_at_close=(None if no_activity_at_close is None else bool(no_activity_at_close)),
        )
        for (
            campaign_id,
            campaign_date,
            campaign_date_basis,
            delivered,
            _observed_open,
            observed_click,
            confirmed_interaction,
            reported,
            training_started,
            training_completed,
            no_activity_at_close,
        ) in rows
    )
    exposures_total = len(entries)
    delivered_total = sum(1 for entry in entries if entry.delivered)
    # The same activity set as the ledger's no-activity-at-close rule and the
    # aggregate repeat distribution (open, click, report, confirmed
    # interaction, training started or completed).
    engaged_total = sum(
        1
        for entry in entries
        if (
            entry.observed_open
            or entry.observed_click
            or entry.confirmed_interaction
            or entry.reported
            or entry.training_started
            or entry.training_completed
        )
    )
    no_activity_at_close_total = sum(1 for entry in entries if entry.no_activity_at_close is True)
    repeat_exposures = max(0, exposures_total - 1)
    return LedgerRecipientHistory(
        recipient_pseudonym=pseudonym,
        pseudonym_key_version=pseudonym_key_version,
        generated_at=report_time,
        truncated=truncated,
        entries=entries,
        exposures_total=exposures_total,
        delivered_total=delivered_total,
        engaged_total=engaged_total,
        no_activity_at_close_total=no_activity_at_close_total,
        repeat_exposures=repeat_exposures,
    )
