"""Small, privacy-minimized aggregate queries for campaign reporting.

The current product is deliberately single-tenant-per-database: the schema
has no tenant discriminator.  Every query therefore requires the explicit
``single_tenant_database`` scope and rejects any other value instead of
pretending that an unenforceable tenant filter exists.

Send-state counts are a current snapshot because the schema does not retain a
timestamped state-transition history.  Optional evidence windows apply only
to immutable interaction timestamps and training completion timestamps.
"""

from __future__ import annotations

import math
import uuid
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any, Final

from kp_domain_models import models as dm
from sqlalchemy import case, distinct, exists, func, select
from sqlalchemy.orm import InstrumentedAttribute, Session
from sqlalchemy.sql import Select

from kp_database.models import (
    AwarenessLedgerEntry,
    Campaign,
    RecipientAssignment,
    TrackingEvent,
    TrackingToken,
    TrainingAssignment,
)

SINGLE_TENANT_DATABASE_SCOPE: Final = "single_tenant_database"
MAX_EVIDENCE_WINDOW: Final = timedelta(days=366)
MAX_TREND_CAMPAIGNS: Final = 12
MAX_TREND_WINDOW: Final = timedelta(days=366)
MAX_LEDGER_TREND_WINDOW: Final = timedelta(days=1_826)
# The repeat-history distribution caps its top bucket at this exposure count;
# the tail bucket means "at least this many exposures". The output is therefore
# bounded by construction regardless of ledger size.
MAX_LEDGER_REPEAT_BUCKET: Final = 5
type CsvCell = str | int | float
type CsvRow = tuple[CsvCell, ...]

_TERMINAL_TREND_STATES: Final = frozenset(
    {
        dm.CampaignState.CANCELLED,
        dm.CampaignState.COMPLETED,
        dm.CampaignState.EXPIRED,
        dm.CampaignState.RECALLED,
        dm.CampaignState.STOPPED,
    }
)


class CampaignReportNotFound(LookupError):
    """The campaign is absent from the explicitly scoped database."""


@dataclass(frozen=True, slots=True)
class EvidenceWindow:
    """Inclusive start and exclusive end for timestamped evidence."""

    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        if self.start.tzinfo is None or self.end.tzinfo is None:
            raise ValueError("evidence window timestamps must include a timezone")
        normalized_start = self.start.astimezone(UTC)
        normalized_end = self.end.astimezone(UTC)
        if normalized_start >= normalized_end:
            raise ValueError("evidence window start must precede end")
        if normalized_end - normalized_start > MAX_EVIDENCE_WINDOW:
            raise ValueError("evidence window cannot exceed 366 days")
        object.__setattr__(self, "start", normalized_start)
        object.__setattr__(self, "end", normalized_end)


@dataclass(frozen=True, slots=True)
class CampaignSelectionWindow:
    """Inclusive/exclusive schedule-start bounds for a longitudinal report."""

    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        if self.start.tzinfo is None or self.end.tzinfo is None:
            raise ValueError("campaign selection timestamps must include a timezone")
        normalized_start = self.start.astimezone(UTC)
        normalized_end = self.end.astimezone(UTC)
        if normalized_start >= normalized_end:
            raise ValueError("campaign selection start must precede end")
        if normalized_end - normalized_start > MAX_TREND_WINDOW:
            raise ValueError("campaign selection window cannot exceed 366 days")
        object.__setattr__(self, "start", normalized_start)
        object.__setattr__(self, "end", normalized_end)


@dataclass(frozen=True, slots=True)
class Rate:
    """One ratio with its denominator made explicit."""

    numerator: int
    denominator: int
    denominator_name: str

    @property
    def value(self) -> float | None:
        return self.numerator / self.denominator if self.denominator else None


@dataclass(frozen=True, slots=True)
class LedgerTrendBucket:
    """One calendar month of the pseudonymous five-year awareness series.

    Counts are assignment-exposure projections from the PII-free ledger
    (RET-005), not raw evidence and not unique people. ``no_click`` is an
    explicit delivered-but-not-clicked bucket, never a subtraction that could
    hide an inconsistency.
    """

    month: date
    targeted: int
    delivered: int
    clicked: int
    no_click: int
    confirmed_interaction: int
    reported: int
    training_assigned: int
    training_completed: int
    no_activity_at_close: int

    @property
    def rates(self) -> tuple[tuple[str, Rate], ...]:
        """Stable monthly rates with explicit delivered denominators."""

        return (
            ("clicked", Rate(self.clicked, self.delivered, "delivered_exposures")),
            ("no_click", Rate(self.no_click, self.delivered, "delivered_exposures")),
            ("confirmed_interaction", Rate(self.confirmed_interaction, self.delivered, "delivered_exposures")),
            ("reported", Rate(self.reported, self.delivered, "delivered_exposures")),
            (
                "training_completed",
                Rate(self.training_completed, self.training_assigned, "ledger_training_assignments"),
            ),
        )


@dataclass(frozen=True, slots=True)
class LedgerTrendPortfolio:
    """Window-total ledger series; rates sum numerators and denominators."""

    targeted: int
    delivered: int
    clicked: int
    no_click: int
    confirmed_interaction: int
    reported: int
    training_assigned: int
    training_completed: int
    no_activity_at_close: int

    @property
    def rates(self) -> tuple[tuple[str, Rate], ...]:
        return (
            ("clicked", Rate(self.clicked, self.delivered, "delivered_exposures")),
            ("no_click", Rate(self.no_click, self.delivered, "delivered_exposures")),
            ("confirmed_interaction", Rate(self.confirmed_interaction, self.delivered, "delivered_exposures")),
            ("reported", Rate(self.reported, self.delivered, "delivered_exposures")),
            (
                "training_completed",
                Rate(self.training_completed, self.training_assigned, "ledger_training_assignments"),
            ),
        )


@dataclass(frozen=True, slots=True)
class LedgerTrendReport:
    """Bounded monthly click/no-click series over the pseudonymous ledger."""

    generated_at: datetime
    window_start_inclusive: date
    window_end_exclusive: date
    buckets: tuple[LedgerTrendBucket, ...]
    portfolio: LedgerTrendPortfolio


@dataclass(frozen=True, slots=True)
class LedgerRepeatBucket:
    """One exposure-count bucket of the repeat-history distribution.

    ``exposures`` is ``1..MAX_LEDGER_REPEAT_BUCKET``, where the top bucket
    means "at least that many". ``participants`` counts distinct tenant-keyed
    recipient pseudonyms in that bucket; it is never a person count.
    """

    exposures: int
    participants: int

    def __post_init__(self) -> None:
        if type(self.exposures) is not int or not 1 <= self.exposures <= MAX_LEDGER_REPEAT_BUCKET:
            raise ValueError(f"repeat bucket exposures must be between 1 and {MAX_LEDGER_REPEAT_BUCKET}")
        if type(self.participants) is not int or self.participants < 0:
            raise ValueError("repeat bucket participants cannot be negative")


@dataclass(frozen=True, slots=True)
class LedgerRepeatDistribution:
    """Bounded repeat-exposure distribution over the pseudonymous ledger.

    ``exposure_buckets`` counts distinct pseudonyms by total exposures in the
    window; ``engaged_buckets`` counts distinct pseudonyms by the number of
    exposures with retained human activity (the same activity set as the
    ledger's no-activity-at-close rule). All counts derive from the PII-free
    ledger and are never resolved to identities.
    """

    generated_at: datetime
    window_start_inclusive: date
    window_end_exclusive: date
    exposure_buckets: tuple[LedgerRepeatBucket, ...]
    engaged_buckets: tuple[LedgerRepeatBucket, ...]
    unique_exposed: int
    exposures_total: int
    unique_engaged: int
    engaged_exposures_total: int
    no_activity_at_close: int

    @property
    def rates(self) -> tuple[tuple[str, Rate], ...]:
        """Repeat rates with explicit distinct-pseudonym denominators."""

        repeated = sum(bucket.participants for bucket in self.exposure_buckets if bucket.exposures >= 2)
        repeatedly_engaged = sum(bucket.participants for bucket in self.engaged_buckets if bucket.exposures >= 2)
        return (
            (
                "repeat_exposure",
                Rate(repeated, self.unique_exposed, "distinct_exposed_pseudonyms"),
            ),
            (
                "repeat_engagement",
                Rate(
                    repeatedly_engaged,
                    self.unique_engaged,
                    "distinct_engaged_pseudonyms",
                ),
            ),
        )


@dataclass(frozen=True, slots=True)
class CampaignFunnel:
    """Aggregate campaign truth containing no recipient-level attributes."""

    campaign_id: uuid.UUID
    generated_at: datetime
    evidence_window: EvidenceWindow | None
    targeted: int
    sent: int
    accepted: int
    delivered: int
    failed: int
    indeterminate: int
    opened: int
    clicked: int
    reported: int
    training_assigned: int
    training_completed: int

    @property
    def rates(self) -> tuple[tuple[str, Rate], ...]:
        """Stable rate definitions; an empty denominator returns ``None``."""

        return (
            ("sent", Rate(self.sent, self.targeted, "targeted_assignments")),
            ("accepted", Rate(self.accepted, self.sent, "provider_attempts")),
            ("delivered", Rate(self.delivered, self.accepted, "provider_accepted_handoffs")),
            ("failed", Rate(self.failed, self.targeted, "targeted_assignments")),
            ("opened", Rate(self.opened, self.accepted, "provider_accepted_handoffs")),
            ("clicked", Rate(self.clicked, self.accepted, "provider_accepted_handoffs")),
            ("reported", Rate(self.reported, self.accepted, "provider_accepted_handoffs")),
            (
                "training_completed",
                Rate(self.training_completed, self.training_assigned, "campaign_training_assignments"),
            ),
        )


@dataclass(frozen=True, slots=True)
class CampaignTrendPoint:
    """One terminal campaign and its canonical aggregate funnel."""

    campaign_id: uuid.UUID
    schedule_start: datetime
    schedule_end: datetime | None
    state: dm.CampaignState
    funnel: CampaignFunnel


@dataclass(frozen=True, slots=True)
class CampaignPortfolio:
    """Weighted assignment-exposure totals across selected campaigns."""

    targeted: int
    sent: int
    accepted: int
    delivered: int
    failed: int
    indeterminate: int
    opened: int
    clicked: int
    reported: int
    training_assigned: int
    training_completed: int

    @property
    def rates(self) -> tuple[tuple[str, Rate], ...]:
        return (
            ("sent", Rate(self.sent, self.targeted, "campaign_assignment_exposures")),
            ("accepted", Rate(self.accepted, self.sent, "provider_attempt_exposures")),
            ("delivered", Rate(self.delivered, self.accepted, "provider_accepted_handoff_exposures")),
            ("failed", Rate(self.failed, self.targeted, "campaign_assignment_exposures")),
            ("opened", Rate(self.opened, self.accepted, "provider_accepted_handoff_exposures")),
            ("clicked", Rate(self.clicked, self.accepted, "provider_accepted_handoff_exposures")),
            ("reported", Rate(self.reported, self.accepted, "provider_accepted_handoff_exposures")),
            (
                "training_completed",
                Rate(
                    self.training_completed,
                    self.training_assigned,
                    "campaign_training_assignment_exposures",
                ),
            ),
        )


@dataclass(frozen=True, slots=True)
class CampaignTrendReport:
    """A bounded chronological series and denominator-correct portfolio."""

    generated_at: datetime
    selection_window: CampaignSelectionWindow
    truncated: bool
    points: tuple[CampaignTrendPoint, ...]
    portfolio: CampaignPortfolio


def _require_scope(scope: str) -> None:
    if scope != SINGLE_TENANT_DATABASE_SCOPE:
        raise ValueError(
            "reporting supports only an isolated single-tenant database; the schema has no tenant discriminator"
        )


def _windowed(
    statement: Select[Any],
    column: InstrumentedAttribute[Any],
    window: EvidenceWindow | None,
    generated_at: datetime,
) -> Select[Any]:
    statement = statement.where(column <= generated_at)
    if window is not None:
        statement = statement.where(column >= window.start, column < window.end)
    return statement


def campaign_funnel(
    session: Session,
    campaign_id: uuid.UUID,
    *,
    scope: str,
    evidence_window: EvidenceWindow | None = None,
    generated_at: datetime | None = None,
) -> CampaignFunnel:
    """Return one bounded campaign aggregate.

    ``sent`` means a durable provider attempt was claimed. ``accepted`` means
    the provider acknowledged handoff and includes subsequently delivered
    rows. For ACS, ``delivered`` means the destination MTA accepted the
    message; it never means inbox placement, display, or reading.

    Interaction numerators count distinct accepted assignments, not raw
    events. Training completion uses its own training-assignment denominator.
    """

    _require_scope(scope)
    if not isinstance(campaign_id, uuid.UUID):
        raise TypeError("campaign_id must be a UUID")
    report_time = generated_at or datetime.now(UTC)
    if report_time.tzinfo is None:
        raise ValueError("generated_at must include a timezone")
    report_time = report_time.astimezone(UTC)
    exists = session.scalar(select(Campaign.campaign_id).where(Campaign.campaign_id == campaign_id).limit(1))
    if exists is None:
        raise CampaignReportNotFound(str(campaign_id))

    assignment_counts = session.execute(
        select(
            func.count(RecipientAssignment.recipient_assignment_id).label("targeted"),
            func.count(RecipientAssignment.recipient_assignment_id)
            .filter(RecipientAssignment.delivery_attempt_id.is_not(None))
            .label("sent"),
            func.count(RecipientAssignment.recipient_assignment_id)
            .filter(RecipientAssignment.provider_accepted_at.is_not(None))
            .label("accepted"),
            func.count(RecipientAssignment.recipient_assignment_id)
            .filter(RecipientAssignment.delivery_confirmed_at.is_not(None))
            .label("delivered"),
            func.count(RecipientAssignment.recipient_assignment_id)
            .filter(RecipientAssignment.send_state == dm.SendState.FAILED)
            .label("failed"),
            func.count(RecipientAssignment.recipient_assignment_id)
            .filter(RecipientAssignment.send_state == dm.SendState.INDETERMINATE)
            .label("indeterminate"),
        ).where(RecipientAssignment.campaign_id == campaign_id)
    ).one()

    assignment_for_event = func.coalesce(
        TrackingEvent.recipient_assignment_id,
        TrackingToken.recipient_assignment_id,
    )
    event_statement = (
        select(
            func.count(
                distinct(
                    case((TrackingEvent.event_type == dm.EventType.OPENED, RecipientAssignment.recipient_assignment_id))
                )
            ).label("opened"),
            func.count(
                distinct(
                    case(
                        (
                            TrackingEvent.event_type == dm.EventType.CLICKED,
                            RecipientAssignment.recipient_assignment_id,
                        )
                    )
                )
            ).label("clicked"),
            func.count(
                distinct(
                    case(
                        (
                            TrackingEvent.event_type == dm.EventType.MESSAGE_REPORTED,
                            RecipientAssignment.recipient_assignment_id,
                        )
                    )
                )
            ).label("reported"),
        )
        .select_from(TrackingEvent)
        .outerjoin(TrackingToken, TrackingToken.token_id == TrackingEvent.token_id)
        .join(RecipientAssignment, RecipientAssignment.recipient_assignment_id == assignment_for_event)
        .where(
            RecipientAssignment.campaign_id == campaign_id,
            RecipientAssignment.provider_accepted_at.is_not(None),
        )
    )
    event_counts = session.execute(
        _windowed(event_statement, TrackingEvent.occurred_at, evidence_window, report_time)
    ).one()

    training_statement = (
        select(func.count(distinct(TrainingAssignment.recipient_assignment_id)).label("assigned"))
        .select_from(TrainingAssignment)
        .join(
            RecipientAssignment,
            RecipientAssignment.recipient_assignment_id == TrainingAssignment.recipient_assignment_id,
        )
        .where(RecipientAssignment.campaign_id == campaign_id)
    )
    # The denominator remains all training assigned for the campaign. A
    # window, when present, limits only completions and is expressed as a
    # separate scalar so it cannot accidentally remove denominator rows.
    training_counts = session.execute(training_statement).one()
    completion_statement = (
        select(func.count(distinct(TrainingAssignment.recipient_assignment_id)))
        .select_from(TrainingAssignment)
        .join(
            RecipientAssignment,
            RecipientAssignment.recipient_assignment_id == TrainingAssignment.recipient_assignment_id,
        )
        .where(
            RecipientAssignment.campaign_id == campaign_id,
            TrainingAssignment.completed_at.is_not(None),
        )
    )
    completed = int(
        session.scalar(_windowed(completion_statement, TrainingAssignment.completed_at, evidence_window, report_time))
        or 0
    )

    return CampaignFunnel(
        campaign_id=campaign_id,
        generated_at=report_time,
        evidence_window=evidence_window,
        targeted=int(assignment_counts.targeted or 0),
        sent=int(assignment_counts.sent or 0),
        accepted=int(assignment_counts.accepted or 0),
        delivered=int(assignment_counts.delivered or 0),
        failed=int(assignment_counts.failed or 0),
        indeterminate=int(assignment_counts.indeterminate or 0),
        opened=int(event_counts.opened or 0),
        clicked=int(event_counts.clicked or 0),
        reported=int(event_counts.reported or 0),
        training_assigned=int(training_counts.assigned or 0),
        training_completed=completed,
    )


def ledger_trend(
    session: Session,
    *,
    scope: str,
    window_start: date,
    window_end: date,
    generated_at: datetime | None = None,
) -> LedgerTrendReport:
    """Return a bounded monthly click/no-click series from the awareness ledger.

    Reads only the PII-free pseudonymous ledger (RET-005), never raw evidence
    or recipient tables. The window selects ``campaign_date`` (schedule start
    or targeted date, whichever the projection recorded) and is capped at the
    ledger's 1,826-day retention so the report cannot outlive its evidence.
    Months with no projected exposures are omitted, and every bucket carries
    explicit denominators.
    """

    _require_scope(scope)
    if not isinstance(window_start, date) or not isinstance(window_end, date):
        raise TypeError("ledger trend window bounds must be dates")
    if window_start >= window_end:
        raise ValueError("ledger trend window start must precede end")
    if window_end - window_start > MAX_LEDGER_TREND_WINDOW:
        raise ValueError("ledger trend window cannot exceed 1826 days")
    report_time = generated_at or datetime.now(UTC)
    if report_time.tzinfo is None:
        raise ValueError("generated_at must include a timezone")
    report_time = report_time.astimezone(UTC)

    rows = session.execute(
        select(
            AwarenessLedgerEntry.campaign_date,
            AwarenessLedgerEntry.targeted,
            AwarenessLedgerEntry.delivered,
            AwarenessLedgerEntry.observed_click,
            AwarenessLedgerEntry.confirmed_interaction,
            AwarenessLedgerEntry.reported,
            AwarenessLedgerEntry.training_assigned,
            AwarenessLedgerEntry.training_completed,
            AwarenessLedgerEntry.no_activity_at_close,
        ).where(
            AwarenessLedgerEntry.tenant_scope == scope,
            AwarenessLedgerEntry.campaign_date >= window_start,
            AwarenessLedgerEntry.campaign_date < window_end,
        )
    )

    month_rows: dict[date, list[Any]] = {}
    for campaign_date, targeted, delivered, clicked, confirmed, reported, assigned, completed, no_activity in rows:
        bucket = month_rows.setdefault(campaign_date.replace(day=1), [])
        bucket.append((targeted, delivered, clicked, confirmed, reported, assigned, completed, no_activity))

    buckets: list[LedgerTrendBucket] = []
    for month in sorted(month_rows):
        targeted = sum(int(row[0]) for row in month_rows[month])
        delivered = sum(int(row[1]) for row in month_rows[month])
        clicked = sum(int(row[2]) for row in month_rows[month])
        no_click = sum(int(row[1]) and not int(row[2]) for row in month_rows[month])
        confirmed = sum(int(row[3]) for row in month_rows[month])
        reported_total = sum(int(row[4]) for row in month_rows[month])
        assigned = sum(int(row[5]) for row in month_rows[month])
        completed = sum(int(row[6]) for row in month_rows[month])
        no_activity = sum(int(row[7]) for row in month_rows[month])
        buckets.append(
            LedgerTrendBucket(
                month=month,
                targeted=targeted,
                delivered=delivered,
                clicked=clicked,
                no_click=no_click,
                confirmed_interaction=confirmed,
                reported=reported_total,
                training_assigned=assigned,
                training_completed=completed,
                no_activity_at_close=no_activity,
            )
        )

    totals = {
        name: sum(int(getattr(bucket, name)) for bucket in buckets)
        for name in (
            "targeted",
            "delivered",
            "clicked",
            "no_click",
            "confirmed_interaction",
            "reported",
            "training_assigned",
            "training_completed",
            "no_activity_at_close",
        )
    }
    return LedgerTrendReport(
        generated_at=report_time,
        window_start_inclusive=window_start,
        window_end_exclusive=window_end,
        buckets=tuple(buckets),
        portfolio=LedgerTrendPortfolio(**totals),
    )


def ledger_trend_csv_rows(report: LedgerTrendReport) -> tuple[CsvRow, ...]:
    """Return a fixed, formula-safe, PII-free ledger-series CSV projection."""

    header: CsvRow = (
        "scope",
        "window_start_inclusive",
        "window_end_exclusive",
        "generated_at",
        "bucket",
        "kind",
        "metric",
        "numerator",
        "denominator",
        "denominator_name",
        "rate",
    )
    rows: list[CsvRow] = [header]

    def append_projection(*, bucket: str, projection: LedgerTrendBucket | LedgerTrendPortfolio) -> None:
        prefix: tuple[CsvCell, ...] = (
            SINGLE_TENANT_DATABASE_SCOPE,
            report.window_start_inclusive.isoformat(),
            report.window_end_exclusive.isoformat(),
            report.generated_at.isoformat(),
            bucket,
        )
        for name in (
            "targeted",
            "delivered",
            "clicked",
            "no_click",
            "confirmed_interaction",
            "reported",
            "training_assigned",
            "training_completed",
            "no_activity_at_close",
        ):
            rows.append((*prefix, "count", name, int(getattr(projection, name)), "", "", ""))
        for name, rate in projection.rates:
            value = rate.value
            if value is not None and not math.isfinite(value):
                raise ValueError("ledger trend rate is not finite")
            rows.append(
                (
                    *prefix,
                    "rate",
                    name,
                    rate.numerator,
                    rate.denominator,
                    rate.denominator_name,
                    "" if value is None else value,
                )
            )

    append_projection(bucket="portfolio", projection=report.portfolio)
    for point in report.buckets:
        append_projection(bucket=point.month.isoformat(), projection=point)
    return tuple(rows)


def ledger_repeat_distribution(
    session: Session,
    *,
    scope: str,
    window_start: date,
    window_end: date,
    generated_at: datetime | None = None,
) -> LedgerRepeatDistribution:
    """Return a bounded repeat-exposure distribution from the awareness ledger.

    Reads only the PII-free pseudonymous ledger (RET-005), never raw evidence
    or recipient tables. Each row is one distinct tenant-keyed recipient
    pseudonym; ``participants`` therefore never names or counts people. The
    window selects ``campaign_date`` and is capped at the ledger's 1,826-day
    retention, matching :func:`ledger_trend`. The top exposure bucket is
    ``MAX_LEDGER_REPEAT_BUCKET`` and means "at least that many", so the output
    is bounded by construction.

    Engagement uses the same activity set as the ledger's no-activity-at-close
    rule (observed open, observed click, reported, confirmed interaction,
    training started, training completed), keeping repeat history consistent
    with the close-disposition definition.
    """

    _require_scope(scope)
    if not isinstance(window_start, date) or not isinstance(window_end, date):
        raise TypeError("ledger repeat window bounds must be dates")
    if window_start >= window_end:
        raise ValueError("ledger repeat window start must precede end")
    if window_end - window_start > MAX_LEDGER_TREND_WINDOW:
        raise ValueError("ledger repeat window cannot exceed 1826 days")
    report_time = generated_at or datetime.now(UTC)
    if report_time.tzinfo is None:
        raise ValueError("generated_at must include a timezone")
    report_time = report_time.astimezone(UTC)

    activity = case(
        (
            (
                AwarenessLedgerEntry.observed_open.is_(True)
                | AwarenessLedgerEntry.observed_click.is_(True)
                | AwarenessLedgerEntry.reported.is_(True)
                | AwarenessLedgerEntry.confirmed_interaction.is_(True)
                | AwarenessLedgerEntry.training_started.is_(True)
                | AwarenessLedgerEntry.training_completed.is_(True)
            ),
            1,
        ),
        else_=0,
    )
    rows = session.execute(
        select(
            AwarenessLedgerEntry.recipient_pseudonym,
            func.count().label("exposures"),
            func.sum(activity).label("engaged"),
            func.sum(case((AwarenessLedgerEntry.no_activity_at_close.is_(True), 1), else_=0)).label("no_activity"),
        )
        .where(
            AwarenessLedgerEntry.tenant_scope == scope,
            AwarenessLedgerEntry.campaign_date >= window_start,
            AwarenessLedgerEntry.campaign_date < window_end,
        )
        .group_by(AwarenessLedgerEntry.recipient_pseudonym)
    )

    exposure_counts: dict[int, int] = {}
    engaged_counts: dict[int, int] = {}
    unique_exposed = 0
    exposures_total = 0
    unique_engaged = 0
    engaged_exposures_total = 0
    no_activity_at_close = 0
    for _pseudonym, exposures, engaged, no_activity in rows:
        exposures = int(exposures)
        engaged = int(engaged)
        unique_exposed += 1
        exposures_total += exposures
        if engaged:
            unique_engaged += 1
            engaged_exposures_total += engaged
        no_activity_at_close += int(no_activity)
        exposure_bucket = min(exposures, MAX_LEDGER_REPEAT_BUCKET)
        exposure_counts[exposure_bucket] = exposure_counts.get(exposure_bucket, 0) + 1
        if engaged:
            engaged_bucket = min(engaged, MAX_LEDGER_REPEAT_BUCKET)
            engaged_counts[engaged_bucket] = engaged_counts.get(engaged_bucket, 0) + 1

    def _buckets(counts: dict[int, int]) -> tuple[LedgerRepeatBucket, ...]:
        return tuple(
            LedgerRepeatBucket(exposures=bucket, participants=counts.get(bucket, 0))
            for bucket in range(1, MAX_LEDGER_REPEAT_BUCKET + 1)
        )

    return LedgerRepeatDistribution(
        generated_at=report_time,
        window_start_inclusive=window_start,
        window_end_exclusive=window_end,
        exposure_buckets=_buckets(exposure_counts),
        engaged_buckets=_buckets(engaged_counts),
        unique_exposed=unique_exposed,
        exposures_total=exposures_total,
        unique_engaged=unique_engaged,
        engaged_exposures_total=engaged_exposures_total,
        no_activity_at_close=no_activity_at_close,
    )


def ledger_repeat_csv_rows(report: LedgerRepeatDistribution) -> tuple[CsvRow, ...]:
    """Return a fixed, formula-safe, PII-free repeat-history CSV projection."""

    header: CsvRow = (
        "scope",
        "window_start_inclusive",
        "window_end_exclusive",
        "generated_at",
        "kind",
        "metric",
        "numerator",
        "denominator",
        "denominator_name",
        "value",
    )
    rows: list[CsvRow] = [header]
    prefix: tuple[CsvCell, ...] = (
        SINGLE_TENANT_DATABASE_SCOPE,
        report.window_start_inclusive.isoformat(),
        report.window_end_exclusive.isoformat(),
        report.generated_at.isoformat(),
    )
    for bucket in report.exposure_buckets:
        rows.append((*prefix, "bucket", f"exposures_{bucket.exposures}", bucket.participants, "", "", ""))
    for bucket in report.engaged_buckets:
        rows.append((*prefix, "bucket", f"engaged_{bucket.exposures}", bucket.participants, "", "", ""))
    for name, value in (
        ("unique_exposed", report.unique_exposed),
        ("exposures_total", report.exposures_total),
        ("unique_engaged", report.unique_engaged),
        ("engaged_exposures_total", report.engaged_exposures_total),
        ("no_activity_at_close", report.no_activity_at_close),
    ):
        rows.append((*prefix, "summary", name, int(value), "", "", ""))
    for name, rate in report.rates:
        rate_value = rate.value
        if rate_value is not None and not math.isfinite(rate_value):
            raise ValueError("ledger repeat rate is not finite")
        rows.append(
            (
                *prefix,
                "summary",
                name,
                rate.numerator,
                rate.denominator,
                rate.denominator_name,
                "" if rate_value is None else rate_value,
            )
        )
    return tuple(rows)


def _utc_database_instant(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    # PostgreSQL returns aware values for timezone columns. SQLite drops the
    # marker in unit tests, so treat that backend-compatible representation as
    # UTC rather than emitting a timezone-less analytics timestamp.
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def campaign_trend(
    session: Session,
    *,
    scope: str,
    schedule_window: CampaignSelectionWindow,
    limit: int = MAX_TREND_CAMPAIGNS,
    generated_at: datetime | None = None,
) -> CampaignTrendReport:
    """Return a bounded, chronological series of terminal campaign funnels.

    The schedule window selects campaigns; it does not filter retained event
    evidence. Every point reuses :func:`campaign_funnel` with one shared
    ``generated_at`` cutoff. Portfolio rates sum canonical numerators and
    denominators, so campaigns are never given equal weight regardless of
    assignment volume.
    """

    _require_scope(scope)
    if not isinstance(schedule_window, CampaignSelectionWindow):
        raise TypeError("schedule_window must be a CampaignSelectionWindow")
    if type(limit) is not int or not 1 <= limit <= MAX_TREND_CAMPAIGNS:
        raise ValueError(f"trend limit must be between 1 and {MAX_TREND_CAMPAIGNS}")
    report_time = generated_at or datetime.now(UTC)
    if report_time.tzinfo is None:
        raise ValueError("generated_at must include a timezone")
    report_time = report_time.astimezone(UTC)

    has_assignment = exists(
        select(RecipientAssignment.recipient_assignment_id).where(
            RecipientAssignment.campaign_id == Campaign.campaign_id
        )
    )
    selected = list(
        session.execute(
            select(
                Campaign.campaign_id,
                Campaign.schedule_start,
                Campaign.schedule_end,
                Campaign.state,
            )
            .where(
                Campaign.schedule_start >= schedule_window.start,
                Campaign.schedule_start < schedule_window.end,
                Campaign.state.in_(_TERMINAL_TREND_STATES),
                has_assignment,
            )
            .order_by(Campaign.schedule_start.desc(), Campaign.campaign_id.desc())
            .limit(limit + 1)
        )
    )
    truncated = len(selected) > limit
    selected = selected[:limit]
    points: list[CampaignTrendPoint] = []
    for campaign_id, schedule_start, schedule_end, state in reversed(selected):
        normalized_start = _utc_database_instant(schedule_start)
        if normalized_start is None:
            continue
        points.append(
            CampaignTrendPoint(
                campaign_id=campaign_id,
                schedule_start=normalized_start,
                schedule_end=_utc_database_instant(schedule_end),
                state=state,
                funnel=campaign_funnel(
                    session,
                    campaign_id,
                    scope=scope,
                    generated_at=report_time,
                ),
            )
        )

    count_names = (
        "targeted",
        "sent",
        "accepted",
        "delivered",
        "failed",
        "indeterminate",
        "opened",
        "clicked",
        "reported",
        "training_assigned",
        "training_completed",
    )
    totals = {name: sum(int(getattr(point.funnel, name)) for point in points) for name in count_names}
    return CampaignTrendReport(
        generated_at=report_time,
        selection_window=schedule_window,
        truncated=truncated,
        points=tuple(points),
        portfolio=CampaignPortfolio(**totals),
    )


def campaign_trend_csv_rows(report: CampaignTrendReport) -> tuple[CsvRow, ...]:
    """Return a fixed, formula-safe, PII-free longitudinal CSV projection."""

    header: CsvRow = (
        "scope",
        "campaign_id",
        "schedule_start",
        "schedule_end",
        "state",
        "generated_at",
        "selection_start_inclusive",
        "selection_end_exclusive",
        "truncated",
        "kind",
        "metric",
        "numerator",
        "denominator",
        "denominator_name",
        "rate",
    )
    rows: list[CsvRow] = [header]

    def append_projection(
        *,
        scope: str,
        campaign_id: str = "",
        schedule_start: str = "",
        schedule_end: str = "",
        state: str = "",
        projection: CampaignFunnel | CampaignPortfolio,
    ) -> None:
        prefix: tuple[CsvCell, ...] = (
            scope,
            campaign_id,
            schedule_start,
            schedule_end,
            state,
            report.generated_at.isoformat(),
            report.selection_window.start.isoformat(),
            report.selection_window.end.isoformat(),
            str(report.truncated).lower(),
        )
        for name in (
            "targeted",
            "sent",
            "accepted",
            "delivered",
            "failed",
            "indeterminate",
            "opened",
            "clicked",
            "reported",
            "training_assigned",
            "training_completed",
        ):
            rows.append((*prefix, "count", name, int(getattr(projection, name)), "", "", ""))
        for name, rate in projection.rates:
            value = rate.value
            if value is not None and not math.isfinite(value):
                raise ValueError("trend rate is not finite")
            rows.append(
                (
                    *prefix,
                    "rate",
                    name,
                    rate.numerator,
                    rate.denominator,
                    rate.denominator_name,
                    "" if value is None else value,
                )
            )

    append_projection(scope="portfolio_assignment_exposures", projection=report.portfolio)
    for point in report.points:
        append_projection(
            scope="campaign",
            campaign_id=str(point.campaign_id),
            schedule_start=point.schedule_start.isoformat(),
            schedule_end=point.schedule_end.isoformat() if point.schedule_end else "",
            state=point.state.value,
            projection=point.funnel,
        )
    return tuple(rows)


def campaign_funnel_csv_rows(report: CampaignFunnel) -> tuple[CsvRow, ...]:
    """Return formula-safe, PII-free primitives ready for ``csv.writer``."""

    rows: list[CsvRow] = [
        ("metric", "value"),
        ("campaign_id", str(report.campaign_id)),
        ("generated_at", report.generated_at.isoformat()),
        ("semantics.sent", "durable_provider_attempt_claimed"),
        ("semantics.accepted", "provider_handoff_acknowledged"),
        ("semantics.delivered", "destination_mta_handoff_not_inbox_or_read"),
    ]
    if report.evidence_window is None:
        rows.append(("evidence_window", "all_retained_evidence"))
    else:
        rows.extend(
            (
                ("evidence_window_start_inclusive", report.evidence_window.start.isoformat()),
                ("evidence_window_end_exclusive", report.evidence_window.end.isoformat()),
            )
        )
    for name in (
        "targeted",
        "sent",
        "accepted",
        "delivered",
        "failed",
        "indeterminate",
        "opened",
        "clicked",
        "reported",
        "training_assigned",
        "training_completed",
    ):
        rows.append((f"count.{name}", int(getattr(report, name))))
    for name, rate in report.rates:
        value = rate.value
        if value is not None and not math.isfinite(value):
            raise ValueError("report rate is not finite")
        rows.extend(
            (
                (f"rate.{name}.numerator", rate.numerator),
                (f"rate.{name}.denominator", rate.denominator),
                (f"rate.{name}.denominator_name", rate.denominator_name),
                (f"rate.{name}.value", "" if value is None else value),
            )
        )
    return tuple(rows)
