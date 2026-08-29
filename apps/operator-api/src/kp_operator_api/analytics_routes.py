"""Privacy-minimized campaign analytics endpoints.

These routes are intentionally separate from the legacy campaign report
surface.  They expose the small, denominator-explicit reporting projection
from :mod:`kp_database.reporting` without recipient attributes.
"""

from __future__ import annotations

import csv
import io
import uuid
from datetime import date, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Response
from kp_authorization.rbac import Capability, Principal
from kp_database.awareness_ledger import LedgerRecipientHistory, ledger_recipient_history
from kp_database.models import Recipient
from kp_database.reporting import (
    MAX_LEDGER_TREND_WINDOW,
    MAX_TREND_CAMPAIGNS,
    SINGLE_TENANT_DATABASE_SCOPE,
    CampaignFunnel,
    CampaignPortfolio,
    CampaignReportNotFound,
    CampaignSelectionWindow,
    CampaignTrendReport,
    EvidenceWindow,
    LedgerRepeatBucket,
    LedgerRepeatDistribution,
    LedgerTrendBucket,
    LedgerTrendPortfolio,
    LedgerTrendReport,
    Rate,
    campaign_funnel,
    campaign_funnel_csv_rows,
    campaign_trend,
    campaign_trend_csv_rows,
    ledger_repeat_csv_rows,
    ledger_repeat_distribution,
    ledger_trend,
    ledger_trend_csv_rows,
)
from kp_domain_models import models as dm
from kp_telemetry.errors import NotFoundError, ValidationError_
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from kp_operator_api.auth import require_capability
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.deps import get_session, get_settings

router = APIRouter(prefix="/api/v1/analytics", tags=["analytics"])

_EVIDENCE_WINDOW_VALIDATION_MESSAGES = frozenset(
    {
        "evidence window timestamps must include a timezone",
        "evidence window start must precede end",
        "evidence window cannot exceed 366 days",
    }
)
_CAMPAIGN_TREND_VALIDATION_MESSAGES = frozenset(
    {
        "campaign selection timestamps must include a timezone",
        "campaign selection start must precede end",
        "campaign selection window cannot exceed 366 days",
        f"trend limit must be between 1 and {MAX_TREND_CAMPAIGNS}",
    }
)
_LEDGER_TREND_VALIDATION_MESSAGES = frozenset(
    {
        "ledger trend window bounds must be dates",
        "ledger trend window start must precede end",
        "ledger trend window cannot exceed 1826 days",
    }
)
_LEDGER_REPEAT_VALIDATION_MESSAGES = frozenset(
    {
        "ledger repeat window bounds must be dates",
        "ledger repeat window start must precede end",
        "ledger repeat window cannot exceed 1826 days",
    }
)
_LEDGER_HISTORY_VALIDATION_MESSAGES = frozenset(
    {
        "awareness pseudonym key must contain at least 32 bytes",
        "awareness pseudonym key version is invalid",
        "recipient_id must be a UUID",
    }
)


def _bounded_validation_message(exc: ValueError, *, allowed: frozenset[str], fallback: str) -> str:
    """Return only an exact public validation message, never exception detail."""

    message = exc.args[0] if len(exc.args) == 1 and type(exc.args[0]) is str else None
    return message if message in allowed else fallback


class CountMetric(BaseModel):
    """One named aggregate count."""

    name: str
    value: int


class RateMetric(BaseModel):
    """One rate with enough information to independently verify it."""

    name: str
    numerator: int
    denominator: int
    denominator_name: str
    value: float | None


class EvidenceWindowView(BaseModel):
    start_inclusive: datetime
    end_exclusive: datetime
    applies_to: tuple[str, ...]
    transport_snapshot: str


class CampaignFunnelView(BaseModel):
    schema_version: Literal["1"] = "1"
    campaign_id: uuid.UUID
    generated_at: datetime
    evidence_window: EvidenceWindowView | None
    transport: tuple[CountMetric, ...]
    engagement: tuple[CountMetric, ...]
    training: tuple[CountMetric, ...]
    rates: tuple[RateMetric, ...]
    semantics: dict[str, str]
    privacy: str


class CampaignTrendPointView(BaseModel):
    campaign_id: uuid.UUID
    schedule_start: datetime
    schedule_end: datetime | None
    state: dm.CampaignState
    counts: tuple[CountMetric, ...]
    rates: tuple[RateMetric, ...]


class CampaignPortfolioView(BaseModel):
    unit: Literal["campaign_assignment_exposures"] = "campaign_assignment_exposures"
    counts: tuple[CountMetric, ...]
    rates: tuple[RateMetric, ...]


class CampaignTrendView(BaseModel):
    schema_version: Literal["1"] = "1"
    generated_at: datetime
    selection_start_inclusive: datetime
    selection_end_exclusive: datetime
    truncated: bool
    points: tuple[CampaignTrendPointView, ...]
    portfolio: CampaignPortfolioView
    semantics: dict[str, str]
    privacy: str


class LedgerTrendBucketView(BaseModel):
    month: date
    counts: tuple[CountMetric, ...]
    rates: tuple[RateMetric, ...]


class LedgerTrendPortfolioView(BaseModel):
    unit: Literal["ledger_exposure_months"] = "ledger_exposure_months"
    counts: tuple[CountMetric, ...]
    rates: tuple[RateMetric, ...]


class LedgerTrendView(BaseModel):
    schema_version: Literal["1"] = "1"
    generated_at: datetime
    window_start_inclusive: date
    window_end_exclusive: date
    buckets: tuple[LedgerTrendBucketView, ...]
    portfolio: LedgerTrendPortfolioView
    semantics: dict[str, str]
    privacy: str


class LedgerRepeatBucketView(BaseModel):
    """One exposure-count bucket; the top bucket means "at least that many"."""

    exposures: int
    participants: int


class LedgerRepeatDistributionView(BaseModel):
    schema_version: Literal["1"] = "1"
    generated_at: datetime
    window_start_inclusive: date
    window_end_exclusive: date
    exposure_buckets: tuple[LedgerRepeatBucketView, ...]
    engaged_buckets: tuple[LedgerRepeatBucketView, ...]
    summary: tuple[CountMetric, ...]
    rates: tuple[RateMetric, ...]
    semantics: dict[str, str]
    privacy: str


class LedgerRecipientHistoryEntryView(BaseModel):
    """One pseudonymous ledger fact; no recipient attributes are returned."""

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


class LedgerRecipientHistoryView(BaseModel):
    schema_version: Literal["1"] = "1"
    generated_at: datetime
    truncated: bool
    summary: tuple[CountMetric, ...]
    entries: tuple[LedgerRecipientHistoryEntryView, ...]
    semantics: dict[str, str]
    privacy: str


def _evidence_window(start: datetime | None, end: datetime | None) -> EvidenceWindow | None:
    if (start is None) != (end is None):
        raise ValidationError_("evidence_start and evidence_end must be supplied together")
    if start is None or end is None:
        return None
    try:
        return EvidenceWindow(start, end)
    except ValueError as exc:
        message = _bounded_validation_message(
            exc,
            allowed=_EVIDENCE_WINDOW_VALIDATION_MESSAGES,
            fallback="evidence window is invalid",
        )
        raise ValidationError_(message) from None


def _load_report(
    session: Session,
    campaign_id: uuid.UUID,
    *,
    evidence_start: datetime | None,
    evidence_end: datetime | None,
) -> CampaignFunnel:
    try:
        return campaign_funnel(
            session,
            campaign_id,
            scope=SINGLE_TENANT_DATABASE_SCOPE,
            evidence_window=_evidence_window(evidence_start, evidence_end),
        )
    except CampaignReportNotFound as exc:
        raise NotFoundError("campaign not found") from exc


def _view(report: CampaignFunnel) -> CampaignFunnelView:
    window = report.evidence_window
    return CampaignFunnelView(
        campaign_id=report.campaign_id,
        generated_at=report.generated_at,
        evidence_window=(
            EvidenceWindowView(
                start_inclusive=window.start,
                end_exclusive=window.end,
                applies_to=("opened", "clicked", "reported", "training_completed"),
                transport_snapshot="current assignment state; not limited by the evidence window",
            )
            if window is not None
            else None
        ),
        transport=tuple(
            CountMetric(name=name, value=getattr(report, name))
            for name in ("targeted", "sent", "accepted", "delivered", "failed", "indeterminate")
        ),
        engagement=tuple(
            CountMetric(name=name, value=getattr(report, name)) for name in ("opened", "clicked", "reported")
        ),
        training=tuple(
            CountMetric(name=name, value=getattr(report, name)) for name in ("training_assigned", "training_completed")
        ),
        rates=tuple(
            RateMetric(
                name=name,
                numerator=rate.numerator,
                denominator=rate.denominator,
                denominator_name=rate.denominator_name,
                value=rate.value,
            )
            for name, rate in report.rates
        ),
        semantics={
            "targeted": "frozen campaign assignments",
            "sent": "durable provider attempt claimed",
            "accepted": "provider acknowledged message handoff",
            "delivered": "destination MTA handoff; not inbox placement, display, or reading",
            "engagement": "distinct accepted assignments with retained evidence",
            "training_completed": "completed campaign training assignments",
        },
        privacy="aggregate counts only; no recipient identifiers or recipient attributes",
    )


_COUNT_NAMES = (
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


def _count_view(projection: CampaignFunnel | CampaignPortfolio) -> tuple[CountMetric, ...]:
    return tuple(CountMetric(name=name, value=int(getattr(projection, name))) for name in _COUNT_NAMES)


def _rate_view(rates: tuple[tuple[str, Rate], ...]) -> tuple[RateMetric, ...]:
    return tuple(
        RateMetric(
            name=name,
            numerator=rate.numerator,
            denominator=rate.denominator,
            denominator_name=rate.denominator_name,
            value=rate.value,
        )
        for name, rate in rates
    )


def _trend_view(report: CampaignTrendReport) -> CampaignTrendView:
    return CampaignTrendView(
        generated_at=report.generated_at,
        selection_start_inclusive=report.selection_window.start,
        selection_end_exclusive=report.selection_window.end,
        truncated=report.truncated,
        points=tuple(
            CampaignTrendPointView(
                campaign_id=point.campaign_id,
                schedule_start=point.schedule_start,
                schedule_end=point.schedule_end,
                state=point.state,
                counts=_count_view(point.funnel),
                rates=_rate_view(point.funnel.rates),
            )
            for point in report.points
        ),
        portfolio=CampaignPortfolioView(
            counts=_count_view(report.portfolio),
            rates=_rate_view(report.portfolio.rates),
        ),
        semantics={
            "selection_window": "selects terminal campaigns by schedule_start; it does not filter event evidence",
            "snapshot": "all retained engagement evidence and current transport state at one generated_at cutoff",
            "portfolio": "sums campaign-assignment exposure numerators and denominators; never averages rates",
            "targeted": "campaign assignment exposures; not unique employees",
            "accepted": "provider acknowledged message handoff",
            "delivered": "destination MTA handoff; not inbox placement, display, or reading",
            "training_completed": "completed campaign training assignment exposures; not causal efficacy",
            "corrections": "scanner or bot corrections are not subtracted without normalized correction evidence",
        },
        privacy="aggregate campaign-assignment counts only; no titles, recipient identifiers, or recipient attributes",
    )


def _load_trend(
    session: Session,
    *,
    schedule_start: datetime,
    schedule_end: datetime,
    limit: int,
) -> CampaignTrendReport:
    try:
        window = CampaignSelectionWindow(schedule_start, schedule_end)
        return campaign_trend(
            session,
            scope=SINGLE_TENANT_DATABASE_SCOPE,
            schedule_window=window,
            limit=limit,
        )
    except ValueError as exc:
        message = _bounded_validation_message(
            exc,
            allowed=_CAMPAIGN_TREND_VALIDATION_MESSAGES,
            fallback="campaign trend request is invalid",
        )
        raise ValidationError_(message) from None


_LEDGER_COUNT_NAMES = (
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


def _ledger_count_view(projection: LedgerTrendBucket | LedgerTrendPortfolio) -> tuple[CountMetric, ...]:
    return tuple(CountMetric(name=name, value=int(getattr(projection, name))) for name in _LEDGER_COUNT_NAMES)


def _ledger_trend_view(report: LedgerTrendReport) -> LedgerTrendView:
    return LedgerTrendView(
        generated_at=report.generated_at,
        window_start_inclusive=report.window_start_inclusive,
        window_end_exclusive=report.window_end_exclusive,
        buckets=tuple(
            LedgerTrendBucketView(
                month=point.month,
                counts=_ledger_count_view(point),
                rates=_rate_view(point.rates),
            )
            for point in report.buckets
        ),
        portfolio=LedgerTrendPortfolioView(
            counts=_ledger_count_view(report.portfolio),
            rates=_rate_view(report.portfolio.rates),
        ),
        semantics={
            "window": "selects projected campaign_date; capped at the ledger's 1826-day retention",
            "unit": "assignment-exposure projections from the PII-free awareness ledger; not unique people",
            "clicked": "ledger exposure with an observed click",
            "no_click": "ledger exposure delivered but with no observed click",
            "confirmed_interaction": "deliberate human-interaction-confirmed exposure",
            "training_completed": "completed campaign training assignment exposures; not causal efficacy",
            "no_activity_at_close": "terminal campaign exposure with no retained activity",
            "portfolio": "sums ledger numerators and denominators; never averages rates",
            "corrections": "scanner or bot corrections are not subtracted without normalized correction evidence",
        },
        privacy="aggregate ledger projections only; no recipient identifiers, pseudonyms, or recipient attributes",
    )


def _load_ledger_trend(
    session: Session,
    *,
    window_start: date,
    window_end: date,
) -> LedgerTrendReport:
    try:
        # Validate at the API boundary as well as the query layer so a
        # failure is caught even when the query service is substituted.
        if window_start >= window_end:
            raise ValueError("ledger trend window start must precede end")
        if window_end - window_start > MAX_LEDGER_TREND_WINDOW:
            raise ValueError("ledger trend window cannot exceed 1826 days")
        return ledger_trend(
            session,
            scope=SINGLE_TENANT_DATABASE_SCOPE,
            window_start=window_start,
            window_end=window_end,
        )
    except ValueError as exc:
        message = _bounded_validation_message(
            exc,
            allowed=_LEDGER_TREND_VALIDATION_MESSAGES,
            fallback="ledger trend request is invalid",
        )
        raise ValidationError_(message) from None


def _ledger_repeat_bucket_view(bucket: LedgerRepeatBucket) -> LedgerRepeatBucketView:
    return LedgerRepeatBucketView(exposures=bucket.exposures, participants=bucket.participants)


def _ledger_repeats_view(report: LedgerRepeatDistribution) -> LedgerRepeatDistributionView:
    return LedgerRepeatDistributionView(
        generated_at=report.generated_at,
        window_start_inclusive=report.window_start_inclusive,
        window_end_exclusive=report.window_end_exclusive,
        exposure_buckets=tuple(_ledger_repeat_bucket_view(bucket) for bucket in report.exposure_buckets),
        engaged_buckets=tuple(_ledger_repeat_bucket_view(bucket) for bucket in report.engaged_buckets),
        summary=(
            CountMetric(name="unique_exposed", value=report.unique_exposed),
            CountMetric(name="exposures_total", value=report.exposures_total),
            CountMetric(name="unique_engaged", value=report.unique_engaged),
            CountMetric(name="engaged_exposures_total", value=report.engaged_exposures_total),
            CountMetric(name="no_activity_at_close", value=report.no_activity_at_close),
        ),
        rates=_rate_view(report.rates),
        semantics={
            "window": "selects projected campaign_date; capped at the ledger's 1826-day retention",
            "unit": "distinct tenant-keyed recipient pseudonyms from the PII-free awareness ledger; "
            "never person counts",
            "exposure_buckets": "distinct pseudonyms by exposures in the window; the top bucket means at "
            "least that many",
            "engaged_buckets": "distinct pseudonyms by exposures with retained human activity (open, "
            "click, report, confirmed interaction, training started or completed)",
            "repeat_exposure": "share of distinct exposed pseudonyms with two or more exposures",
            "repeat_engagement": "share of distinct engaged pseudonyms engaged in two or more campaigns",
            "corrections": "scanner or bot corrections are not subtracted without normalized correction evidence",
        },
        privacy=(
            "aggregate ledger projections only; no recipient identifiers, pseudonyms, or recipient attributes "
            "are returned"
        ),
    )


def _load_ledger_repeats(
    session: Session,
    *,
    window_start: date,
    window_end: date,
) -> LedgerRepeatDistribution:
    try:
        # Validate at the API boundary as well as the query layer so a
        # failure is caught even when the query service is substituted.
        if window_start >= window_end:
            raise ValueError("ledger repeat window start must precede end")
        if window_end - window_start > MAX_LEDGER_TREND_WINDOW:
            raise ValueError("ledger repeat window cannot exceed 1826 days")
        return ledger_repeat_distribution(
            session,
            scope=SINGLE_TENANT_DATABASE_SCOPE,
            window_start=window_start,
            window_end=window_end,
        )
    except ValueError as exc:
        message = _bounded_validation_message(
            exc,
            allowed=_LEDGER_REPEAT_VALIDATION_MESSAGES,
            fallback="ledger repeat request is invalid",
        )
        raise ValidationError_(message) from None


def _ledger_recipient_history_view(
    history: LedgerRecipientHistory,
) -> LedgerRecipientHistoryView:
    return LedgerRecipientHistoryView(
        generated_at=history.generated_at,
        truncated=history.truncated,
        summary=(
            CountMetric(name="exposures_total", value=history.exposures_total),
            CountMetric(name="delivered_total", value=history.delivered_total),
            CountMetric(name="engaged_total", value=history.engaged_total),
            CountMetric(name="no_activity_at_close_total", value=history.no_activity_at_close_total),
            CountMetric(name="repeat_exposures", value=history.repeat_exposures),
        ),
        entries=tuple(
            LedgerRecipientHistoryEntryView(
                campaign_id=entry.campaign_id,
                campaign_date=entry.campaign_date,
                campaign_date_basis=entry.campaign_date_basis,
                delivered=entry.delivered,
                observed_open=entry.observed_open,
                observed_click=entry.observed_click,
                confirmed_interaction=entry.confirmed_interaction,
                reported=entry.reported,
                training_started=entry.training_started,
                training_completed=entry.training_completed,
                no_activity_at_close=entry.no_activity_at_close,
            )
            for entry in history.entries
        ),
        semantics={
            "unit": "pseudonymous ledger facts for one named recipient; the recipient pseudonym is never returned",
            "exposures_total": "retained ledger exposures for this recipient within the 1,826-day ledger",
            "engaged_total": "exposures with retained human activity (open, click, report, confirmed "
            "interaction, training started or completed)",
            "repeat_exposures": "exposures beyond the first; the basis for repeat history",
            "delivered": "destination MTA handoff, never inbox placement or reading",
            "corrections": "scanner or bot corrections are not subtracted without normalized correction evidence",
        },
        privacy=(
            "named capability-protected ledger history; no recipient identifiers, mailboxes, display names, "
            "departments, or pseudonyms are returned"
        ),
    )


def _ledger_recipient_history_csv_rows(
    history: LedgerRecipientHistory,
) -> tuple[tuple[str | int, ...], ...]:
    """Formula-safe, PII-free CSV projection of one named ledger history.

    The recipient is identified by the request path, so the export carries no
    recipient identifier, mailbox, pseudonym, or recipient attribute.
    """

    header = (
        "scope",
        "generated_at",
        "truncated",
        "campaign_date",
        "campaign_date_basis",
        "campaign_id",
        "delivered",
        "observed_open",
        "observed_click",
        "confirmed_interaction",
        "reported",
        "training_started",
        "training_completed",
        "no_activity_at_close",
    )
    rows: list[tuple[str | int, ...]] = [header]
    prefix = (
        SINGLE_TENANT_DATABASE_SCOPE,
        history.generated_at.isoformat(),
        str(history.truncated).lower(),
    )
    for entry in history.entries:
        rows.append(
            (
                *prefix,
                entry.campaign_date.isoformat(),
                entry.campaign_date_basis,
                str(entry.campaign_id),
                int(entry.delivered),
                int(entry.observed_open),
                int(entry.observed_click),
                int(entry.confirmed_interaction),
                int(entry.reported),
                int(entry.training_started),
                int(entry.training_completed),
                "" if entry.no_activity_at_close is None else int(entry.no_activity_at_close),
            )
        )
    for name, value in (
        ("exposures_total", history.exposures_total),
        ("delivered_total", history.delivered_total),
        ("engaged_total", history.engaged_total),
        ("no_activity_at_close_total", history.no_activity_at_close_total),
        ("repeat_exposures", history.repeat_exposures),
    ):
        rows.append((*prefix, "summary", "", "", name, int(value), "", "", "", "", "", "", ""))
    return tuple(rows)


def _load_ledger_recipient_history(
    session: Session,
    settings: OperatorApiSettings,
    recipient_id: uuid.UUID,
) -> LedgerRecipientHistory:
    known = session.execute(select(Recipient.recipient_id).where(Recipient.recipient_id == recipient_id)).first()
    if known is None:
        raise NotFoundError("recipient does not exist")
    try:
        pseudonym_key, key_version = settings.require_awareness_pseudonym_config()
        return ledger_recipient_history(
            session,
            tenant_scope=SINGLE_TENANT_DATABASE_SCOPE,
            recipient_id=recipient_id,
            pseudonym_key=pseudonym_key,
            pseudonym_key_version=key_version,
        )
    except ValueError as exc:
        message = _bounded_validation_message(
            exc,
            allowed=_LEDGER_HISTORY_VALIDATION_MESSAGES,
            fallback="ledger recipient history request is invalid",
        )
        raise ValidationError_(message) from None


EvidenceStart = Annotated[datetime | None, Query(description="Inclusive RFC 3339 timestamp with timezone")]
EvidenceEnd = Annotated[datetime | None, Query(description="Exclusive RFC 3339 timestamp with timezone")]
ScheduleStart = Annotated[datetime, Query(description="Inclusive campaign schedule-start timestamp with timezone")]
ScheduleEnd = Annotated[datetime, Query(description="Exclusive campaign schedule-start timestamp with timezone")]
TrendLimit = Annotated[int, Query(ge=1, le=MAX_TREND_CAMPAIGNS)]


@router.get("/campaigns/trend", response_model=CampaignTrendView)
def get_campaign_trend(
    schedule_start: ScheduleStart,
    schedule_end: ScheduleEnd,
    limit: TrendLimit = MAX_TREND_CAMPAIGNS,
    session: Session = Depends(get_session),
    _principal: Principal = Depends(require_capability(Capability.VIEW_AGGREGATE)),
) -> CampaignTrendView:
    """Return a bounded, PII-free longitudinal campaign projection."""

    return _trend_view(
        _load_trend(
            session,
            schedule_start=schedule_start,
            schedule_end=schedule_end,
            limit=limit,
        )
    )


@router.get("/campaigns/trend.csv")
def export_campaign_trend(
    schedule_start: ScheduleStart,
    schedule_end: ScheduleEnd,
    limit: TrendLimit = MAX_TREND_CAMPAIGNS,
    session: Session = Depends(get_session),
    _principal: Principal = Depends(require_capability(Capability.EXPORT_BULK)),
) -> Response:
    """Export the same bounded longitudinal projection as formula-safe CSV."""

    report = _load_trend(
        session,
        schedule_start=schedule_start,
        schedule_end=schedule_end,
        limit=limit,
    )
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerows(campaign_trend_csv_rows(report))
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="campaign-trend-analytics.csv"'},
    )


LedgerWindowStart = Annotated[date, Query(description="Inclusive campaign-date (YYYY-MM-DD)")]
LedgerWindowEnd = Annotated[date, Query(description="Exclusive campaign-date (YYYY-MM-DD)")]


@router.get("/ledger/trend", response_model=LedgerTrendView)
def get_ledger_trend(
    window_start: LedgerWindowStart,
    window_end: LedgerWindowEnd,
    session: Session = Depends(get_session),
    _principal: Principal = Depends(require_capability(Capability.VIEW_AGGREGATE)),
) -> LedgerTrendView:
    """Return the bounded five-year click/no-click series from the ledger."""

    return _ledger_trend_view(
        _load_ledger_trend(
            session,
            window_start=window_start,
            window_end=window_end,
        )
    )


@router.get("/ledger/trend.csv")
def export_ledger_trend(
    window_start: LedgerWindowStart,
    window_end: LedgerWindowEnd,
    session: Session = Depends(get_session),
    _principal: Principal = Depends(require_capability(Capability.EXPORT_BULK)),
) -> Response:
    """Export the same bounded five-year ledger series as formula-safe CSV."""

    report = _load_ledger_trend(
        session,
        window_start=window_start,
        window_end=window_end,
    )
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerows(ledger_trend_csv_rows(report))
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="awareness-ledger-trend.csv"'},
    )


@router.get("/ledger/repeats", response_model=LedgerRepeatDistributionView)
def get_ledger_repeats(
    window_start: LedgerWindowStart,
    window_end: LedgerWindowEnd,
    session: Session = Depends(get_session),
    _principal: Principal = Depends(require_capability(Capability.VIEW_AGGREGATE)),
) -> LedgerRepeatDistributionView:
    """Return the bounded repeat-exposure distribution from the ledger."""

    return _ledger_repeats_view(
        _load_ledger_repeats(
            session,
            window_start=window_start,
            window_end=window_end,
        )
    )


@router.get("/ledger/repeats.csv")
def export_ledger_repeats(
    window_start: LedgerWindowStart,
    window_end: LedgerWindowEnd,
    session: Session = Depends(get_session),
    _principal: Principal = Depends(require_capability(Capability.EXPORT_BULK)),
) -> Response:
    """Export the same bounded repeat-exposure distribution as formula-safe CSV."""

    report = _load_ledger_repeats(
        session,
        window_start=window_start,
        window_end=window_end,
    )
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerows(ledger_repeat_csv_rows(report))
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="awareness-ledger-repeats.csv"'},
    )


@router.get("/ledger/recipients/{recipient_id}/history", response_model=LedgerRecipientHistoryView)
def get_ledger_recipient_history(
    recipient_id: uuid.UUID,
    session: Session = Depends(get_session),
    settings: OperatorApiSettings = Depends(get_settings),
    _principal: Principal = Depends(require_capability(Capability.VIEW_NAMED_RESULTS)),
) -> LedgerRecipientHistoryView:
    """Return the bounded pseudonymous ledger history for one named recipient.

    Named (capability-protected) drill-down into the PII-free ledger. The
    recipient id is resolved server-side with the governed pseudonym key; the
    response contains only ledger outcome facts, never recipient attributes or
    the pseudonym itself.
    """

    return _ledger_recipient_history_view(
        _load_ledger_recipient_history(
            session,
            settings=settings,
            recipient_id=recipient_id,
        )
    )


@router.get("/ledger/recipients/{recipient_id}/history.csv")
def export_ledger_recipient_history(
    recipient_id: uuid.UUID,
    session: Session = Depends(get_session),
    settings: OperatorApiSettings = Depends(get_settings),
    _principal: Principal = Depends(require_capability(Capability.EXPORT_BULK)),
) -> Response:
    """Export the same bounded named ledger history as formula-safe CSV."""

    history = _load_ledger_recipient_history(
        session,
        settings=settings,
        recipient_id=recipient_id,
    )
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerows(_ledger_recipient_history_csv_rows(history))
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="awareness-ledger-recipient-history.csv"'},
    )


@router.get("/campaigns/{campaign_id}/funnel", response_model=CampaignFunnelView)
def get_campaign_funnel(
    campaign_id: uuid.UUID,
    evidence_start: EvidenceStart = None,
    evidence_end: EvidenceEnd = None,
    session: Session = Depends(get_session),
    _principal: Principal = Depends(require_capability(Capability.VIEW_AGGREGATE)),
) -> CampaignFunnelView:
    """Return PII-free aggregate campaign analytics."""

    return _view(
        _load_report(
            session,
            campaign_id,
            evidence_start=evidence_start,
            evidence_end=evidence_end,
        )
    )


@router.get("/campaigns/{campaign_id}/funnel.csv")
def export_campaign_funnel(
    campaign_id: uuid.UUID,
    evidence_start: EvidenceStart = None,
    evidence_end: EvidenceEnd = None,
    session: Session = Depends(get_session),
    _principal: Principal = Depends(require_capability(Capability.EXPORT_BULK)),
) -> Response:
    """Export the same PII-free aggregate projection as formula-safe CSV."""

    report = _load_report(
        session,
        campaign_id,
        evidence_start=evidence_start,
        evidence_end=evidence_end,
    )
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerows(campaign_funnel_csv_rows(report))
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="campaign-{campaign_id}-analytics.csv"'},
    )
