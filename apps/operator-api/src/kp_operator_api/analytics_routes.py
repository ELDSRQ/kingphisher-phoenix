"""Privacy-minimized campaign analytics endpoints.

These routes are intentionally separate from the legacy campaign report
surface.  They expose the small, denominator-explicit reporting projection
from :mod:`kp_database.reporting` without recipient attributes.
"""

from __future__ import annotations

import csv
import io
import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Response
from kp_authorization.rbac import Capability, Principal
from kp_database.reporting import (
    MAX_TREND_CAMPAIGNS,
    SINGLE_TENANT_DATABASE_SCOPE,
    CampaignFunnel,
    CampaignPortfolio,
    CampaignReportNotFound,
    CampaignSelectionWindow,
    CampaignTrendReport,
    EvidenceWindow,
    Rate,
    campaign_funnel,
    campaign_funnel_csv_rows,
    campaign_trend,
    campaign_trend_csv_rows,
)
from kp_domain_models import models as dm
from kp_telemetry.errors import NotFoundError, ValidationError_
from pydantic import BaseModel
from sqlalchemy.orm import Session

from kp_operator_api.auth import require_capability
from kp_operator_api.deps import get_session

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
