"""W4-02 (KP-AUD-003/005/014): UI / CSV / evidence-ZIP must agree.

One event set is computed once by ``campaign_funnel``; the UI view builder, the
CSV builder and the evidence-ZIP document builder all derive from that single
result, so they cannot report different numbers. These tests prove the shared
acceptance points against the real reporting query layer:

* the same numbers across all three surfaces;
* a scanner/automation click never inflates the human click metric;
* the unknown (indeterminate) count is visible on every surface;
* each export records the registered metric/export version and digest.
"""

from __future__ import annotations

import csv
import io

import pytest
from _analytics_fixtures import CAMPAIGN_ID, NOW, make_session, seed
from kp_database.reporting import (
    EXPORT_SCHEMA_VERSION,
    METRIC_DEFINITIONS_VERSION,
    SINGLE_TENANT_DATABASE_SCOPE,
    campaign_funnel,
    campaign_funnel_csv_rows,
    campaign_metric_document,
    metric_definitions_digest,
)
from kp_operator_api.analytics_routes import _view
from sqlalchemy.orm import Session


@pytest.fixture
def session() -> Session:
    database_session = make_session()
    seed(database_session)
    try:
        yield database_session
    finally:
        database_session.close()


def _funnel(session: Session):  # noqa: ANN202
    return campaign_funnel(session, CAMPAIGN_ID, scope=SINGLE_TENANT_DATABASE_SCOPE, generated_at=NOW)


def _csv_cells(report) -> dict[str, str]:  # noqa: ANN001
    rows = campaign_funnel_csv_rows(report)
    return {str(name): str(value) for name, value in rows}


def test_ui_csv_and_zip_report_identical_numbers_for_one_event_set(session: Session) -> None:
    report = _funnel(session)
    ui = _view(report)
    document = campaign_metric_document(report)
    cells = _csv_cells(report)

    ui_counts = {metric.name: metric.value for group in (ui.transport, ui.engagement, ui.training) for metric in group}
    # A single-campaign funnel has no cohort suppression; it reports that
    # honestly rather than as a vacuous zero count.
    assert ui.cohort_suppression == "not_applicable"
    assert document["cohort_suppression"] == "not_applicable"

    for name, value in document["counts"].items():  # type: ignore[union-attr]
        assert ui_counts[name] == value, name
        assert cells[f"count.{name}"] == str(value), name

    ui_rates = {metric.name: (metric.numerator, metric.denominator, metric.value) for metric in ui.rates}
    for rate in document["rates"]:  # type: ignore[union-attr]
        name = rate["name"]
        assert ui_rates[name] == (rate["numerator"], rate["denominator"], rate["value"])
        assert cells[f"rate.{name}.numerator"] == str(rate["numerator"])
        assert cells[f"rate.{name}.denominator"] == str(rate["denominator"])


def test_automation_suspected_click_does_not_inflate_human_metrics(session: Session) -> None:
    report = _funnel(session)

    # One genuine click and one scanner click were seeded; only the genuine one
    # counts as a human click, and the scanner click is surfaced separately.
    assert report.clicked == 1
    assert report.clicked_automation_suspected == 1
    document = campaign_metric_document(report)
    assert document["counts"]["clicked"] == 1  # type: ignore[index]
    assert document["counts"]["clicked_automation_suspected"] == 1  # type: ignore[index]
    clicked_rate = next(rate for rate in document["rates"] if rate["name"] == "clicked")  # type: ignore[union-attr]
    # Human click rate is 1/3 accepted, not 2/3 — the scanner never inflates it.
    assert clicked_rate["numerator"] == 1 and clicked_rate["denominator"] == 3


def test_reply_confidence_is_separate_from_provider_acceptance(session: Session) -> None:
    report = _funnel(session)
    # Acceptance counts three accepted handoffs; the correlated reply (human
    # CONFIDENCE) is one and is never merged into acceptance.
    assert report.accepted == 3
    assert report.reply_correlated == 1
    rates = dict(report.rates)
    assert rates["reply_correlated"].denominator_name == "provider_accepted_handoffs"


def test_unknowns_are_visible_on_every_surface(session: Session) -> None:
    report = _funnel(session)
    ui = _view(report)
    cells = _csv_cells(report)
    document = campaign_metric_document(report)

    assert any(metric.name == "indeterminate" and metric.value == 1 for metric in ui.transport)
    assert cells["count.indeterminate"] == "1"
    assert document["counts"]["indeterminate"] == 1  # type: ignore[index]


def test_every_surface_records_the_registered_schema_version_and_digest(session: Session) -> None:
    report = _funnel(session)
    ui = _view(report)
    cells = _csv_cells(report)
    document = campaign_metric_document(report)

    assert ui.definitions.metric_definitions_version == METRIC_DEFINITIONS_VERSION
    assert ui.definitions.export_schema_version == EXPORT_SCHEMA_VERSION
    assert ui.definitions.metric_definitions_digest == metric_definitions_digest()

    assert cells["metric_definitions_version"] == METRIC_DEFINITIONS_VERSION
    assert cells["export_schema_version"] == EXPORT_SCHEMA_VERSION
    assert cells["metric_definitions_digest"] == metric_definitions_digest()

    assert document["metric_definitions_version"] == METRIC_DEFINITIONS_VERSION
    assert document["export_schema_version"] == EXPORT_SCHEMA_VERSION
    assert document["metric_definitions_digest"] == metric_definitions_digest()


def test_csv_is_formula_safe(session: Session) -> None:
    report = _funnel(session)
    output = io.StringIO(newline="")
    csv.writer(output, lineterminator="\n").writerows(campaign_funnel_csv_rows(report))
    projection = output.getvalue()
    cells = [cell.strip() for row in csv.reader(io.StringIO(projection)) for cell in row if cell.strip()]
    assert not any(cell.startswith(("=", "+", "-", "@")) for cell in cells)


def test_legacy_report_click_count_equals_the_analytics_click_count(session: Session) -> None:
    """The legacy report must not contradict the analytics funnel.

    ``_campaign_report`` classifies clicks in memory from the same predicate the
    funnel uses, so for one 1-human + 1-scanner event set both surfaces report
    the same human click count (1) and neither credits the scanner click.
    """

    from datetime import timedelta
    from types import SimpleNamespace
    from uuid import uuid4

    from kp_domain_models import models as dm
    from kp_operator_api.routes.campaigns import _campaign_report

    # The funnel computed over the real seeded DB: one human click, one scanner.
    funnel = _funnel(session)
    assert funnel.clicked == 1 and funnel.clicked_automation_suspected == 1

    human_id, scanner_id = uuid4(), uuid4()
    human_token, scanner_token = uuid4(), uuid4()
    assignments = [
        SimpleNamespace(
            recipient_assignment_id=human_id,
            send_state=dm.SendState.DELIVERED,
            failure_reason=None,
            provider_accepted_at=NOW - timedelta(hours=4),
            token_id=human_token,
        ),
        SimpleNamespace(
            recipient_assignment_id=scanner_id,
            send_state=dm.SendState.ACCEPTED,
            failure_reason=None,
            provider_accepted_at=NOW - timedelta(hours=4),
            token_id=scanner_token,
        ),
    ]
    events = [
        SimpleNamespace(
            event_type=dm.EventType.CLICKED,
            confidence=dm.Confidence.MEDIUM,
            payload={},
            recipient_assignment_id=human_id,
            token_id=human_token,
        ),
        SimpleNamespace(
            event_type=dm.EventType.CLICKED,
            confidence=dm.Confidence.MEDIUM,
            payload={"automation_suspected": True},
            recipient_assignment_id=scanner_id,
            token_id=scanner_token,
        ),
    ]

    class _FakeReportSession:
        def __init__(self) -> None:
            self._scalars = [assignments, events, [], []]  # assignments, events, training, correlations

        def scalars(self, _statement: object) -> list[object]:
            return self._scalars.pop(0)

        def scalar(self, _statement: object) -> object | None:
            return None

    campaign = SimpleNamespace(
        campaign_id=CAMPAIGN_ID,
        title="t",
        state=dm.CampaignState.COMPLETED,
        schedule_start=None,
        schedule_end=None,
        sender_mailbox="x@y.z",
        sender_display_name="n",
    )
    report = _campaign_report(_FakeReportSession(), campaign)  # type: ignore[arg-type]

    # Single export, no contradiction: the legacy clicked equals the analytics
    # clicked, and the scanner click is surfaced separately, not as a human.
    assert report["event_counts"]["clicked"] == funnel.clicked == 1
    assert report["clicked_automation_suspected"] == funnel.clicked_automation_suspected == 1
