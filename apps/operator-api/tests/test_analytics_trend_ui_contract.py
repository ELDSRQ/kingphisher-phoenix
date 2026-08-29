from __future__ import annotations

from pathlib import Path

APP = (Path(__file__).resolve().parents[2] / "operator-ui" / "src" / "console" / "app.js").read_text(encoding="utf-8")
TREND_VIEW = APP[
    APP.index("/* ---------- executive campaign trends ---------- */") : APP.index(
        "/* ---------- template review ----------"
    )
]


def test_executive_trend_is_a_bounded_gui_route() -> None:
    assert '["trends", "Executive trends"]' in APP
    assert "views.trends = async (root) =>" in TREND_VIEW
    assert "365 * 24 * 60 * 60 * 1000" in TREND_VIEW
    assert 'limit: "12"' in TREND_VIEW
    assert "Trend window cannot exceed 366 days" in TREND_VIEW
    assert "api(`/analytics/campaigns/trend?${query.toString()}`)" in TREND_VIEW


def test_executive_trend_exposes_denominator_correct_aggregate_evidence() -> None:
    assert "campaign-assignment exposures" in TREND_VIEW
    assert "Weighted event count" in TREND_VIEW
    assert "rate.numerator" in TREND_VIEW
    assert "rate.denominator" in TREND_VIEW
    assert "rate.denominator === 0 || rate.value === null" in TREND_VIEW
    assert '"N/A"' in TREND_VIEW
    assert "they do not average campaign percentages" in TREND_VIEW
    assert "Destination MTA handoff is not inbox delivery, placement, display or reading" in TREND_VIEW
    assert "Current snapshots are not causal evidence" in TREND_VIEW
    assert "Normalizations and scanner or bot corrections are not silently applied" in TREND_VIEW


def test_executive_trend_csv_uses_authenticated_blob_download() -> None:
    assert "/analytics/campaigns/trend.csv?${query.toString()}" in TREND_VIEW
    assert "await downloadApiCsv(" in TREND_VIEW
    assert '"campaign-trend-analytics.csv"' in TREND_VIEW


def test_executive_trend_renders_only_aggregate_safe_fields() -> None:
    assert "point.campaign_id" in TREND_VIEW
    assert "point.schedule_start" in TREND_VIEW
    assert "point.state" in TREND_VIEW
    assert "point.title" not in TREND_VIEW
    assert "point.mailbox" not in TREND_VIEW
    assert "point.recipient" not in TREND_VIEW
    assert "point.group" not in TREND_VIEW
    assert ".innerHTML" not in TREND_VIEW
    assert '"aria-label": "Weighted portfolio rates"' in TREND_VIEW


def test_five_year_ledger_trend_is_a_bounded_pseudonym_free_gui_route() -> None:
    assert "Five-year awareness ledger trend" in TREND_VIEW
    assert "1,826 days" in TREND_VIEW
    assert "1826 * 24 * 60 * 60 * 1000" in TREND_VIEW
    assert "Ledger trend window cannot exceed 1,826 days." in TREND_VIEW
    assert "api(`/analytics/ledger/trend?${query.toString()}`)" in TREND_VIEW
    assert "/analytics/ledger/trend.csv?${query.toString()}" in TREND_VIEW
    assert '"awareness-ledger-trend.csv"' in TREND_VIEW


def test_five_year_ledger_trend_exposes_only_projected_buckets() -> None:
    assert "bucket.month" in TREND_VIEW
    assert 'counts.get("targeted")' in TREND_VIEW
    assert 'counts.get("delivered")' in TREND_VIEW
    assert 'rates.get("clicked")' in TREND_VIEW
    assert 'rates.get("no_click")' in TREND_VIEW
    assert "pseudonymous assignment-exposure projections" in TREND_VIEW
    assert "explicit no-click bucket" in TREND_VIEW
    assert "bucket.recipient" not in TREND_VIEW
    assert "bucket.pseudonym" not in TREND_VIEW
    assert "bucket.campaign_id" not in TREND_VIEW
    assert "bucket.mailbox" not in TREND_VIEW
    assert '"aria-label": "Five-year pseudonymous awareness ledger trend"' in TREND_VIEW
    assert '"aria-label": "Campaign exposure trend points"' in TREND_VIEW


def test_repeat_exposure_history_is_a_bounded_pseudonym_free_gui_route() -> None:
    assert "Repeat exposure history" in TREND_VIEW
    assert "Repeat history window cannot exceed 1,826 days." in TREND_VIEW
    assert "api(`/analytics/ledger/repeats?${query.toString()}`)" in TREND_VIEW
    assert "/analytics/ledger/repeats.csv?${query.toString()}" in TREND_VIEW
    assert '"awareness-ledger-repeats.csv"' in TREND_VIEW
    assert "Download repeat CSV" in TREND_VIEW


def test_repeat_exposure_history_renders_only_aggregate_bucket_fields() -> None:
    assert "report.exposure_buckets" in TREND_VIEW
    assert "report.engaged_buckets" in TREND_VIEW
    assert "bucket.exposures === 5" in TREND_VIEW
    assert "bucket.participants" in TREND_VIEW
    assert 'summary.get("unique_exposed")' in TREND_VIEW
    assert 'rates.get("repeat_exposure")' in TREND_VIEW
    assert "never resolved to identities" in TREND_VIEW
    assert "bucket.pseudonym" not in TREND_VIEW
    assert "bucket.recipient" not in TREND_VIEW
    assert "bucket.campaign_id" not in TREND_VIEW
    assert "bucket.mailbox" not in TREND_VIEW
    assert '"aria-label": "Repeat exposure history"' in TREND_VIEW
