from __future__ import annotations

from pathlib import Path

APP = (Path(__file__).resolve().parents[2] / "operator-ui" / "src" / "console" / "app.js").read_text(encoding="utf-8")
DOWNLOAD_HELPER = APP[APP.index("const MAX_CSV_DOWNLOAD_BYTES") : APP.index("/* ---------- state ----------")]
CAMPAIGN_ANALYTICS = APP[APP.index("async function openCampaignAnalytics") : APP.index("/* Reviewed import outcomes")]
CAMPAIGN_VIEW = APP[APP.index("views.campaigns = async (root) =>") : APP.index("/* ---------- recipients ----------")]
NAMED_RESULTS = CAMPAIGN_ANALYTICS[
    CAMPAIGN_ANALYTICS.index("if (canViewNamedResults && namedResults !== null)") : CAMPAIGN_ANALYTICS.index(
        "  const actions = [];"
    )
]


def test_campaign_report_combines_aggregate_surfaces_without_named_access() -> None:
    assert "api(`/analytics/campaigns/${campaign.campaign_id}/funnel${query}`)" in CAMPAIGN_ANALYTICS
    assert "api(`/campaigns/${campaign.campaign_id}/report`)" in CAMPAIGN_ANALYTICS
    assert "Operational delivery report" in CAMPAIGN_ANALYTICS
    assert "Aggregate operational campaign report" in CAMPAIGN_ANALYTICS
    assert "operational.reported_mail_pipeline.mailbox_status" in CAMPAIGN_ANALYTICS

    assert "const canViewNamedResults = hasCapability(CAPABILITY.VIEW_NAMED_RESULTS)" in CAMPAIGN_ANALYTICS
    assert "canViewNamedResults" in CAMPAIGN_ANALYTICS
    assert "`/campaigns/${campaign.campaign_id}/recipients?limit=500&offset=0`" in CAMPAIGN_ANALYTICS
    assert ".then((payload) => boundedRecipientPage(payload, 500))" in CAMPAIGN_ANALYTICS
    assert "const visibleResults = namedResults.items;" in NAMED_RESULTS
    assert "namedResults.truncated" in NAMED_RESULTS
    assert "namedResults.total" in NAMED_RESULTS
    assert "namedResults.slice" not in NAMED_RESULTS
    assert "Capability-protected recipient outcomes" in NAMED_RESULTS
    assert "result.recipient_id" in NAMED_RESULTS
    assert "result.department" in NAMED_RESULTS
    assert "result.recipient_id" not in CAMPAIGN_ANALYTICS[: CAMPAIGN_ANALYTICS.index(NAMED_RESULTS)]


def test_bulk_exports_are_capability_gated_and_use_one_bounded_same_origin_helper() -> None:
    assert "if (hasCapability(CAPABILITY.EXPORT_BULK))" in CAMPAIGN_ANALYTICS
    assert "/analytics/campaigns/${campaignId}/funnel.csv${query}" in CAMPAIGN_ANALYTICS
    assert "const MAX_CSV_DOWNLOAD_BYTES = 5 * 1024 * 1024" in DOWNLOAD_HELPER
    assert 'contentType !== "text/csv"' in DOWNLOAD_HELPER
    assert 'response.headers.get("content-length")' in DOWNLOAD_HELPER
    assert "received > MAX_CSV_DOWNLOAD_BYTES" in DOWNLOAD_HELPER
    assert "await reader.cancel()" in DOWNLOAD_HELPER
    assert 'credentials: "same-origin"' in DOWNLOAD_HELPER
    assert "if (token()) headers.Authorization = `Bearer ${token()}`" in DOWNLOAD_HELPER
    assert "Export failed (${response.status})" in DOWNLOAD_HELPER
    assert "response.json()" not in DOWNLOAD_HELPER
    assert "response.text()" not in DOWNLOAD_HELPER
    assert "/^[A-Za-z0-9][A-Za-z0-9._-]{0,126}\\.csv$/" in DOWNLOAD_HELPER
    assert "URL.revokeObjectURL(url)" in DOWNLOAD_HELPER


def test_alert_subscription_lifecycle_is_capability_gated_and_owner_safe() -> None:
    assert "const canSubscribeAlerts = hasCapability(CAPABILITY.SUBSCRIBE_ALERTS)" in CAMPAIGN_VIEW
    assert 'canSubscribeAlerts ? boundedCollection("/alerts/subscriptions") : Promise.resolve([])' in CAMPAIGN_VIEW
    assert "subscription.campaign_id === campaign.campaign_id" in CAMPAIGN_VIEW
    assert "Only subscriptions owned by your signed-in account are shown" in CAMPAIGN_VIEW
    assert 'subscription.destination_configured ? "Configured" : "In-app"' in CAMPAIGN_VIEW
    assert "api(`/alerts/subscriptions/${encodeURIComponent(subscription.alert_subscription_id)}`" in CAMPAIGN_VIEW
    assert 'method: "DELETE"' in CAMPAIGN_VIEW
    assert "Disable this alert subscription?" in CAMPAIGN_VIEW
    assert 'api("/alerts/subscriptions", { method: "POST"' in CAMPAIGN_VIEW
    assert "await render()" in CAMPAIGN_VIEW
    assert "if (canSubscribeAlerts) actions.push" in CAMPAIGN_VIEW
    assert 'text: alertsLoaded ? "Manage alerts" : "Alerts unavailable"' in CAMPAIGN_VIEW


def test_alert_failures_do_not_present_an_empty_success_state() -> None:
    assert 'const alertsLoaded = dependencyResults[5].status === "fulfilled"' in CAMPAIGN_VIEW
    assert '"alert subscriptions"' in CAMPAIGN_VIEW
    assert "No successful fallback is assumed" in CAMPAIGN_VIEW
    assert 'disabled: alertsLoaded ? null : "disabled"' in CAMPAIGN_VIEW
