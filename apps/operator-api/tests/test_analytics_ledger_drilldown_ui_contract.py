from __future__ import annotations

from pathlib import Path

APP = (Path(__file__).resolve().parents[2] / "operator-ui" / "src" / "console-js" / "app.js").read_text(
    encoding="utf-8"
)
# The drill-down section is authored inside views.trends, between the repeat
# exposure history section and the template review helper.
TREND_VIEW = APP[
    APP.index("/* ---------- executive campaign trends ---------- */") : APP.index(
        "/* ---------- template review ----------"
    )
]


def test_per_recipient_drill_down_is_capability_gated() -> None:
    assert "Per-recipient ledger history" in TREND_VIEW
    # The endpoint requires view_named:results, so the whole drill-down must be
    # behind the named-results capability gate (stronger than the view's
    # aggregate gate).
    assert "hasCapability(CAPABILITY.VIEW_NAMED_RESULTS)" in APP


def test_per_recipient_drill_down_fetches_bounded_server_route() -> None:
    assert "api(`/analytics/ledger/recipients/${encodeURIComponent(drillDownRecipientId)}/history`)" in TREND_VIEW
    assert "encodeURIComponent(drillDownRecipientId)" in TREND_VIEW
    assert "boundedRecipientPage(payload, 500)" in TREND_VIEW
    assert "/recipients?limit=500&offset=0" in TREND_VIEW
    assert "aria-live" in TREND_VIEW


def test_per_recipient_drill_down_csv_path_is_allowed_by_download_guard() -> None:
    # The downloadApiCsv guard used to require /analytics/campaigns/ only, which
    # silently rejected the ledger trend/repeats and (new) recipient-history CSV
    # downloads. All real analytics exports share the /analytics/ prefix.
    assert '!path.startsWith("/analytics/")' in APP
    assert '"/analytics/campaigns/"' not in APP
    assert "await downloadApiCsv(" in TREND_VIEW
    assert "/analytics/ledger/recipients/${encodeURIComponent(drillDownRecipientId)}/history.csv" in TREND_VIEW
    assert '"awareness-ledger-recipient-history.csv"' in TREND_VIEW


def test_per_recipient_drill_down_never_renders_identity_or_pseudonym() -> None:
    # Only ledger outcome facts may be rendered; never recipient attributes,
    # the pseudonym key, or the full recipient id.
    assert "recipient.recipient_id.slice(0, 8)" in TREND_VIEW
    assert "entry.campaign_date" in TREND_VIEW
    assert "entry.observed_open" in TREND_VIEW
    assert "entry.observed_click" in TREND_VIEW
    assert ".innerHTML" not in TREND_VIEW
    # Only ledger outcome facts are rendered; never recipient-identifying fields.
    assert "entry.mailbox" not in TREND_VIEW
    assert "entry.recipient" not in TREND_VIEW
    assert "entry.pseudonym" not in TREND_VIEW
    assert "history.pseudonym" not in TREND_VIEW
    assert "The drill-down never reveals identities or pseudonyms" in TREND_VIEW
    assert '"aria-label": "Per-recipient pseudonymous ledger history"' in TREND_VIEW
