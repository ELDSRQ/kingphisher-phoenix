from __future__ import annotations

from pathlib import Path

from kp_operator_api.routers import router

APP = (Path(__file__).resolve().parents[2] / "operator-ui" / "src" / "console-js" / "app.js").read_text(
    encoding="utf-8"
)
HELPER = APP[APP.index("const EXCLUSION_TYPE_LABELS") : APP.index("views.recipients = async (root) =>")]
VIEW = APP[APP.index("views.recipients = async (root) =>") : APP.index("/* ---------- privacy ---------- */")]


def _route_inventory() -> set[tuple[str, str]]:
    inventory: set[tuple[str, str]] = set()
    for route in router.routes:
        inventory.update((method, route.path) for method in route.methods or set())
    return inventory


def test_recipient_exclusion_routes_exist_with_exact_methods() -> None:
    routes = _route_inventory()
    expected = {
        ("GET", "/api/v1/recipients/{recipient_id}/exclusions"),
        ("POST", "/api/v1/recipients/{recipient_id}/exclusions"),
        (
            "POST",
            "/api/v1/recipients/{recipient_id}/exclusions/{exclusion_id}/revoke",
        ),
    }
    assert expected <= routes


def test_exclusion_history_and_controls_are_manage_exclusions_only() -> None:
    assert "if (!hasCapability(CAPABILITY.MANAGE_EXCLUSIONS)) return;" in HELPER
    assert "const canManageExclusions = hasCapability(CAPABILITY.MANAGE_EXCLUSIONS);" in VIEW
    assert 'canManageExclusions ? boundedCollection("/campaigns") : Promise.resolve([])' in VIEW
    assert '...(canManageExclusions ? [el("button", {' in VIEW
    assert 'text: "Manage exclusions"' in VIEW
    assert "await manageRecipientExclusions(r, campaigns, campaignsLoaded);" in VIEW
    assert "/exclusions?include_inactive=true&limit=50" in HELPER
    assert "/exclusions?include_inactive=true&limit=50" not in VIEW
    assert "canManageRecipients && canManageExclusions" not in VIEW


def test_exclusion_mutations_are_bounded_scoped_and_explicit() -> None:
    assert "const eligibleCampaigns = campaigns.slice(0, 100);" in HELPER
    assert HELPER.count("maxLength: 500") == 2
    assert 'values.exclusion_type === "campaign_specific"' in HELPER
    assert "campaignSpecific !== Boolean(values.campaign_id)" in HELPER
    assert 'localDateTimeToIso(values.expires_at, "Expiry")' in HELPER
    assert "Date.parse(expiresAt) <= Date.now()" in HELPER
    assert 'method: "POST"' in HELPER
    assert "JSON.stringify({ confirm: true, rationale })" in HELPER
    assert 'title: "Revoke this active exclusion?"' in HELPER
    assert 'confirmLabel: "Revoke exclusion"' in HELPER
    assert "danger: true" in HELPER
    assert 'exclusion.active ? [el("button"' in HELPER


def test_exclusion_lifecycle_has_fail_closed_and_honest_states() -> None:
    assert "Loading active and recent exclusion history" in HELPER
    assert "Exclusion history is unavailable. No exclusion controls are enabled." in HELPER
    assert 'if (!Array.isArray(history)) throw new Error("The server returned an invalid history response")' in HELPER
    assert "history = history.slice(0, 50);" in HELPER
    assert "No active or recent exclusions are recorded" in HELPER
    assert "selected-campaign creation is disabled" in HELPER
    assert "New exclusions require an active recipient record." in HELPER
    assert "An identical active exclusion already exists; no change was made." in HELPER
    assert "Exclusion was already revoked; no change was made." in HELPER
    assert "result.created" in HELPER
    assert "result.changed" in HELPER
    assert HELPER.count("await render();") == 2
    assert HELPER.count(".trim();") == 2


def test_exclusion_history_does_not_expand_recipient_identity() -> None:
    assert "recipient.mailbox" not in HELPER
    assert "recipient.employee_key" not in HELPER
    assert "exclusion.mailbox" not in HELPER
    assert "exclusion.employee_key" not in HELPER
    assert 'String(recipient.recipient_id || "").slice(0, 8)' in HELPER
    assert 'exclusion.reason || "Reason recorded"' in HELPER
    assert ".innerHTML" not in HELPER
