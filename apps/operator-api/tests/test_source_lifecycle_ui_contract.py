from __future__ import annotations

from pathlib import Path

from fastapi.routing import APIRoute
from kp_operator_api.routers import router

APP = (Path(__file__).resolve().parents[2] / "operator-ui" / "src" / "console-js" / "app.js").read_text(
    encoding="utf-8"
)
SOURCE_VIEW = APP[APP.index("/* ---------- sources ---------- */") : APP.index("/* ---------- patterns ---------- */")]


def test_source_lifecycle_routes_match_gui_actions() -> None:
    routes = {
        (method, route.path)
        for route in router.routes
        if isinstance(route, APIRoute)
        for method in route.methods or set()
    }
    assert {
        ("GET", "/api/v1/sources"),
        ("POST", "/api/v1/sources"),
        ("POST", "/api/v1/sources/{source_id}/enable"),
        ("POST", "/api/v1/sources/{source_id}/disable"),
        ("POST", "/api/v1/sources/{source_id}/ingest"),
        ("POST", "/api/v1/sources/{source_id}/terms"),
        ("GET", "/api/v1/sources/{source_id}/terms/current"),
        ("POST", "/api/v1/sources/{source_id}/terms/revoke"),
    }.issubset(routes)
    assert "api(`/sources/${encodeURIComponent(source.source_id)}/${action}`" in SOURCE_VIEW
    assert "api(`/sources/${encodeURIComponent(source.source_id)}/terms/current`)" in SOURCE_VIEW
    assert "api(`/sources/${encodeURIComponent(source.source_id)}/terms`, {" in SOURCE_VIEW
    assert 'api(`/sources/${encodeURIComponent(source.source_id)}/terms/revoke`, { method: "POST" })' in SOURCE_VIEW
    assert 'method: "POST"' in SOURCE_VIEW


def test_source_creation_never_sends_the_legacy_license_pointer() -> None:
    create_request = SOURCE_VIEW[
        SOURCE_VIEW.index('await api("/sources", { method: "POST"') : SOURCE_VIEW.index(
            'toast("Source created.',
        )
    ]
    assert "license_state_id" not in create_request
    for field in ("name", "source_type", "base_domain", "fetch_path"):
        assert field in create_request


def test_sources_truthfully_show_supported_types_and_operational_state() -> None:
    assert "supported RSS, STIX, and bulk-download source adapters" in SOURCE_VIEW
    assert 'rss: "RSS feed"' in SOURCE_VIEW
    assert 'stix: "STIX feed"' in SOURCE_VIEW
    assert 'bulk_download: "Bulk download"' in SOURCE_VIEW
    for field in (
        "source.source_type",
        "source.last_attempt_at",
        "source.last_success_at",
        "source.consecutive_failures",
    ):
        assert field in SOURCE_VIEW
    assert '"Consecutive failures", "Failure breaker", "Terms governance", "Actions"' in SOURCE_VIEW
    assert "Disabled with unresolved failures; the disabling cause is not recorded" in SOURCE_VIEW


def test_source_terms_state_and_bounded_metadata_are_visible() -> None:
    assert "governance.governance_ready === true" in SOURCE_VIEW
    assert "acknowledgement?.enabled === true" in SOURCE_VIEW
    for label in ("Current", "Missing", "Expired", "Revoked", "Incomplete", "Unavailable"):
        assert f'"{label}"' in SOURCE_VIEW
    for field in ("terms_reference", "terms_hash", "reviewed_at", "next_review_at"):
        assert f"acknowledgement.{field}" in SOURCE_VIEW
    assert "boundedMetadata(acknowledgement.terms_reference, 2048)" in SOURCE_VIEW
    assert "boundedMetadata(acknowledgement.terms_hash, 64)" in SOURCE_VIEW
    assert "Terms state unavailable. Enable and Ingest remain disabled." in SOURCE_VIEW


def test_source_actions_are_capability_gated_busy_and_state_aware() -> None:
    assert "requireAnyCapability(root, CAPABILITY.MANAGE_SOURCES)" in SOURCE_VIEW
    assert "const canManageSources = hasCapability(CAPABILITY.MANAGE_SOURCES);" in SOURCE_VIEW
    assert "if (busy || !canManageSources || (needsCurrentTerms && !governanceReady)) return;" in SOURCE_VIEW
    assert "(needsCurrentTerms && !governanceReady)" in SOURCE_VIEW
    assert "button.dataset.requiresCurrentTerms = String(needsCurrentTerms);" in SOURCE_VIEW
    assert (
        'title: needsCurrentTerms && !governanceReady ? "Record a current terms acknowledgement first" : null'
        in SOURCE_VIEW
    )
    assert 'makeAction("enable", "Enable", true)' in SOURCE_VIEW
    assert 'makeAction("disable", "Disable")' in SOURCE_VIEW
    assert 'makeAction("ingest", "Ingest now", true)' in SOURCE_VIEW
    assert "if (err.status === 409)" in SOURCE_VIEW
    assert "if (err.status === 403)" in SOURCE_VIEW
    assert "no job was queued" in SOURCE_VIEW
    assert "No change was made" in SOURCE_VIEW


def test_terms_acknowledgement_requires_four_unchecked_explicit_confirmations() -> None:
    assert 'type: "checkbox", name' in SOURCE_VIEW
    for field in ("commercial_use_ok", "automation_ok", "redistribution_ok", "retention_ok"):
        assert f'["{field}"' in SOURCE_VIEW
        assert f"{field}:" in SOURCE_VIEW
    assert "confirmations.some(([, input]) => !input.checked)" in SOURCE_VIEW
    assert "Explicitly confirm all four source-use permissions." in SOURCE_VIEW
    assert 'pattern: "[0-9A-Fa-f]{64}"' in SOURCE_VIEW
    assert "/^[0-9a-f]{64}$/.test(normalizedHash)" in SOURCE_VIEW
    assert 'maxlength: "2048"' in SOURCE_VIEW
    assert 'type: "datetime-local"' in SOURCE_VIEW
    assert "reviewDate.getTime() <= Date.now()" in SOURCE_VIEW
    assert "next_review_at: reviewDate.toISOString()" in SOURCE_VIEW
    checkbox_creation = SOURCE_VIEW[
        SOURCE_VIEW.index('type: "checkbox", name') - 100 : SOURCE_VIEW.index('type: "checkbox", name') + 100
    ]
    assert "checked" not in checkbox_creation


def test_terms_revoke_is_explicitly_confirmed_and_controls_refresh() -> None:
    assert "const confirmed = await confirmDialog({" in SOURCE_VIEW
    assert 'confirmLabel: "Revoke terms and disable source"' in SOURCE_VIEW
    assert "danger: true" in SOURCE_VIEW
    assert 'text: "Refresh terms"' in SOURCE_VIEW
    assert "onclick: refreshSourceView" in SOURCE_VIEW
    assert SOURCE_VIEW.count("await refreshSourceView();") >= 4


def test_disable_and_job_reference_wording_do_not_overclaim() -> None:
    assert "Disable is not cancellation" in SOURCE_VIEW
    assert "prevents new and not-yet-started ingestion" in SOURCE_VIEW
    assert "does not cancel a fetch already in progress" in SOURCE_VIEW
    assert "an in-progress fetch is not cancelled" in SOURCE_VIEW
    assert "Request reference: ${result.job_id}" in SOURCE_VIEW
    assert SOURCE_VIEW.count("This reference is not a status link") == 2
    assert "/jobs/${result.job_id}" not in SOURCE_VIEW


def test_source_refresh_and_accessibility_preserve_session_authority() -> None:
    assert "const refreshSourceView = async () =>" in SOURCE_VIEW
    assert "root.replaceChildren();" in SOURCE_VIEW
    assert "await views.sources(root);" in SOURCE_VIEW
    assert SOURCE_VIEW.count("await refreshSourceView();") >= 4
    assert "location.reload" not in SOURCE_VIEW
    assert '"aria-label": "Configured source ingestion lifecycle"' in SOURCE_VIEW
    assert '"aria-label": `${label} for source ${source.name}`' in SOURCE_VIEW
    assert 'collectionLoadError("Sources could not be loaded. Refresh and retry.", () => render())' in SOURCE_VIEW
    assert 'role: "status", colspan: 10, text: "No configured sources."' in SOURCE_VIEW
    assert "${e.message}" not in SOURCE_VIEW
    assert "err.message" not in SOURCE_VIEW
    assert "localStorage" not in SOURCE_VIEW
    assert ".innerHTML" not in SOURCE_VIEW
