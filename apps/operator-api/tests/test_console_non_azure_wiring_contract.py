from __future__ import annotations

import re
from pathlib import Path

from kp_authorization.rbac import Capability
from kp_operator_api.analytics_routes import router as analytics_router
from kp_operator_api.console import router as console_router
from kp_operator_api.program_routes import router as program_router
from kp_operator_api.routers import router as api_router
from kp_operator_api.training_library import router as training_library_router

APP = (Path(__file__).resolve().parents[2] / "operator-ui" / "src" / "console" / "app.js").read_text()


def _view(start: str, end: str) -> str:
    return APP[APP.index(start) : APP.index(end)]


def _route_inventory() -> set[tuple[str, str]]:
    inventory: set[tuple[str, str]] = set()
    for router in (api_router, analytics_router, console_router, program_router, training_library_router):
        for route in router.routes:
            inventory.update((method, route.path) for method in route.methods or set())
    return inventory


def test_browser_capability_inventory_exactly_matches_backend() -> None:
    capability_block = APP[APP.index("const CAPABILITY") : APP.index("const KNOWN_CAPABILITIES")]
    browser = set(re.findall(r': "([a-z_]+:[a-z_]+)"', capability_block))
    backend = {
        f"{capability.action}:{capability.object}"
        for capability in vars(Capability).values()
        if isinstance(capability, Capability)
    }
    assert browser == backend


def test_non_azure_console_calls_have_matching_backend_methods() -> None:
    routes = _route_inventory()
    expected = {
        ("GET", "/api/v1/console/status"),
        ("GET", "/api/v1/campaigns"),
        ("GET", "/api/v1/campaigns/{campaign_id}/review"),
        ("PUT", "/api/v1/campaigns/{campaign_id}/training-resource"),
        ("POST", "/api/v1/audit/verify"),
        ("POST", "/api/v1/campaigns/{campaign_id}/training/reminders"),
        ("GET", "/api/v1/analytics/campaigns/{campaign_id}/funnel.csv"),
        ("GET", "/api/v1/audience-groups"),
        ("POST", "/api/v1/recipients/import"),
        ("POST", "/api/v1/recipients/directory/apply"),
        ("GET", "/api/v1/templates"),
        ("GET", "/api/v1/templates/pending"),
        ("POST", "/api/v1/templates/{template_version_id}/decision"),
        ("GET", "/api/v1/patterns"),
        ("POST", "/api/v1/patterns/{pattern_id}/clone"),
        ("POST", "/api/v1/patterns/{pattern_id}/approve"),
        ("POST", "/api/v1/sources/{source_id}/terms"),
        ("GET", "/api/v1/sources/{source_id}/terms/current"),
        ("POST", "/api/v1/sources/{source_id}/terms/revoke"),
        ("GET", "/api/v1/training-resources"),
        ("GET", "/api/v1/training-resources/{training_resource_id}/preview"),
        ("POST", "/api/v1/training-resources"),
        ("POST", "/api/v1/training-resources/{training_resource_id}/submit"),
        ("POST", "/api/v1/training-resources/{training_resource_id}/decision"),
    }
    assert expected <= routes


def test_every_literal_non_azure_api_path_exists_in_the_backend_inventory() -> None:
    backend_paths = {path.removeprefix("/api/v1") for _, path in _route_inventory()}
    browser_paths = {
        path
        for path in re.findall(r'\bapi\("(/[^"?]+)(?:\?[^"}]*)?"', APP)
        if not path.startswith("/console/azure-deployment")
    }
    assert browser_paths
    assert browser_paths <= backend_paths


def test_mixed_capability_views_do_not_call_forbidden_endpoints() -> None:
    dashboard = _view("/* ---------- dashboard ---------- */", "/* ---------- campaigns ---------- */")
    readiness = _view("async function campaignReadinessContext()", "function readinessForCampaign")
    assert 'canViewAggregate ? api("/console/status") : Promise.resolve(null)' in dashboard
    assert 'canViewAggregate ? boundedCollection("/campaigns") : Promise.resolve([])' in dashboard
    assert 'canViewAudit ? api("/audit/verify", { method: "POST" }) : Promise.resolve(null)' in dashboard
    assert 'hasCapability(CAPABILITY.MANAGE_ROLES) ? api("/console/onboarding")' in readiness
    assert 'hasCapability(CAPABILITY.USE_KILL_SWITCH) ? api("/kill-switch")' in readiness
    assert 'boundedCollection("/sending-domains", "domains")' in readiness
    assert 'boundedCollection("/roe", "roes")' in readiness


def test_help_navigation_and_view_use_defined_role_read_capability() -> None:
    navigation = _view("const NAV_CAPABILITIES", "function visibleNavigation()")
    help_view = _view("views.help = async (root) =>", "/* ---------- dashboard ---------- */")
    assert "help: [CAPABILITY.VIEW_AGGREGATE]" in navigation
    assert "help: [CAPABILITY.MANAGE_ROLES]" not in navigation
    assert "requireAnyCapability(root, CAPABILITY.VIEW_AGGREGATE)" in help_view
    assert "CAPABILITY.MANAGE_ROLES" not in help_view


def test_visible_actions_are_gated_by_their_backend_capabilities() -> None:
    analytics = _view("async function openCampaignAnalytics", "/* The CSV route is authenticated")
    campaigns = _view("views.campaigns = async (root) =>", "/* ---------- finite campaign programs ---------- */")
    templates = _view("views.templates = async (root) =>", "/* ---------- recipients ---------- */")
    recipients = _view("views.recipients = async (root) =>", "/* ---------- privacy ---------- */")
    patterns = _view("views.patterns = async (root) =>", "/* ---------- failed jobs")
    assert "if (hasCapability(CAPABILITY.SCHEDULE_CAMPAIGN)) actions.push(" in analytics
    assert "if (hasCapability(CAPABILITY.EXPORT_BULK)) actions.push(" in analytics
    assert 'canCreateCampaign\n      ? el("div", { class: "btn-row" }' in campaigns
    assert '...(canCreateCampaign ? [el("button", {' in campaigns
    assert '"aria-label": `Edit audience group ${group.name}`' in campaigns
    assert "const canApproveTemplate = hasCapability(CAPABILITY.APPROVE_TEMPLATE);" in templates
    assert "const canPreviewTemplate = canCreateCampaign || canApproveTemplate;" in templates
    assert "if (canCreateCampaign) {" in templates
    assert 'text: "Clone as draft"' in templates
    assert "if (!canApproveTemplate)" in templates
    assert '...(canPreviewTemplate ? [el("button", {' in templates
    assert 'text: "Preview desktop, mobile & plain"' in templates
    assert 'text: "Approve", onclick: decide(draft, "approved")' in templates
    assert 'text: "Reject", onclick: decide(draft, "rejected")' in templates
    assert (
        '...(canCreateCampaign ? [el("button", {\n        class: "btn small", type: "button", text: "Preview desktop'
        not in templates
    )
    assert "if (canManageRecipients) {\n    const csvArea" in recipients
    assert 'api("/recipients/import/preview"' in recipients
    assert 'api("/recipients/import/apply"' in recipients
    assert "const actionAuthorityValid = hasBooleanActionFlags(pattern, PATTERN_ACTION_FLAGS);" in patterns
    assert "if (pattern.can_clone === true)" in patterns
    assert "if (pattern.can_approve === true)" in patterns


def test_directory_and_session_actions_do_not_leave_stale_or_secret_browser_state() -> None:
    recipients = _view("views.recipients = async (root) =>", "/* ---------- privacy ---------- */")
    shell = _view("function shell()", "/* ---------- shared UI helpers ---------- */")
    assert "window.confirm" not in APP
    assert "window.prompt" not in APP
    assert 'confirmLabel: "Apply reviewed preview"' in recipients
    assert recipients.count("await render();") >= 4
    assert "clearToken();" in shell
    assert "serverLogoutConfirmed" in shell
    assert "localStorage" not in APP
    assert "document.cookie" not in APP
    assert "indexedDB" not in APP


def test_runtime_status_failures_do_not_enable_unverified_lifecycle_controls() -> None:
    onboarding = _view("views.onboarding = async (root) =>", 'views["azure-deployment"]')
    settings = _view("views.settings = async (root) =>", "/* ---------- boot ---------- */")
    assert "Setup changes are disabled until status is available." in onboarding
    assert "Preserve local setup when status is unavailable" not in onboarding
    assert "processRestart: false" in settings
    assert "processStop" not in settings
    assert "Restart controls are hidden until the server confirms" in settings


def test_oidc_aggregate_export_uses_cookie_credentials_without_empty_bearer() -> None:
    export = _view("async function downloadAnalyticsCsv", "function showImportResult")
    helper = _view("async function downloadApiCsv", "/* ---------- state ---------- */")
    assert "await downloadApiCsv(" in export
    assert 'const headers = { Accept: "text/csv" };' in helper
    assert "if (token()) headers.Authorization" in helper
    assert 'credentials: "same-origin"' in helper
    assert "Authorization: `Bearer ${token()}`" not in helper
