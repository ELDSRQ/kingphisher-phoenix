from __future__ import annotations

from pathlib import Path

APP = (Path(__file__).resolve().parents[2] / "operator-ui" / "src" / "console" / "app.js").read_text(encoding="utf-8")


def _view(start: str, end: str) -> str:
    return APP[APP.index(start) : APP.index(end)]


def test_session_authority_is_stored_from_server_responses_and_validated_fail_closed() -> None:
    assert APP.count("roles: data.roles") == 2
    assert APP.count("capabilities: data.capabilities") == 2
    assert "function hasValidSessionAuthority" in APP
    assert "KNOWN_ROLES.has(role)" in APP
    assert "KNOWN_CAPABILITIES.has(capability)" in APP
    assert "if ((token() || sessionInfo()) && !hasValidSessionAuthority())" in APP
    assert "clearToken();" in APP
    assert "oidcSessionChecked = false;" in APP
    assert "return hasValidSessionAuthority(info) && info.capabilities.includes(capability);" in APP
    assert "if (hasCapability(CAPABILITY.MANAGE_ROLES))" in APP


def test_login_does_not_fall_back_to_local_password_when_auth_mode_is_unknown() -> None:
    login = _view("/* ---------- login ---------- */", "/* ---------- shell ---------- */")
    assert "let authMode;" in login
    assert 'if (!resp.ok) throw new Error("Authentication mode is unavailable")' in login
    assert 'if (!new Set(["dev", "oidc"]).has(authMode))' in login
    assert "No password was submitted." in login
    assert "Managed Azure uses Microsoft identity sign-in and disables password login." in login
    assert 'let authMode = "dev"' not in login
    assert "console-password secret in Key Vault" not in login


def test_navigation_is_filtered_by_server_derived_capabilities() -> None:
    expected = {
        "programs: [CAPABILITY.VIEW_AGGREGATE]",
        "trends: [CAPABILITY.VIEW_AGGREGATE]",
        "sending: [CAPABILITY.VERIFY_DOMAIN, CAPABILITY.SIGN_ROE]",
        ("recipients: [CAPABILITY.VIEW_NAMED_RESULTS, CAPABILITY.MANAGE_RECIPIENTS, CAPABILITY.MANAGE_EXCLUSIONS]"),
        "sources: [CAPABILITY.MANAGE_SOURCES]",
        "privacy: [CAPABILITY.HANDLE_PRIVACY]",
        "queues: [CAPABILITY.MANAGE_QUEUE]",
        "audit: [CAPABILITY.VIEW_AUDIT]",
        "settings: [CAPABILITY.MANAGE_ROLES]",
    }
    assert all(entry in APP for entry in expected)
    assert "function visibleNavigation()" in APP
    assert "function canNavigateTo(viewId)" in APP
    assert "for (const [id, label] of visible)" in APP
    assert "hasAnyCapability(...required)" in APP


def test_program_and_trend_controls_are_capability_aware() -> None:
    program = _view(
        "/* ---------- finite campaign programs ---------- */",
        "/* ---------- sending domains & rules of engagement ----------",
    )
    trend = _view(
        "/* ---------- executive campaign trends ---------- */",
        "/* ---------- template review ----------",
    )
    assert "requireAnyCapability(root, CAPABILITY.VIEW_AGGREGATE)" in program
    assert "const canCreateProgram = hasCapability(CAPABILITY.CREATE_CAMPAIGN);" in program
    assert "const canChangeProgramState = hasCapability(CAPABILITY.SCHEDULE_CAMPAIGN);" in program
    assert 'disabled: canCreateProgram ? null : "disabled"' in program
    assert "if (!program.complete && canChangeProgramState)" in program
    assert "requireAnyCapability(root, CAPABILITY.VIEW_AGGREGATE)" in trend
    assert "const canExportTrend = hasCapability(CAPABILITY.EXPORT_BULK);" in trend
    assert 'disabled: canExportTrend ? null : "disabled"' in trend


def test_combined_views_do_not_fetch_or_offer_the_other_capability() -> None:
    sending = _view(
        "/* ---------- sending domains & rules of engagement ----------",
        "/* ---------- executive campaign trends ---------- */",
    )
    recipients = _view("views.recipients = async (root) =>", "/* ---------- privacy ---------- */")
    audit = _view("/* ---------- audit ---------- */", "/* ---------- settings ---------- */")
    assert 'boundedCollection("/sending-domains", "domains")' in sending
    assert 'boundedCollection("/roe", "roes")' in sending
    assert 'canManageRecipients ? api("/integrations/microsoft365/status") : Promise.resolve(null)' in recipients
    assert "requireAnyCapability(root, CAPABILITY.VIEW_NAMED_RESULTS, CAPABILITY.MANAGE_RECIPIENTS)" in recipients
    assert 'canManageRecipients ? [el("button"' in recipients
    assert 'canUseKillSwitch ? api("/kill-switch") : Promise.resolve(null)' in audit
    assert 'canUseKillSwitch ? el("button"' in audit


def test_capability_identifiers_are_non_secret_stable_rbac_names() -> None:
    for capability in (
        "create:campaign",
        "schedule:campaign",
        "view_aggregate:results",
        "export_bulk:results",
        "manage:source",
        "manage:recipients",
        "view_named:results",
        "view:audit",
        "manage:job_queue",
        "handle:privacy_requests",
        "verify:sending_domain",
        "sign:rules_of_engagement",
        "manage:roles",
    ):
        assert f'"{capability}"' in APP
    assert "access_token" not in APP
    assert "id_token" not in APP
