from __future__ import annotations

import re
from pathlib import Path

APP = (Path(__file__).resolve().parents[2] / "operator-ui" / "src" / "console-js" / "app.js").read_text(
    encoding="utf-8"
)


def _section(start: str, end: str) -> str:
    return APP[APP.index(start) : APP.index(end)]


CAMPAIGNS = _section("views.campaigns = async (root) =>", "/* ---------- finite campaign programs ---------- */")
RECIPIENTS = _section("views.recipients = async (root) =>", "/* ---------- privacy ---------- */")
PRIVACY = _section("views.privacy = async (root) =>", "/* ---------- sources ---------- */")
SOURCES = _section("views.sources = async (root) =>", "/* ---------- patterns ---------- */")
TEMPLATES = _section("views.templates = async (root) =>", "/* ---------- training resource library ---------- */")
SETTINGS = _section("views.settings = async (root) =>", "/* ---------- boot ---------- */")
ONBOARDING = _section("views.onboarding = async (root) =>", 'views["azure-deployment"]')


def test_authenticated_console_responses_are_never_browser_cached() -> None:
    assert 'fetch(`${API}${path}`, { ...options, cache: "no-store", headers })' in APP
    assert 'fetch(`${API}${path}`, { headers, credentials: "same-origin", cache: "no-store" })' in APP
    assert 'fetch(`${API}/console/session`, { credentials: "same-origin", cache: "no-store" })' in APP


def test_every_visible_navigation_item_has_a_view_and_hidden_readiness_links_are_not_rendered() -> None:
    nav = _section("const NAV = [", "const NAV_CAPABILITIES")
    view_ids = re.findall(r'^  \["([a-z-]+)",', nav, flags=re.MULTILINE)
    assert view_ids
    for view_id in view_ids:
        assert f"views.{view_id} =" in APP or f'views["{view_id}"] =' in APP

    readiness = _section("function campaignReadinessView", "views.campaigns = async (root) =>")
    assert "canNavigateTo(check.destination)" in readiness
    assert "An operator with access to that configuration must complete this check." in readiness
    assert "function canNavigateTo(viewId)" in APP
    assert "if (!NAV.some(([id]) => id === viewId)) return false;" in APP


def test_partial_or_truncated_campaign_dependencies_never_clear_saved_audience_selectors() -> None:
    assert "if (!Array.isArray(campaigns))" in CAMPAIGNS
    assert "const patternsLoaded =" in CAMPAIGNS
    assert "const templatesLoaded =" in CAMPAIGNS
    assert "const groupsLoaded =" in CAMPAIGNS
    assert "const alertsLoaded =" in CAMPAIGNS
    assert "patterns: invalid response" in CAMPAIGNS
    assert "audience groups: invalid response" in CAMPAIGNS
    assert "const namedRecipientSelectionComplete =" in CAMPAIGNS
    assert "recipientPage.truncated === false" in CAMPAIGNS
    assert "memberSelect.disabled = !namedRecipientSelectionComplete;" in CAMPAIGNS
    assert "Existing members will be preserved" in CAMPAIGNS
    assert "Array.isArray(existing?.recipient_ids) ? existing.recipient_ids : []" in CAMPAIGNS
    assert "groupSelect.disabled = !groupsLoaded;" in CAMPAIGNS
    assert "includeSelect.disabled = !namedRecipientSelectionComplete;" in CAMPAIGNS
    assert "excludeSelect.disabled = !namedRecipientSelectionComplete;" in CAMPAIGNS
    assert "group_ids: groupsLoaded ? selectedValues(groupSelect) : (current.group_ids || [])" in CAMPAIGNS
    assert "(current.include_recipient_ids || [])" in CAMPAIGNS
    assert "(current.exclude_recipient_ids || [])" in CAMPAIGNS
    assert "never replaces missing or truncated dependency data with an empty selection" in CAMPAIGNS


def test_new_campaign_does_not_ship_local_or_example_delivery_defaults() -> None:
    assert 'value: "security-drills@example.com"' not in CAMPAIGNS
    assert 'id: "c-tdomain", value: "127.0.0.1"' not in CAMPAIGNS
    assert "security-awareness@your-verified-domain.example" in CAMPAIGNS
    assert "training.your-domain.example" in CAMPAIGNS
    assert "Title, sender mailbox, and training domain are required" in CAMPAIGNS
    assert "sender_mailbox: senderMailbox" in CAMPAIGNS
    assert "training_domain: trainingDomain" in CAMPAIGNS


def test_template_requester_does_not_receive_known_dead_review_controls() -> None:
    assert "const principalId = sessionInfo()?.principalId;" in TEMPLATES
    assert "const canReviewDraft = !draft.requested_by" in TEMPLATES
    assert "draft.requested_by !== principalId" in TEMPLATES
    assert "...(canReviewDraft ? [" in TEMPLATES
    assert "A different authorized reviewer must record its decision." in TEMPLATES


def test_mutations_use_their_exact_capabilities() -> None:
    assert "const canDeleteData = hasCapability(CAPABILITY.DELETE_DATA);" in PRIVACY
    assert 'if (canDeleteData && ["verified", "in_progress"].includes(r.status)' in PRIVACY
    assert '["search", "access_export", "correction", "deletion"].includes(r.request_type)' in PRIVACY
    assert "const canSubmitSource = hasCapability(CAPABILITY.SUBMIT_SOURCE);" in SOURCES
    assert 'disabled: canSubmitSource ? null : "disabled"' in SOURCES
    assert "if (!canSubmitSource) return;" in SOURCES
    assert "Source-submission capability is required." in SOURCES


def test_source_terms_hash_can_be_calculated_entirely_in_the_gui() -> None:
    assert "Calculate from reviewed terms file (optional)" in SOURCES
    assert "file.size > 5 * 1024 * 1024" in SOURCES
    assert 'globalThis.crypto.subtle.digest("SHA-256", await file.arrayBuffer())' in SOURCES
    assert "new Uint8Array(digest)" in SOURCES
    assert "The file is never uploaded." in SOURCES
    assert "enter the reviewed hash manually" in SOURCES


def test_privacy_fulfillment_is_complete_and_deletion_is_high_friction() -> None:
    assert "async function fulfillRequest(request, button)" in PRIVACY
    assert "const typedConfirmation = `DELETE ${requestReference}`;" in PRIVACY
    assert "Erase matched recipient data" in PRIVACY
    assert "danger = true;" in PRIVACY
    assert 'for (const field of ["employee_key", "mailbox", "display_name", "department"])' in PRIVACY
    assert 'values[field] === "CLEAR"' in PRIVACY
    assert "Enter at least one supported correction." in PRIVACY
    assert "Download the export first." in PRIVACY
    assert "verified search request" in PRIVACY
    assert "Exception completion requires documented legal review" in PRIVACY
    assert 'method: "POST", body: JSON.stringify(body)' in PRIVACY
    assert 'api(`/privacy/requests/${r.privacy_request_id}/export`, { method: "POST" })' in PRIVACY
    assert "Request completed. Matched ${result.matched}" in PRIVACY
    assert "const PRIVACY_STATES" not in APP
    assert "configCache" not in APP


def test_privacy_requests_remain_usable_when_notice_loading_fails() -> None:
    request_load = 'requests = await boundedCollection("/privacy/requests")'
    notice_load = 'notice = await api("/privacy/notice")'
    assert request_load in PRIVACY
    assert notice_load in PRIVACY
    assert PRIVACY.index(request_load) < PRIVACY.index(notice_load)
    assert "Privacy requests remain available, but the current notice could not be loaded" in PRIVACY
    assert 'Promise.all([api("/privacy/notice")' not in PRIVACY


def test_microsoft_365_actions_fail_closed_on_missing_or_malformed_status() -> None:
    assert "const integrationLoaded = !canManageRecipients || Boolean(" in RECIPIENTS
    assert "the server returned an invalid status response" in RECIPIENTS
    assert 'return "Unavailable · status could not be verified";' in RECIPIENTS
    assert "integration?.directory_preview_available !== true" in RECIPIENTS
    assert "directory.apply_available !== true || !previewReference" in RECIPIENTS
    assert "directory.discard_available !== true || !previewReference" in RECIPIENTS
    assert "integration?.mailbox_poll_available !== true" in RECIPIENTS
    assert "preview_id: previewReference" in RECIPIENTS
    assert "preview_id: directory.preview_id" not in RECIPIENTS


def test_download_controls_attach_links_and_always_revoke_object_urls() -> None:
    azure = _section('views["azure-deployment"] = async (root) =>', "/* ---------- help ---------- */")
    for section in (azure, PRIVACY):
        assert "document.body.appendChild(link);" in section
        assert "link.remove();" in section
        assert "URL.revokeObjectURL(url)" in section


def test_gui_does_not_offer_a_full_stack_stop_that_requires_shell_recovery() -> None:
    assert 'api("/console/stop"' not in SETTINGS
    assert 'text: "Stop services"' not in SETTINGS
    assert "Full-stack shutdown is intentionally not offered here" in SETTINGS
    assert "Use the audited global emergency stop in Audit" in SETTINGS
    assert 'api("/kill-switch"' in APP


def test_onboarding_provider_fields_fail_closed_and_do_not_submit_inactive_or_secret_ai_values() -> None:
    assert "const providerInput = step.provider_key ? inputs[step.provider_key] : null;" in ONBOARDING
    assert "const providers = Array.isArray(field.providers) ? field.providers : [];" in ONBOARDING
    assert "fieldRows[field.key].hidden = !active;" in ONBOARDING
    assert "input.disabled = !active;" in ONBOARDING
    assert '!input.disabled && input.value !== ""' in ONBOARDING
    assert "if (!input || input.disabled) return false;" in ONBOARDING
    assert "!field.secret && !inputs[field.key]?.disabled" in ONBOARDING
    assert "inputs[key].disabled" in ONBOARDING


def test_onboarding_distinguishes_verified_from_reachability_only_before_save() -> None:
    assert 'outcome === "reachable_unverified" ? "warning" : "error"' in ONBOARDING
    assert "testResult.save_allowed !== true" in ONBOARDING
    assert 'testResult?.outcome === "reachable_unverified" ? "validated and saved" : "tested and saved"' in ONBOARDING
    assert 'outcome === "verified" ? "success"' in ONBOARDING
