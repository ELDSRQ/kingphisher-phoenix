from __future__ import annotations

from pathlib import Path

APP = (Path(__file__).resolve().parents[1] / "apps" / "operator-ui" / "src" / "console" / "app.js").read_text()


def test_campaign_console_builds_one_truthful_readiness_gate() -> None:
    for endpoint in (
        'api("/console/status")',
        'api("/console/onboarding")',
        'api("/integrations/microsoft365/status")',
        'api("/kill-switch")',
        'boundedCollection("/sending-domains", "domains")',
        'boundedCollection("/roe", "roes")',
    ):
        assert endpoint in APP

    for key in ("audience", "lesson", "approvals", "roe", "mailer", "training", "reporting", "kill", "canary"):
        assert f'key: "{key}"' in APP

    assert "check.required && check.ready === false" in APP
    assert '"data-readiness-blockers"' in APP
    assert 'text: "Review & run canary"' in APP
    assert 'text: "Publish full audience"' in APP
    assert 'disabled: blockers.length ? "disabled" : null' in APP
    assert "The scheduling API will revalidate it and fail closed" in APP


def test_campaign_console_only_offers_approved_creation_inputs() -> None:
    assert 'patterns.filter((pattern) => pattern.approval_state === "approved")' in APP
    assert 'templates.filter((template) => template.approval_state === "approved")' in APP
    assert 'boundedCollection("/training-resources?approval_state=approved")' in APP
    assert "training_resource_id: trainingResourceId" in APP
    assert "Campaign creation is disabled until at least one pattern and one template are approved" in APP
    assert "disabled: canCreateCampaign && approvedPatterns.length && approvedTemplates.length" in APP
    assert '"Approve a pattern and a template first."' in APP
    assert '"Campaign creation capability is required."' in APP


def test_campaign_review_surfaces_and_rebinds_the_exact_training_lesson() -> None:
    assert "campaign.training_lesson?.ready === true" in APP
    assert "bound_content_digest" in APP
    assert "Recipient lesson content" in APP
    assert "Review campaign" in APP
    assert "training-resource`, {" in APP
    assert "Changing a reviewed campaign resets it to draft" in APP


def test_canary_and_publish_confirmations_name_authoritative_server_gates() -> None:
    for phrase in (
        "test accounts locked into the reviewed manifest",
        "full audience remains blocked until successful provider evidence",
        "reviewed, server-marked test cohort",
        "reviewed manifest, approvals, RoE",
        "emergency stop",
        "provider configuration and unexpired canary evidence",
        "queueing non-canary recipients",
        "Queue locked canary",
        "Publish exact audience",
    ):
        assert phrase in APP
    assert '"Reported mail"' in APP


def test_canary_is_server_designated_and_has_no_ad_hoc_send_bypass() -> None:
    assert "api(`/campaigns/${campaign.campaign_id}/test-send`" not in APP
    assert "api(`/campaigns/${campaign.campaign_id}/schedule`" in APP
    assert "api(`/campaigns/${campaign.campaign_id}/publish`" in APP
    assert "only the test accounts locked into the reviewed manifest" in APP
    assert "Only the reviewed, server-marked test cohort is queued in this phase" in APP


def test_template_preview_is_safe_accessible_and_device_explicit() -> None:
    assert 'api("/templates/preview"' in APP
    assert '[["desktop", "Desktop"], ["mobile", "Mobile"], ["plain", "Plain text"]]' in APP
    assert 'role: "group", "aria-label": "Preview format"' in APP
    assert '"aria-pressed": "false"' in APP
    assert "plain-text body" in APP
    assert "deliberately not executed in the operator console" in APP
    assert ".innerHTML" not in APP
    assert ".srcdoc" not in APP


def test_campaign_drafts_survive_automatic_refresh_and_navigation_requires_confirmation() -> None:
    assert 'guardUnsavedForm(form, "New campaign draft")' in APP
    assert "if (currentUnsavedForm()) {" in APP
    assert "Unsaved changes — automatic refresh paused" in APP
    assert 'title: "Discard unsaved changes?"' in APP
    assert 'window.addEventListener("beforeunload"' in APP
    assert "if (currentView() === viewId) return" in APP
    assert "onclick: () => navigateTo(id)" in APP


def test_campaign_prerequisites_offer_gui_next_actions() -> None:
    assert 'text: "Before you create a campaign"' in APP
    for destination in ("patterns", "templates", "training"):
        assert f'"{destination}"' in APP
    for action in ("Open patterns", "Open template review", "Open training lessons"):
        assert action in APP
    assert 'text: "Creation stays locked until the reviewed content below is available.' in APP


def test_campaign_actions_and_readiness_are_named_per_campaign() -> None:
    assert "`${campaignTitle}: ${blockers.length} readiness blocker" in APP
    assert '"aria-label": `Actions for ${c.title}`' in APP
    for phrase in (
        "Review and run locked canary for",
        "Publish exact full audience for",
        "Review campaign ${c.title}",
        "Open aggregate report for",
    ):
        assert phrase in APP


def test_audience_preview_explains_every_freeze_blocker() -> None:
    assert '"aria-label": "Masked exact audience preview"' in APP
    assert '"aria-describedby": "audience-preview-guidance"' in APP
    assert "const freezeBlockers = [" in APP
    assert "at least one eligible recipient is required" in APP
    assert "the result exceeds this campaign's recipient limit" in APP
    assert "a signed Rules of Engagement must cover this campaign window" in APP
