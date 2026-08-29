from __future__ import annotations

from pathlib import Path

APP = (Path(__file__).resolve().parents[2] / "operator-ui" / "src" / "console" / "app.js").read_text(encoding="utf-8")
CAMPAIGNS = APP[
    APP.index("views.campaigns = async (root) =>") : APP.index("/* ---------- finite campaign programs ---------- */")
]
PATTERNS = APP[
    APP.index("views.patterns = async (root) =>") : APP.index(
        "/* ---------- failed jobs / dead-letter queue ---------- */"
    )
]


def test_campaign_mutations_require_a_complete_boolean_authority_envelope() -> None:
    for flag in (
        "can_configure_audience",
        "can_submit",
        "can_approve_security",
        "can_approve_privacy",
        "can_schedule",
        "can_publish",
        "can_test_send",
        "can_recall",
    ):
        assert f'"{flag}"' in APP[APP.index("const CAMPAIGN_ACTION_FLAGS") : APP.index("const PATTERN_ACTION_FLAGS")]

    for flag in (
        "can_configure_audience",
        "can_submit",
        "can_approve_security",
        "can_approve_privacy",
        "can_schedule",
        "can_publish",
        "can_recall",
    ):
        assert f"c.{flag} === true" in CAMPAIGNS

    assert 'requiredFlags.every((flag) => typeof resource[flag] === "boolean")' in APP
    assert "const actionAuthorityValid = hasBooleanActionFlags(c, CAMPAIGN_ACTION_FLAGS);" in CAMPAIGNS
    assert "if (!actionAuthorityValid)" in CAMPAIGNS
    assert 'actionAuthorityUnavailable("Campaign"' in CAMPAIGNS
    assert "Mutable actions are hidden" in APP
    assert 'type: "button", text: "Refresh actions"' in APP


def test_campaign_buttons_do_not_reconstruct_identity_or_lifecycle_authority() -> None:
    action_block = CAMPAIGNS[
        CAMPAIGNS.index("const actionAuthorityValid") : CAMPAIGNS.index("function act(path, successMsg)")
    ]
    for obsolete_gate in (
        "canScheduleCampaign",
        "hasCapability(CAPABILITY.APPROVE_SECURITY)",
        "hasCapability(CAPABILITY.APPROVE_PRIVACY)",
        "hasCapability(CAPABILITY.SEND_CAMPAIGN)",
        "hasCapability(CAPABILITY.STOP_CAMPAIGN)",
    ):
        assert obsolete_gate not in action_block

    assert 'c.state === "pending_approval"' not in action_block
    assert '["scheduled", "approved"].includes(c.state)' not in action_block
    assert 'text: "Approve security"' in action_block
    assert 'text: "Approve privacy"' in action_block
    assert 'text: "Recall"' in action_block
    assert 'text: "Publish full audience"' in action_block
    assert 'text: "Send to test accounts"' not in action_block


def test_readiness_remains_an_additional_canary_and_full_publish_blocker() -> None:
    assert "const blockers = readiness.filter((check) => check.required && check.ready === false);" in CAMPAIGNS
    assert CAMPAIGNS.count('disabled: blockers.length ? "disabled" : null') >= 2
    assert "if (c.can_schedule === true)" in CAMPAIGNS
    assert "if (c.can_publish === true)" in CAMPAIGNS


def test_pattern_list_and_preview_actions_fail_closed_on_server_flags() -> None:
    assert 'const PATTERN_ACTION_FLAGS = Object.freeze(["can_clone", "can_approve"]);' in APP
    assert "const actionAuthorityValid = hasBooleanActionFlags(pattern, PATTERN_ACTION_FLAGS);" in PATTERNS
    assert "const previewActionAuthorityValid = hasBooleanActionFlags(detail, PATTERN_ACTION_FLAGS);" in PATTERNS
    assert 'actionAuthorityUnavailable("Pattern"' in PATTERNS
    assert 'actionAuthorityUnavailable("Pattern preview"' in PATTERNS
    assert "if (pattern.can_clone === true)" in PATTERNS
    assert "if (pattern.can_approve === true)" in PATTERNS
    assert "const canCreateCampaign" not in PATTERNS
    assert "const canApprovePattern" not in PATTERNS
    assert 'if (!Array.isArray(patterns)) throw new Error("The server returned an invalid pattern list")' in PATTERNS


def test_stale_authority_responses_refresh_before_actions_are_offered_again() -> None:
    assert "const STALE_ACTION_STATUSES = new Set([403, 409]);" in APP
    assert "async function refreshAfterStaleActionFailure" in APP
    assert "await refreshAction();" in APP
    assert CAMPAIGNS.count("refreshAfterStaleActionFailure(err, render)") >= 4
    assert PATTERNS.count("refreshAfterStaleActionFailure(err, load)") >= 2


def test_preserved_campaign_controls_stay_on_their_separate_authority_paths() -> None:
    assert "separate server controls and are intentionally not campaign flags" in CAMPAIGNS
    assert "hasCapability(CAPABILITY.USE_KILL_SWITCH)" in CAMPAIGNS
    assert "if (canSubscribeAlerts) actions.push" in CAMPAIGNS
    assert 'type: "button", text: "Kill switch"' in CAMPAIGNS
    assert 'type: "button", text: "Report"' in CAMPAIGNS
    assert 'type: "button", text: alertsLoaded ? "Manage alerts"' in CAMPAIGNS
