"""UX-011 console wiring contract.

Source-level assertions on the authored console module (read, like the other UI
contract tests, from console-js/app.js). These lock the presence and shape of
the UX-011 wiring; the visual/interaction correctness is validated by the
operator in a real browser, which these string checks deliberately do not
attempt to replace.
"""

from __future__ import annotations

from pathlib import Path

APP = (Path(__file__).resolve().parents[2] / "operator-ui" / "src" / "console-js" / "app.js").read_text(
    encoding="utf-8"
)


def test_arc002_hides_azure_deployment_when_connector_disabled() -> None:
    # Consumes the server's deploy_connector_enabled hint from /console/auth-mode
    # and hides the nav item — presentation only; the routes stay server-gated.
    assert "deploy_connector_enabled !== false" in APP
    assert 'viewId === "azure-deployment" && !deployConnectorEnabled' in APP
    assert "await ensureDeployConnectorState()" in APP


def test_emergency_stop_is_surfaced_in_the_sidebar_for_kill_switch_holders() -> None:
    assert "function sidebarEmergencyStop()" in APP
    assert "if (!hasCapability(CAPABILITY.USE_KILL_SWITCH)) return null;" in APP
    assert "sidebarEmergencyStop()," in APP  # placed in the shell footer
    # Same audited endpoint, capability, and confirm+reason flow as before.
    assert '"/kill-switch/reset" : "/kill-switch"' in APP
    assert "JSON.stringify({ confirm: true, reason: values.reason })" in APP


def test_needs_my_decision_queue_is_consumed_from_the_new_endpoint() -> None:
    assert 'api("/campaigns/needs-my-decision")' in APP
    assert "Needs my decision (" in APP
    assert "row.can_approve_security" in APP
    assert "row.can_approve_privacy" in APP
    assert 'class: "nav-badge"' in APP  # sidebar badge


def test_campaign_report_and_evidence_exports_are_wired() -> None:
    assert "async function downloadCampaignExport(" in APP
    assert "/campaigns/${campaign.campaign_id}/report.csv" in APP
    assert "/campaigns/${campaign.campaign_id}/evidence.zip" in APP
    assert '"application/zip"' in APP
    # Allow-list is exactly the two campaign export shapes; nothing else.
    assert "const CAMPAIGN_EXPORT_PATH = /^\\/campaigns\\/[0-9a-fA-F-]{36}\\/(?:report\\.csv|evidence\\.zip)$/" in APP


def test_recipient_labels_are_masked_not_raw_uuids() -> None:
    assert "function recipientReference(recipient)" in APP
    assert "recipient.display_name && recipient.masked_mailbox" in APP
    # The masked mailbox is only ever the server-provided masked form.
    assert "recipient.masked_mailbox" in APP
    # The pseudonymous ledger drill-down is explicitly NOT masked-labelled: it
    # keeps the truncated reference (privacy contract).
    assert "recipient.recipient_id.slice(0, 8)" in APP


def test_html_preview_never_executes_html_in_the_console() -> None:
    # UX-011 §2a originally rendered the sanitized HTML in a sandboxed srcdoc
    # iframe, but that conflicts with the console's standing safety invariant
    # (see test_operator_ui_campaign_readiness): template HTML is deliberately
    # NOT executed in the operator console. The preview shows only the approved
    # plain-text body; the HTML alternative is disclosed but never rendered.
    assert ".srcdoc" not in APP
    assert ".innerHTML" not in APP
    assert "extractPreviewLinks" not in APP
    assert "deliberately not executed in the operator console" in APP


def test_clone_and_resign_roe_start_fresh() -> None:
    assert "function cloneCampaignIntoForm(campaign)" in APP
    assert "Approvals and Rules of Engagement do not carry over." in APP
    assert "Clone as new draft" in APP
    # Re-sign opens the sign dialog prefilled; it is always a brand-new signature.
    assert "async function signRoe(prefill = {})" in APP
    assert "Re-sign for a new window" in APP


def test_proof_send_button_is_flag_gated_and_offers_no_destination_input() -> None:
    # UX-011 §2b. The button exists, it is gated on the server's own
    # can_proof_send flag, and it posts a body that carries ONLY confirm+reason.
    assert '"can_proof_send"' in APP
    assert "if (c.can_proof_send === true)" in APP
    assert 'text: "Send proof to test mailbox"' in APP
    assert "function proofSendAct(campaign)" in APP
    assert "api(`/campaigns/${campaign.campaign_id}/proof-send`" in APP
    assert "JSON.stringify({ confirm: true, reason: values.reason.trim() })" in APP
    # The console must never be able to name a destination: the dialog has one
    # field (a reason), the request body is built exactly once, and no
    # recipient picker or address input exists on this path.
    proof_block = APP[APP.index("function proofSendAct(campaign)") : APP.index("function scheduleAct(campaign")]
    assert proof_block.count("name: ") == 1
    assert 'name: "reason"' in proof_block
    assert proof_block.count("JSON.stringify(") == 1
    for forbidden in ('name: "recipient', 'name: "mailbox', 'name: "email', 'name: "to"', "recipientPicker"):
        assert forbidden not in proof_block
    assert "chosen by the server" in APP
