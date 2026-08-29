"""Static GUI contract for preservation-first Azure deployment recovery."""

from pathlib import Path

APP = (Path(__file__).resolve().parents[2] / "operator-ui" / "src" / "console-js" / "app.js").read_text(
    encoding="utf-8"
)
AZURE = APP.split("/* ---------- Azure deployment wizard ---------- */", maxsplit=1)[1].split(
    "views.campaigns = async", maxsplit=1
)[0]


def test_gui_consumes_server_recovery_policy_and_evidence_without_reconstructing_categories() -> None:
    assert "plan.recovery" in AZURE
    assert "recovery?.policy" in AZURE
    assert "policy.preservation_required" in AZURE
    assert "policy.prohibited_automatic_actions" in AZURE
    assert "policy.automatic_cleanup_allowed === false" in AZURE
    assert 'policy.strategy === "reconcile_existing_operation"' in AZURE
    assert "recovery?.verification" in AZURE
    assert "evidenceContract?.connector_verified" in AZURE
    assert '"awaiting_protected_workflow", "evidence_unverified", "verified"' in AZURE
    assert 'evidenceContract?.source === "bounded_github_run_job_step_activity"' in AZURE
    assert "Object.entries(evidenceContract.checks)" in AZURE
    assert "check.required_fields" in AZURE
    assert '"aria-label": "Preservation-required deployment state"' in AZURE
    assert '"aria-label": "Required deployment preflight evidence"' in AZURE
    assert "Verification comes only from bounded exact job and step results" in AZURE
    assert '"aria-label": "Unverified required workflow activity"' in AZURE


def test_gui_requires_server_action_flags_before_dispatch_or_retry() -> None:
    for field in ("next_action", "retry_allowed", "reconcile_only", "destructive_cleanup_allowed"):
        assert f"action.{field}" in AZURE
    assert (
        "const mutationContractValid = action.valid && action.preservationSafe && recoveryValid && checkpointIntegrity"
        in AZURE
    )
    assert (
        'rawState === "reviewed" && mutationContractValid && !action.retryAllowed && !action.reconcileRequired' in AZURE
    )
    assert (
        'rawState === "dispatch_failed" && mutationContractValid && action.retryAllowed && !action.reconcileRequired'
    ) in AZURE
    assert 'text: "Retry rejected dispatch"' in AZURE
    assert '["dispatch_failed", "run_failed"].includes(rawState)' not in AZURE
    assert 'text: "Retry after review"' not in AZURE
    assert "This deployment action is not authorized by the current recovery state" in AZURE


def test_uncertain_and_in_progress_operations_are_reconcile_only() -> None:
    for state in ("dispatching", "dispatch_accepted", "dispatch_indeterminate", "queued", "running"):
        assert f'"{state}"' in AZURE
    assert 'text: action.reconcileRequired ? "Reconcile existing operation" : "Refresh status"' in AZURE
    assert "Reconciliation is required; a new dispatch is blocked." in AZURE
    assert "do not retry or clean up resources" not in AZURE.lower()  # guidance comes from the bounded server field
    assert '"dispatch_indeterminate"].includes' not in AZURE


def test_rejected_dispatch_confirmation_is_explicit_and_preservation_safe() -> None:
    assert 'title: retry ? "Confirm rejected-dispatch retry"' in AZURE
    assert 'confirmLabel: retry ? "Retry rejected dispatch"' in AZURE
    assert "only because GitHub created no prior run" in AZURE
    assert "Existing resources, volumes, databases, images, caches, and evidence remain preserved." in AZURE
    for forbidden_label in (
        'text: "Clean',
        'text: "Delete',
        'text: "Prune',
        'text: "Recreate',
        'text: "Remove',
        'text: "Reset',
    ):
        assert forbidden_label not in AZURE


def test_gui_bounds_and_renders_checkpoint_sequence_and_integrity() -> None:
    assert "rawCheckpointRows.length > 0 && rawCheckpointRows.length <= 64" in AZURE
    assert "checkpoint.sequence === index + 1" in AZURE
    assert "checkpoint.previous_digest === previousDigest" in AZURE
    assert "/^[0-9a-f]{64}$/.test(checkpoint.digest)" in AZURE
    assert "checkpoint.recorded_at.length <= 64" in AZURE
    assert '"aria-label": "Tamper-evident deployment checkpoints"' in AZURE
    assert '"aria-label": "Deployment checkpoint integrity"' in AZURE
    assert "Checkpoint integrity: tamper-evident server-validated chain" in AZURE
    assert "Only refresh and workflow inspection are safe." in AZURE


def test_gui_bounds_state_error_and_safe_next_action() -> None:
    assert "const knownStates = new Set" in AZURE
    assert 'const rawState = typeof plan.state === "string" && knownStates.has(plan.state)' in AZURE
    assert "plan.last_error.length <= 600" in AZURE
    assert "action.next_action.length <= 400" in AZURE
    assert "Deployment status details are unavailable; inspect the protected workflow." in AZURE
    assert 'text: "Safe next action: "' in AZURE
    assert 'role: lastError ? "alert" : "status"' in AZURE
    assert '"aria-live": lastError ? "assertive" : "polite"' in AZURE
