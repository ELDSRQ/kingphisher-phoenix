from pathlib import Path

APP = (Path(__file__).resolve().parents[2] / "operator-ui" / "src" / "console" / "app.js").read_text(encoding="utf-8")


def test_welcome_treats_required_reviewers_as_a_verified_apply_precondition() -> None:
    assert (
        "Preflight verifies the selected GitHub environment has required reviewers; "
        "apply is blocked unless that protection is present"
    ) in APP
    assert "Production remains protected by the GitHub environment’s required reviewers" not in APP


def test_gui_presents_local_only_edge_and_recovery_truth() -> None:
    assert '"aria-label": "Production edge and recovery gates"' in APP
    assert "Production edge & recovery gates" in APP
    assert "Evidence level:" in APP
    assert "cannot be changed by an operator attestation" in APP
    assert "Inputs are structurally valid; production readiness is not proven." in APP
    assert "Configuration is structurally ready." not in APP


def test_gui_blocks_production_plan_action_without_hiding_staging_bootstrap() -> None:
    assert 'collected.environment === "production"' in APP
    assert "result.release_readiness?.production_plan_allowed !== true" in APP
    assert "Production workflow planning is blocked" in APP
    assert "Use staging to bootstrap the required Azure resources." in APP
    assert "Create reviewed workflow plan" in APP


def test_downloads_include_every_mail_and_provider_value_without_credentials() -> None:
    export_block = APP.split("const terraformValues = {", maxsplit=1)[1].split("const workflowValues = {", maxsplit=1)[
        0
    ]
    for key in (
        "acs_resource_mode",
        "acs_sending_domain",
        "acs_sender_local_part",
        "acs_daily_message_limit",
        "acs_messages_per_minute",
        "acs_ramp_batch_size",
        "acs_ramp_interval_seconds",
        "graph_endpoint",
        "directory_group_ids",
        "reported_mailbox_endpoint",
        "reported_mailbox_address",
        "reported_mailbox_folder",
        "allowed_recipient_domains",
        "ciphertext_active_key_id",
        "ciphertext_prior_key_ids",
        "ciphertext_prior_keys_secret_id",
    ):
        assert f"{key}:" in export_block
    workflow_block = APP.split("const workflowValues = {", maxsplit=1)[1].split("};", maxsplit=1)[0]
    assert "AZURE_CLIENT_ID" in workflow_block
    assert "DEPLOYMENT_GITHUB_TOKEN_SECRET_ID" in workflow_block
    assert "DEPLOYMENT_GITHUB_TOKEN:" not in workflow_block
    assert "password" not in workflow_block.lower()


def test_ciphertext_recovery_export_contains_references_but_no_key_material_fields() -> None:
    export_block = APP.split("const terraformValues = {", maxsplit=1)[1].split("const workflowValues = {", maxsplit=1)[
        0
    ]
    assert "ciphertext_active_key_id:" in export_block
    assert "ciphertext_prior_key_ids:" in export_block
    assert "ciphertext_prior_keys_secret_id:" in export_block
    for forbidden in (
        "ciphertext_prior_key_value",
        "ciphertext_prior_keys_value",
        "CIPHERTEXT_KEK",
        "64-hex",
    ):
        assert forbidden not in export_block


def test_gui_uses_three_server_evidenced_stages_and_restores_latest_plan() -> None:
    for stage in ("foundation_bootstrap", "foundation_finalize", "workloads"):
        assert stage in APP
    assert '"aria-label": "Three-stage Azure deployment timeline"' in APP
    assert "/console/azure-deployment/orchestration/latest?environment=" in APP
    assert "Restored your latest active Azure deployment plan after reload." in APP
    assert "/advance`" in APP
    assert "It does not redispatch the completed plan." in APP
    assert 'rawAcsEvidence?.status === "verified"' in APP


def test_gui_has_no_operator_entered_or_exported_acs_readiness_attestations() -> None:
    for obsolete in (
        "acs_domain_verification_status",
        "acs_spf_verification_status",
        "acs_dkim_verification_status",
        "acs_dkim2_verification_status",
        "acs_sender_username_status",
        "acs_domain_association_status",
        "acs_readiness_checked_at",
    ):
        assert obsolete not in APP
    assert '"aria-label": "Bounded ACS deployment evidence"' in APP
    assert "Artifact status:" in APP
    assert "Mail delivery, inbox placement, and human mailbox validation remain separate gates." in APP
    assert "az containerapp" not in APP.split("/* ---------- Azure deployment wizard ---------- */", maxsplit=1)[1]


def test_advanced_fields_collapse_behind_disclosure_with_strong_defaults() -> None:
    assert "const normalFields = (step.fields || []).filter((field) => field.advanced !== true);" in APP
    assert "const advancedFields = (step.fields || []).filter((field) => field.advanced === true);" in APP
    assert "text: `Advanced options (${advancedFields.length})`" in APP
    assert "These resource IDs, quotas, and GitHub/Terraform hooks use reviewed defaults" in APP
    assert "Most operators never change them." in APP
    assert "field.suggested_default" in APP
    assert "normalFields.forEach((field, index) => form.appendChild(renderField(field, index)));" in APP


def test_managed_ai_is_required_and_pattern_approval_uses_durable_request_truth() -> None:
    azure_export = APP.split("const terraformValues = {", maxsplit=1)[1].split("const workflowValues = {", maxsplit=1)[
        0
    ]
    assert "ai_endpoint: collected.ai_endpoint" in azure_export
    assert "Managed deployment validation requires that gateway." in APP
    assert "generation_request_recorded !== true" in APP
    assert 'Object.hasOwn(approval, "generation_queued")' in APP
    assert "Pattern approved; template generation requested" in APP


def test_azure_ai_suggestions_require_explicit_form_apply_and_review() -> None:
    azure = APP.split("/* ---------- Azure deployment wizard ---------- */", maxsplit=1)[1]
    assert '"aria-label": "AI suggestions requiring review"' in azure
    assert 'text: "Apply to form"' in azure
    assert "Object.hasOwn(inputs, key)" in azure
    assert ".slice(0, 16)" in azure
    assert "Review it before creating a plan." in azure
    assert "inputs[key].value = value" in azure
    assert "Creating a plan does not start a workflow." in azure
