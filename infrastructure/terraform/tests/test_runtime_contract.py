"""Static contracts for mandatory managed-runtime Terraform wiring."""

from __future__ import annotations

import re
from pathlib import Path

TERRAFORM_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = TERRAFORM_DIR.parents[1]
MAIN = (TERRAFORM_DIR / "main.tf").read_text(encoding="utf-8")
VARIABLES = (TERRAFORM_DIR / "variables.tf").read_text(encoding="utf-8")
OUTPUTS = (TERRAFORM_DIR / "outputs.tf").read_text(encoding="utf-8")


def test_existing_acs_endpoint_variable_matches_the_runtime_origin_contract() -> None:
    block = VARIABLES.split('variable "acs_existing_email_endpoint"', maxsplit=1)[1].split("\n}\n", maxsplit=1)[0]
    match = re.search(r'regex\("([^"]+)"', block)
    assert match is not None
    pattern = match.group(1).replace("\\\\", "\\")

    for endpoint in (
        "https://name.communication.azure.com",
        "https://name.communication.azure.com/",
        "https://name.communication.azure.com:443",
        "https://name.communication.azure.com:443/",
    ):
        assert re.fullmatch(pattern, endpoint) is not None

    for endpoint in (
        "https://communication.azure.com",
        "https://nested.name.communication.azure.com",
        "https://name.communication.azure.com:444",
        "https://operator@name.communication.azure.com",
        "https://-name.communication.azure.com",
        "https://name-.communication.azure.com",
        "https://name.communication.azure.com./",
        "https://name.communication.azure.com/path",
        "https://name.communication.azure.com?query=yes",
        "https://name.communication.azure.com#fragment",
    ):
        assert re.fullmatch(pattern, endpoint) is None


def test_independent_safety_keys_are_256_bit_and_stored_in_key_vault() -> None:
    assert 'resource "random_id" "roe_signing" { byte_length = 32 }' in MAIN
    assert 'resource "random_id" "domain_verification" { byte_length = 32 }' in MAIN
    assert "roe-signing-key" in MAIN and "random_id.roe_signing.hex" in MAIN
    assert "domain-verify-key" in MAIN and "random_id.domain_verification.hex" in MAIN
    assert 'resource "random_id" "training_token_hmac" { byte_length = 32 }' in MAIN
    assert "training-token-hmac" in MAIN and "random_id.training_token_hmac.hex" in MAIN
    assert 'resource "random_id" "acs_receipt_signing" { byte_length = 32 }' in MAIN
    assert "acs-receipt-signing-key" in MAIN and "random_id.acs_receipt_signing.hex" in MAIN


def test_awareness_pseudonym_key_is_stable_versioned_and_retention_scoped() -> None:
    assert 'resource "random_id" "awareness_pseudonym"' in MAIN
    assert (
        "byte_length = 32"
        in MAIN.split('resource "random_id" "awareness_pseudonym"', maxsplit=1)[1].split("\n}", maxsplit=1)[0]
    )
    assert (
        "prevent_destroy = true"
        in MAIN.split('resource "random_id" "awareness_pseudonym"', maxsplit=1)[1].split(
            'resource "azurerm_role_assignment" "deployer_secrets"', maxsplit=1
        )[0]
    )
    assert "awareness-pseudonym-key = random_id.awareness_pseudonym.hex" in MAIN
    assert 'contains(roles, "retention") ? toset(["awareness-pseudonym-key"]) : toset([])' in MAIN
    worker = MAIN.split('resource "azurerm_container_app" "worker"', maxsplit=1)[1].split(
        'resource "azurerm_role_assignment" "communication_sender"', maxsplit=1
    )[0]
    assert 'contains(local.worker_deployment_roles[each.key], "retention") ? {' in worker
    assert worker.count('KP_WORKER_AWARENESS_PSEUDONYM_KEY"') == 1
    assert worker.count('KP_WORKER_AWARENESS_PSEUDONYM_KEY_VERSION"') == 1
    assert 'secret_name = "awareness-pseudonym-key"' in worker
    assert "value = trimspace(var.awareness_pseudonym_key_version)" in worker

    version = VARIABLES.split('variable "awareness_pseudonym_key_version"', maxsplit=1)[1].split("\n}", maxsplit=1)[0]
    assert 'default     = "v1"' in version
    assert "{0,31}" in version


def test_safety_keys_are_wired_only_to_required_workloads() -> None:
    assert "OPERATOR_API_ROE_SIGNING_KEY" in MAIN
    assert 'secret = "roe-signing-key"' in MAIN
    assert "OPERATOR_API_DOMAIN_VERIFY_KEY" in MAIN
    assert 'secret = "domain-verify-key"' in MAIN
    assert 'contains(local.worker_deployment_roles[each.key], "delivery") ? {' in MAIN
    assert 'roe-signing-key         = azurerm_key_vault_secret.runtime["roe-signing-key"].versionless_id' in MAIN
    assert 'name        = "KP_WORKER_ROE_SIGNING_KEY"' in MAIN
    worker_section = MAIN.split('resource "azurerm_container_app" "worker"', maxsplit=1)[1]
    assert "KP_WORKER_DOMAIN_VERIFY_KEY" not in worker_section


def test_tracking_token_hmac_is_distinct_and_scoped_to_issuer_and_verifier() -> None:
    assert 'resource "random_id" "tracking_token_hmac" { byte_length = 32 }' in MAIN
    assert "tracking-token-hmac" in MAIN and "random_id.tracking_token_hmac.hex" in MAIN
    assert "OPERATOR_API_TRACKING_TOKEN_HMAC_KEY" in MAIN
    assert "TRACKING_API_TRACKING_TOKEN_HMAC_KEY" in MAIN
    worker_section = MAIN.split('resource "azurerm_container_app" "worker"', maxsplit=1)[1]
    assert "TRACKING_TOKEN_HMAC_KEY" not in worker_section


def test_retired_corrections_secret_is_not_generated_or_provisioned() -> None:
    bootstrap = (PROJECT_ROOT / "scripts" / "bootstrap_env.sh").read_text(encoding="utf-8")
    env_example = (PROJECT_ROOT / ".env.example").read_text(encoding="utf-8")
    tracking_config = (PROJECT_ROOT / "apps" / "tracking-api" / "src" / "kp_tracking_api" / "config.py").read_text(
        encoding="utf-8"
    )

    for retired_name in (
        "TRACKING_API_CORRECTIONS_SECRET",
        "corrections-secret",
        "random_id.corrections",
        "corrections_secret",
    ):
        assert retired_name not in MAIN
        assert retired_name not in bootstrap
        assert retired_name not in env_example
        assert retired_name not in tracking_config


def test_training_token_hmac_is_scoped_to_operator_tracking_and_reminder() -> None:
    assert "OPERATOR_API_TRAINING_TOKEN_HMAC_KEY" in MAIN
    assert "TRACKING_API_TRAINING_TOKEN_HMAC_KEY" in MAIN
    worker_section = MAIN.split('resource "azurerm_container_app" "worker"', maxsplit=1)[1].split(
        'resource "azurerm_role_assignment" "communication_sender"', maxsplit=1
    )[0]
    assert 'contains(local.worker_deployment_roles[each.key], "reminder") ? {' in worker_section
    assert 'name        = "KP_WORKER_TRAINING_TOKEN_HMAC_KEY"' in worker_section
    assert worker_section.count("KP_WORKER_TRAINING_TOKEN_HMAC_KEY") == 1
    assert 'contains(roles, "reminder") ? toset(["training-token-hmac"]) : toset([])' in MAIN
    for forbidden in ("delivery", "ingestion", "retention", "alert"):
        assert f'role == "{forbidden}" ? toset(["training-token-hmac"])' not in MAIN


def test_managed_identities_follow_deployments_with_separate_provider_identities() -> None:
    assert 'resource "azurerm_user_assigned_identity" "runtime"' not in MAIN
    assert 'resource "azurerm_user_assigned_identity" "workload"' in MAIN
    assert "for_each            = local.workload_identities" in MAIN
    assert 'toset(["operator", "tracking", "migration"])' in MAIN
    assert "local.worker_deployments" in MAIN
    assert 'identity_ids = [azurerm_user_assigned_identity.workload["operator"].id]' in MAIN
    assert 'identity_ids = [azurerm_user_assigned_identity.workload["tracking"].id]' in MAIN
    assert "provider_identity_names = {" in MAIN
    assert 'role => "provider-${role}"' in MAIN
    assert "identity_ids = concat(" in MAIN
    assert "local.provider_identity_names[role]" in MAIN
    assert 'identity_ids = [azurerm_user_assigned_identity.workload["migration"].id]' in MAIN
    assert "for_each                     = var.deploy_workloads ? local.worker_deployments : toset([])" in MAIN
    assert "for_each                     = var.deploy_workloads ? local.worker_roles : toset([])" not in MAIN


def test_directory_and_mailbox_use_distinct_explicit_identity_client_ids() -> None:
    worker = MAIN.split('resource "azurerm_container_app" "worker"', maxsplit=1)[1].split(
        'resource "azurerm_role_assignment" "communication_sender"', maxsplit=1
    )[0]
    assert 'toset(["directory", "mailbox"])' in worker
    assert '"KP_WORKER_GRAPH_CLIENT_ID"' in worker
    assert '"KP_WORKER_REPORTED_MAILBOX_CLIENT_ID"' in worker
    assert "local.provider_identity_names[env.value]" in worker
    assert "KP_WORKER_MICROSOFT_TENANT_ID" in MAIN
    assert "KP_WORKER_GRAPH_GROUP_IDS" in MAIN
    assert "KP_WORKER_REPORTED_MAILBOX_ID" in MAIN
    assert "KP_WORKER_REPORTED_MAILBOX_FOLDER_ID" in MAIN
    assert "KP_WORKER_REPORTED_MAILBOX_PROVIDER" in MAIN


def test_provider_identities_get_no_key_vault_or_image_pull_access() -> None:
    assert "for_each             = local.image_pull_identities" in MAIN
    assert (
        "toset(values(local.provider_identity_names))"
        not in MAIN.split('resource "azurerm_role_assignment" "acr_pull"', maxsplit=1)[1].split(
            'resource "azurerm_key_vault"', maxsplit=1
        )[0]
    )
    secret_access = MAIN.split("locals {\n  workload_secret_names", maxsplit=1)[1].split(
        'resource "azurerm_role_assignment" "workload_secret"', maxsplit=1
    )[0]
    assert "provider_identity_names" not in secret_access
    assert "microsoft_graph_identities" in OUTPUTS


def test_runtime_secret_access_is_secret_scoped_not_vault_scoped() -> None:
    assert 'resource "azurerm_role_assignment" "runtime_secrets"' not in MAIN
    access = MAIN.split('resource "azurerm_role_assignment" "workload_secret"', maxsplit=1)[1].split(
        'resource "azurerm_container_app_environment"', maxsplit=1
    )[0]
    assert ".resource_versionless_id" in access
    assert "azurerm_key_vault.main.id" not in access
    assert "each.value.workload" in access


def test_audit_signing_root_is_exposed_only_to_migration_identity() -> None:
    assert 'migration = toset(concat(\n        ["migration-database-url", "audit-password", "audit-hmac"]' in MAIN
    operator = MAIN.split('resource "azurerm_container_app" "operator"', maxsplit=1)[1].split(
        'resource "azurerm_container_app" "tracking"', maxsplit=1
    )[0]
    workers = MAIN.split('resource "azurerm_container_app" "worker"', maxsplit=1)[1].split(
        'resource "azurerm_role_assignment" "communication_sender"', maxsplit=1
    )[0]
    migration = MAIN.split('resource "azurerm_container_app_job" "migration"', maxsplit=1)[1]
    assert "AUDIT_HMAC_KEY" not in operator + workers
    assert 'AUDIT_ROOT_KEY        = "audit-hmac"' in migration


def test_runtime_database_credentials_are_distinct_and_admin_dsn_is_migration_only() -> None:
    assert 'operator = "kp_operator"' in MAIN
    assert 'tracking = "kp_tracking"' in MAIN
    assert '"kp_worker_${replace(role, "-", "_")}"' in MAIN
    assert 'resource "random_password" "runtime_database"' in MAIN
    assert "migration-database-url  = local.migration_database_url" in MAIN
    operator_section = MAIN.split('resource "azurerm_container_app" "operator"', maxsplit=1)[1].split(
        'resource "azurerm_container_app" "tracking"', maxsplit=1
    )[0]
    tracking_section = MAIN.split('resource "azurerm_container_app" "tracking"', maxsplit=1)[1].split(
        'resource "azurerm_container_app" "worker"', maxsplit=1
    )[0]
    worker_section = MAIN.split('resource "azurerm_container_app" "worker"', maxsplit=1)[1].split(
        'resource "azurerm_role_assignment" "communication_sender"', maxsplit=1
    )[0]
    assert 'secret = "operator-database-url"' in operator_section
    assert "tracking-database-url" not in operator_section
    assert 'secret = "tracking-database-url"' in tracking_section
    assert "audit-database-url" not in tracking_section
    assert "local.runtime_database_secret_names[secret.value]" in worker_section
    assert 'name        = "KP_WORKER_DATABASE_URL_${upper(replace(env.value, "-", "_"))}"' in worker_section
    assert "migration-database-url" not in operator_section + tracking_section + worker_section


def test_only_the_combined_worker_and_optional_isolated_delivery_can_send_email() -> None:
    sender = MAIN.split('resource "azurerm_role_assignment" "communication_sender"', maxsplit=1)[1].split(
        'resource "azurerm_container_app_job" "migration"', maxsplit=1
    )[0]
    assert "for_each = var.deploy_workloads ? (" in sender
    assert 'var.isolate_delivery_worker ? toset(["worker", "delivery"]) : toset(["worker"])' in sender
    assert ") : toset([])" in sender
    assert "workload[each.key].principal_id" in sender


def test_acs_sender_uses_the_explicit_delivery_workload_identity() -> None:
    worker = MAIN.split('resource "azurerm_container_app" "worker"', maxsplit=1)[1].split(
        'resource "azurerm_role_assignment" "communication_sender"', maxsplit=1
    )[0]
    assert 'name  = "KP_WORKER_ACS_CLIENT_ID"' in worker
    assert "value = azurerm_user_assigned_identity.workload[each.key].client_id" in worker
    assert 'name  = "AZURE_CLIENT_ID"' not in worker


def test_tracking_replicas_use_the_shared_redis_rate_limit_backend() -> None:
    tracking_section = MAIN.split('resource "azurerm_container_app" "tracking"', maxsplit=1)[1].split(
        'resource "azurerm_container_app" "worker"', maxsplit=1
    )[0]
    assert 'redis-url             = local.common_secrets["redis-url"]' in tracking_section
    assert 'TRACKING_API_REDIS_URL                = { value = null, secret = "redis-url" }' in tracking_section
    assert 'TRACKING_API_RATE_LIMIT_BACKEND       = { value = "redis", secret = null }' in tracking_section
    assert (
        "TRACKING_API_TRUSTED_PROXIES          = { value = local.tracking_trusted_proxies, secret = null }"
        in tracking_section
    )
    assert "azurerm_subnet.container_apps.address_prefixes" in MAIN
    assert '["127.0.0.1/32", "::1/128"]' in MAIN
    operator_section = MAIN.split('resource "azurerm_container_app" "operator"', maxsplit=1)[1].split(
        'resource "azurerm_container_app" "tracking"', maxsplit=1
    )[0]
    assert 'OPERATOR_API_REDIS_URL                    = { value = null, secret = "redis-url" }' in operator_section
    assert 'OPERATOR_API_RATE_LIMIT_BACKEND       = { value = "redis", secret = null }' in operator_section


def test_managed_worker_health_targets_are_exact_and_nonsecret() -> None:
    health = OUTPUTS.split('output "managed_worker_health_targets"', maxsplit=1)[1].split(
        'output "key_vault_name"', maxsplit=1
    )[0]

    assert "local.worker_deployment_roles" in health
    assert "azurerm_container_app.worker[deployment].name" in health
    assert "roles = sort(tolist(roles))" in health
    assert 'output "log_analytics_workspace_customer_id"' in OUTPUTS
    assert "azurerm_log_analytics_workspace.main.workspace_id" in OUTPUTS


def test_alert_destination_allowlist_is_shared_by_operator_and_workers() -> None:
    operator_section = MAIN.split('resource "azurerm_container_app" "operator"', maxsplit=1)[1].split(
        'resource "azurerm_container_app" "tracking"', maxsplit=1
    )[0]
    worker_section = MAIN.split('resource "azurerm_container_app" "worker"', maxsplit=1)[1].split(
        'resource "azurerm_role_assignment" "communication_sender"', maxsplit=1
    )[0]

    expected = "KP_WORKER_ALERT_WEBHOOK_DOMAINS"
    assert expected in operator_section
    assert expected in worker_section
    assert operator_section.count("var.alert_webhook_domains") == 1
    assert worker_section.count("var.alert_webhook_domains") == 1


def test_managed_workers_never_fall_back_to_local_providers() -> None:
    worker_section = MAIN.split('resource "azurerm_container_app" "worker"', maxsplit=1)[1].split(
        'resource "azurerm_role_assignment" "communication_sender"', maxsplit=1
    )[0]
    assert 'name  = "KP_WORKER_RUNTIME_MODE"\n        value = "managed"' in MAIN
    assert "value = local.tracking_base_url" in MAIN
    assert "value = local.training_base_url" in MAIN
    assert "localhost" not in worker_section
    assert "127.0.0.1" not in worker_section


def test_optional_provider_roles_require_explicit_endpoints() -> None:
    assert 'generation = trimspace(var.ai_endpoint) == "" ? {} :' in MAIN
    assert 'directory = trimspace(var.graph_endpoint) == "" ? {} :' in MAIN
    assert 'mailbox = trimspace(var.reported_mailbox_endpoint) == "" ? {} :' in MAIN
    assert "setunion(local.core_worker_roles, local.provider_worker_roles)" in MAIN
    assert 'name  = "KP_WORKER_AI_BASE_URL"' not in MAIN
    assert "KP_WORKER_GRAPH_BEARER_TOKEN" not in MAIN
    assert "KP_WORKER_REPORTED_MAILBOX_BEARER_TOKEN" not in MAIN
    assert '"microsoft365"' in MAIN


def test_default_topology_is_three_continuous_apps_with_one_supervised_worker() -> None:
    isolation = VARIABLES.split('variable "isolate_delivery_worker"', maxsplit=1)[1].split("\n}\n", maxsplit=1)[0]
    assert "default     = false" in isolation
    assert (
        'worker = var.isolate_delivery_worker ? setsubtract(local.worker_roles, toset(["delivery"])) : '
        "local.worker_roles" in MAIN
    )
    assert 'command = each.key == "worker" ? ["kp-worker", "supervise"] : ["kp-worker", "delivery"]' in MAIN
    assert 'name  = "KP_WORKER_ROLES"' in MAIN
    assert "continuously_running_apps" in OUTPUTS
    assert "2 + length(local.worker_deployments)" in OUTPUTS
    assert "manual_migration_jobs" in OUTPUTS


def test_delivery_isolation_is_the_only_optional_worker_split() -> None:
    assert 'setsubtract(local.worker_roles, toset(["delivery"]))' in MAIN
    assert 'var.isolate_delivery_worker ? { delivery = toset(["delivery"]) } : {}' in MAIN
    assert "var.isolate_delivery_worker ?" in MAIN
    assert 'each.key == "delivery" ? (local.production ? 5 : 2) : 1' in MAIN
    assert "delivery_isolated" in OUTPUTS
    assert "worker_deployments" in OUTPUTS


def test_combined_identity_gets_only_enabled_role_secrets() -> None:
    access = MAIN.split("locals {\n  workload_secret_names", maxsplit=1)[1].split(
        'resource "azurerm_role_assignment" "workload_secret"', maxsplit=1
    )[0]
    assert "for deployment, roles in local.worker_deployment_roles" in access
    assert "for role in roles : local.runtime_database_secret_names[role]" in access
    assert 'contains(roles, "directory") ? toset(["recipient-salt"]) : toset([])' in access
    assert 'contains(roles, "delivery") ? toset(["roe-signing-key", "acs-receipt-signing-key"]) : toset([])' in access
    assert 'contains(roles, "reminder") ? toset(["training-token-hmac"]) : toset([])' in access
    deployment_access = access.split("for deployment, roles in local.worker_deployment_roles", maxsplit=1)[1]
    for forbidden in ("migration-database-url", "audit-hmac", "domain-verify-key", "console-jwt"):
        assert forbidden not in deployment_access


def test_core_roles_are_always_enabled_and_provider_roles_are_conditional() -> None:
    assert (
        'core_worker_roles = toset(["ingestion", "delivery", "retention", "reminder", "alert", "audit-anchor"])' in MAIN
    )
    assert "worker_roles = setunion(local.core_worker_roles, local.provider_worker_roles)" in MAIN
    for role, variable in (
        ("generation", "ai_endpoint"),
        ("directory", "graph_endpoint"),
        ("mailbox", "reported_mailbox_endpoint"),
    ):
        assert f'{role} = trimspace(var.{variable}) == "" ? {{}} :' in MAIN


def test_tracking_and_training_urls_share_the_public_tracking_boundary() -> None:
    assert 'tracking_base_url             = "https://${lower(trimspace(var.tracking_fqdn))}"' in MAIN
    assert 'training_base_url             = "${local.tracking_base_url}/v1/training/awareness"' in MAIN
    assert "TRACKING_API_TRAINING_BASE_URL        = { value = local.training_base_url, secret = null }" in MAIN
    assert "https://${var.operator_fqdn}/training" not in MAIN


def test_provider_inputs_use_native_graph_and_validate_selected_resources() -> None:
    ai = VARIABLES.split('variable "ai_endpoint"', maxsplit=1)[1].split("\n}\n", maxsplit=1)[0]
    assert "startswith(lower(trimspace(var.ai_endpoint))" in ai
    for variable in ("graph_endpoint", "reported_mailbox_endpoint"):
        block = VARIABLES.split(f'variable "{variable}"', maxsplit=1)[1].split("\n}\n", maxsplit=1)[0]
        assert '"https://graph.microsoft.com/v1.0"' in block
        assert "localhost" not in block
    assert 'variable "directory_group_ids"' in VARIABLES
    assert 'variable "reported_mailbox_address"' in VARIABLES
    assert 'variable "reported_mailbox_folder"' in VARIABLES


def test_placeholder_images_are_rejected_when_workloads_are_enabled() -> None:
    assert 'resource "terraform_data" "workload_config_guard"' in MAIN
    assert '!startswith(image, "bootstrap.invalid/")' in MAIN


def test_acs_uses_customer_domain_and_fresh_fail_closed_readiness() -> None:
    assert 'domain_management                = "CustomerManaged"' in MAIN
    assert "AzureManagedDomain" not in MAIN
    assert 'variable "acs_resource_mode"' in VARIABLES
    assert 'contains(["provision", "existing"], var.acs_resource_mode)' in VARIABLES
    assert "local.acs_readiness_current" in MAIN
    assert "Domain, SPF, DKIM and DKIM2 as Verified" in MAIN
    assert 'endswith(lower(trimspace(var.acs_sending_domain)), ".azurecomm.net")' in VARIABLES


def test_acs_dns_is_automated_only_for_explicit_in_scope_azure_zone() -> None:
    assert 'variable "acs_dns_zone_id"' in VARIABLES
    assert "local.acs_dns_automation" in MAIN
    assert 'lower(try(local.acs_dns_zone_parts[2], "")) == lower(var.subscription_id)' in MAIN
    assert 'resource "azurerm_dns_txt_record" "acs_verification"' in MAIN
    assert 'resource "azurerm_dns_cname_record" "acs_verification"' in MAIN
    assert "manual_dns_required" in OUTPUTS
    assert "dns_records" in OUTPUTS


def test_acs_domain_link_and_sender_require_explicit_finalize_stage_and_fresh_readiness() -> None:
    association = MAIN.split('resource "azurerm_communication_service_email_domain_association" "main"', maxsplit=1)[
        1
    ].split("}\n", maxsplit=1)[0]
    sender = MAIN.split('resource "azurerm_email_communication_service_domain_sender_username" "main"', maxsplit=1)[
        1
    ].split("}\n", maxsplit=1)[0]
    assert "local.acs_binding_management_enabled && local.acs_domain_live_ready" in association
    assert "local.acs_binding_management_enabled && local.acs_domain_live_ready" in sender
    assert "var.deploy_workloads" not in association
    assert "var.deploy_workloads" not in sender
    assert "prevent_destroy = true" in association
    assert "prevent_destroy = true" in sender
    assert 'lower(trimspace(var.acs_sender_username_status)) == "verified"' in MAIN
    assert 'lower(trimspace(var.acs_domain_association_status)) == "verified"' in MAIN
    assert "acs_domain_association_status" in VARIABLES
    assert "planned_after_domain_verification" in OUTPUTS
    assert 'output "acs_control_plane_resources"' in OUTPUTS
    assert 'output "acs_stage_contract"' in OUTPUTS
    assert '["foundation_finalize", "workloads"]' in MAIN
    assert "bootstrap_can_manage_binding      = false" in OUTPUTS
    assert "azure_control_plane_readback_in_deployment_workflow" in OUTPUTS


def test_acs_sender_and_pacing_are_explicit_nonsecret_worker_configuration() -> None:
    for name in (
        "KP_WORKER_ACS_SENDING_DOMAIN",
        "KP_WORKER_ACS_SENDER_LOCAL_PART",
        "KP_WORKER_ACS_SENDER_DISPLAY_NAME",
        "KP_WORKER_ACS_READINESS_CHECKED_AT",
        "KP_WORKER_ACS_DAILY_MESSAGE_LIMIT",
        "KP_WORKER_ACS_MESSAGES_PER_MINUTE",
        "KP_WORKER_ACS_RAMP_BATCH_SIZE",
    ):
        assert name in MAIN
    assert "ACS_EMAIL_CONNECTION_STRING" not in MAIN
    assert 'data "azurerm_communication_service"' not in MAIN
    assert "acs_existing_communication_service_id" in MAIN
    assert "acs_existing_email_endpoint" in MAIN
    assert "acceptance_semantics" in OUTPUTS
    assert "authenticated delivery reports" in OUTPUTS


def test_acs_receipts_use_entra_webhook_and_private_hmac_boundary() -> None:
    assert 'resource "azurerm_eventgrid_system_topic" "acs_delivery"' in MAIN
    assert 'topic_type          = "Microsoft.Communication.CommunicationServices"' in MAIN
    assert 'resource "azurerm_eventgrid_system_topic_event_subscription" "acs_delivery"' in MAIN
    assert "var.deploy_workloads && var.enable_acs_event_subscription ? 1 : 0" in MAIN
    activation = VARIABLES.split('variable "enable_acs_event_subscription"', maxsplit=1)[1].split("\n}", maxsplit=1)[0]
    assert "default     = false" in activation
    assert '"Microsoft.Communication.EmailDeliveryReportReceived"' in MAIN
    assert "active_directory_tenant_id        = var.entra_tenant_id" in MAIN
    assert "active_directory_app_id_or_uri    = var.entra_client_id" in MAIN
    assert "max_events_per_batch              = 64" in MAIN
    assert "preferred_batch_size_in_kilobytes = 256" in MAIN
    assert "aeg-sas-key" not in MAIN.lower()
    assert "OPERATOR_API_EVENT_GRID_TENANT_ID" in MAIN
    assert "OPERATOR_API_EVENT_GRID_AUDIENCE" in MAIN
    assert "OPERATOR_API_EVENT_GRID_SUBSCRIPTION_NAME" in MAIN
    assert "OPERATOR_API_EVENT_GRID_TOPIC" in MAIN
    assert "OPERATOR_API_ACS_RECEIPT_SIGNING_KEY" in MAIN
    assert "KP_WORKER_ACS_RECEIPT_SIGNING_KEY" in MAIN
    assert "acs_receipt_ingress" in OUTPUTS


def test_receipt_signing_secret_is_scoped_only_to_operator_and_delivery_deployment() -> None:
    access = MAIN.split("locals {\n  workload_secret_names", maxsplit=1)[1].split(
        'resource "azurerm_role_assignment" "workload_secret"', maxsplit=1
    )[0]
    assert access.count('"acs-receipt-signing-key"') == 2
    assert "operator = toset([" in access
    assert 'contains(roles, "delivery")' in access
    for role in ("tracking", "migration"):
        block = access.split(f"{role} = toset(", maxsplit=1)[1].split(")", maxsplit=1)[0]
        assert "acs-receipt-signing-key" not in block


def test_gui_deployment_connector_is_optional_and_uses_only_external_key_vault_secret_reference() -> None:
    assert 'variable "deployment_orchestration_mode"' in VARIABLES
    mode = VARIABLES.split('variable "deployment_orchestration_mode"', maxsplit=1)[1].split("\n}", maxsplit=1)[0]
    assert 'default     = "disabled"' in mode
    assert 'contains(["disabled", "github_actions"]' in mode
    assert 'variable "deployment_github_repository"' in VARIABLES
    assert 'variable "deployment_github_ref"' in VARIABLES
    assert 'variable "deployment_github_token_secret_id"' in VARIABLES
    assert 'resource "azurerm_role_assignment" "deployment_github_token_reader"' in MAIN
    assert "var.deploy_workloads && local.deployment_orchestration_enabled" in MAIN
    assert "deployment-github-token = local.deployment_github_token_versionless_uri" in MAIN
    assert "scope                = trimspace(var.deployment_github_token_secret_id)" in MAIN
    assert "OPERATOR_API_DEPLOYMENT_ORCHESTRATION_MODE" in MAIN
    assert "OPERATOR_API_DEPLOYMENT_GITHUB_REPOSITORY" in MAIN
    assert "OPERATOR_API_DEPLOYMENT_GITHUB_REF" in MAIN
    assert 'OPERATOR_API_DEPLOYMENT_GITHUB_TOKEN = { value = null, secret = "deployment-github-token" }' in MAIN
    assert "deployment_github_token_value" not in MAIN
    assert "github_pat_" not in MAIN


def test_ciphertext_recovery_uses_one_secret_reference_and_one_key_id_for_all_runtimes() -> None:
    assert 'variable "ciphertext_active_key_id"' in VARIABLES
    assert 'variable "ciphertext_prior_key_ids"' in VARIABLES
    assert 'variable "ciphertext_prior_keys_secret_id"' in VARIABLES
    assert 'resource "azurerm_role_assignment" "ciphertext_prior_key_reader"' in MAIN
    assert "scope                = local.ciphertext_prior_keys_secret_id" in MAIN
    assert "ciphertext-prior-keys = local.ciphertext_prior_keys_versionless_uri" in MAIN
    assert "key_vault_secret_id = local.ciphertext_prior_keys_versionless_uri" in MAIN
    assert '${trimsuffix(azurerm_key_vault.main.vault_uri, "/")}/secrets/' in MAIN
    assert "OPERATOR_API_CIPHERTEXT_KEY_ID            = { value = trimspace(var.ciphertext_active_key_id)" in MAIN
    assert 'name  = "KP_WORKER_CIPHERTEXT_KEY_ID"' in MAIN
    assert "value = trimspace(var.ciphertext_active_key_id)" in MAIN
    assert 'OPERATOR_API_CIPHERTEXT_PRIOR_KEYS = { value = null, secret = "ciphertext-prior-keys" }' in MAIN
    assert 'name        = "KP_WORKER_CIPHERTEXT_PRIOR_KEYS"' in MAIN
    assert 'secret_name = "ciphertext-prior-keys"' in MAIN
    assert MAIN.count("local.ciphertext_prior_keys_secret_id") >= 4
    assert "active_key_id = trimspace(var.ciphertext_active_key_id)" in MAIN
    active_key = MAIN.split('resource "random_id" "ciphertext_kek"', maxsplit=1)[1].split(
        'resource "random_id" "console_jwt"', maxsplit=1
    )[0]
    assert "prevent_destroy = true" in active_key
    assert "active_key_id = trimspace(var.ciphertext_active_key_id)" in active_key


def test_ciphertext_prior_key_material_never_enters_terraform() -> None:
    assert 'data "azurerm_key_vault_secret"' not in MAIN
    assert "ciphertext_prior_key_value" not in MAIN + VARIABLES + OUTPUTS
    assert "ciphertext_prior_keys_value" not in MAIN + VARIABLES + OUTPUTS
    assert "key-id=64-hex" in VARIABLES
    assert "prior_material_exposed_to_terraform = false" in OUTPUTS
    assert "external_versionless_key_vault_reference" in OUTPUTS


def test_ciphertext_recovery_is_bounded_and_foundation_fails_closed() -> None:
    prior_ids = VARIABLES.split('variable "ciphertext_prior_key_ids"', maxsplit=1)[1].split("\n}\n", maxsplit=1)[0]
    assert "<= 4" in prior_ids
    assert "length(distinct(" in prior_ids
    guard = MAIN.split('resource "terraform_data" "workload_config_guard"', maxsplit=1)[1].split(
        'resource "azurerm_resource_group" "main"', maxsplit=1
    )[0]
    assert "!contains(local.ciphertext_prior_key_ids" in guard
    assert "var.deploy_workloads" in guard
    assert 'can(regex("/secrets/[A-Za-z0-9-]+$"' in guard
    assert "foundation plans cannot add recovery keys" in guard
