from pathlib import Path

TERRAFORM_DIR = Path(__file__).resolve().parents[1]
MAIN = (TERRAFORM_DIR / "main.tf").read_text(encoding="utf-8")
VARIABLES = (TERRAFORM_DIR / "variables.tf").read_text(encoding="utf-8")
OUTPUTS = (TERRAFORM_DIR / "outputs.tf").read_text(encoding="utf-8")


def test_audit_anchor_storage_is_versioned_private_and_locked_worm() -> None:
    account = MAIN.split('resource "azurerm_storage_account" "audit_anchor"', maxsplit=1)[1].split(
        'resource "azurerm_storage_container" "audit_anchor"', maxsplit=1
    )[0]
    policy = MAIN.split('resource "azurerm_storage_container_immutability_policy" "audit_anchor"', maxsplit=1)[1].split(
        'resource "azurerm_role_definition" "audit_anchor_writer"', maxsplit=1
    )[0]
    assert "versioning_enabled = true" in account
    assert "shared_access_key_enabled" in account and "false" in account
    assert "public_network_access_enabled     = local.public_data_plane" in account
    assert 'default_action             = "Deny"' in account
    assert 'bypass                     = ["AzureServices"]' in account
    assert "virtual_network_subnet_ids = [azurerm_subnet.container_apps.id]" in account
    assert 'service_endpoint {\n    service = "Microsoft.Storage"\n  }' in MAIN
    assert "storage_container_resource_manager_id" in policy
    assert "immutability_period_in_days           = local.audit_anchor_retention_days" in policy
    assert "locked" in policy and "= true" in policy
    assert 'variable "audit_anchor_retention_days"' in VARIABLES


def test_retention_defaults_preserve_production_and_bound_disposable_cleanup() -> None:
    assert (
        "audit_anchor_retention_days = coalesce(var.audit_anchor_retention_days, "
        'var.environment == "production" ? 365 : 1)' in MAIN
    )
    variable = VARIABLES.split('variable "audit_anchor_retention_days"', maxsplit=1)[1].split("\n}\n", maxsplit=1)[0]
    assert "default     = null" in variable
    assert "nullable    = true" in variable
    assert "whole number between 1 and 146,000" in variable
    readiness = OUTPUTS.split('output "audit_anchor_readiness"', maxsplit=1)[1]
    assert "retention_days        = local.audit_anchor_retention_days" in readiness
    assert 'static_status         = var.deploy_workloads ? "configured_unproven" : "worker_not_deployed"' in readiness
    assert 'immutability_policy   = "locked_container_time_based_worm"' in readiness


def test_anchor_identity_has_only_create_and_read_data_actions_at_container_scope() -> None:
    role = MAIN.split('resource "azurerm_role_definition" "audit_anchor_writer"', maxsplit=1)[1].split(
        'resource "azurerm_role_assignment" "audit_anchor_writer"', maxsplit=1
    )[0]
    assignment = MAIN.split('resource "azurerm_role_assignment" "audit_anchor_writer"', maxsplit=1)[1].split(
        'resource "azurerm_private_dns_zone"', maxsplit=1
    )[0]
    assert "containers/blobs/add/action" in role
    assert "containers/blobs/read" in role
    # Azure gates create-block-blob (PUT Blob, used create-only via If-None-Match:*)
    # behind blobs/write; overwrite and delete are prevented by the container's
    # locked immutability (WORM) policy, not by withholding write.
    assert "containers/blobs/write" in role
    assert "containers/blobs/delete" not in role
    assert "runAsSuperUser" not in role
    assert "azurerm_storage_container.audit_anchor.id" in assignment
    assert 'workload["worker"].principal_id' in assignment


def test_anchor_uses_private_blob_networking_and_non_secret_worker_configuration() -> None:
    assert 'name                = "privatelink.blob.core.windows.net"' in MAIN
    endpoint = MAIN.split('resource "azurerm_private_endpoint" "audit_anchor"', maxsplit=1)[1].split(
        "locals {\n  migration_database_url", maxsplit=1
    )[0]
    assert 'subresource_names              = ["blob"]' in endpoint
    worker = MAIN.split('resource "azurerm_container_app" "worker"', maxsplit=1)[1].split(
        'resource "azurerm_role_assignment" "communication_sender"', maxsplit=1
    )[0]
    assert "KP_WORKER_AUDIT_ANCHOR_CONTAINER_URL" in worker
    assert "KP_WORKER_AUDIT_ANCHOR_CLIENT_ID" in worker
    assert "KP_WORKER_AUDIT_ANCHOR_INTERVAL_SECONDS" in worker
    assert "KP_WORKER_AUDIT_HMAC_KEY" not in worker
