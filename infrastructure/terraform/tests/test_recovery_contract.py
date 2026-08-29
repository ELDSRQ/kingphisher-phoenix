"""Static fail-closed recovery and teardown contracts for managed Azure."""

from __future__ import annotations

from pathlib import Path

TERRAFORM_DIR = Path(__file__).resolve().parents[1]
MAIN = (TERRAFORM_DIR / "main.tf").read_text(encoding="utf-8")
OUTPUTS = (TERRAFORM_DIR / "outputs.tf").read_text(encoding="utf-8")


def _resource(name: str, next_name: str) -> str:
    return MAIN.split(name, maxsplit=1)[1].split(next_name, maxsplit=1)[0]


def test_postgresql_has_bounded_pitr_ha_and_storage_safety() -> None:
    postgres = _resource(
        'resource "azurerm_postgresql_flexible_server" "main"',
        'resource "azurerm_postgresql_flexible_server_database" "main"',
    )
    assert "backup_retention_days         = local.production ? 35 : 7" in postgres
    assert "geo_redundant_backup_enabled  = local.production" in postgres
    assert 'mode                      = "ZoneRedundant"' in postgres
    assert "auto_grow_enabled             = true" in postgres
    assert "prevent_destroy = true" in postgres


def test_redis_runtime_auth_and_production_durability_are_explicit() -> None:
    redis = _resource(
        'resource "azurerm_managed_redis" "main"',
        'resource "azurerm_storage_account" "audit_anchor"',
    )
    assert "access_keys_authentication_enabled            = true" in redis
    assert 'client_protocol                               = "Encrypted"' in redis
    assert 'eviction_policy                               = "NoEviction"' in redis
    assert 'persistence_append_only_file_backup_frequency = local.production ? "1s" : null' in redis
    assert "high_availability_enabled = local.production" in redis
    assert "primary_access_key" in MAIN
    assert "rediss://default:" in MAIN


def test_foundation_phase_does_not_grant_email_sender_role() -> None:
    sender = _resource(
        'resource "azurerm_role_assignment" "communication_sender"',
        'resource "azurerm_container_app_job" "migration"',
    )
    assert "for_each = var.deploy_workloads ? (" in sender
    assert ") : toset([])" in sender


def test_worker_recipient_salt_environment_has_one_name() -> None:
    worker = _resource(
        'resource "azurerm_container_app" "worker"',
        'resource "azurerm_role_assignment" "communication_sender"',
    )
    assert worker.count('name        = "KP_WORKER_RECIPIENT_HASH_SALT"') == 1


def test_recovery_output_distinguishes_static_controls_from_live_evidence() -> None:
    recovery = OUTPUTS.split('output "recovery_readiness"', maxsplit=1)[1]
    assert 'overall_status = "configured_unproven"' in recovery
    assert 'live_restore_evidence     = "not_collected_by_terraform"' in recovery
    assert 'live_recovery_evidence     = "not_collected_by_terraform"' in recovery
    assert 'legal_hold                = "not_configured_time_based_retention_only"' in recovery
    assert 'live_rollback_evidence = "not_collected_by_terraform"' in recovery
    assert "contains_sensitive_values" in recovery
    assert "backend_controls_managed_externally" in recovery


def test_secret_state_and_ciphertext_rotation_limits_remain_truthful() -> None:
    assert 'data "azurerm_key_vault_secret"' not in MAIN
    assert "scope                = local.ciphertext_prior_keys_secret_id" in MAIN
    assert "prevent_destroy = true" in _resource(
        'resource "random_id" "ciphertext_kek"',
        'resource "random_id" "console_jwt"',
    )
    assert "prior_material_exposed_to_terraform = false" in OUTPUTS
    assert "contains_sensitive_values           = true" in OUTPUTS
