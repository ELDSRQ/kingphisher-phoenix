output "resource_group_name" { value = azurerm_resource_group.main.name }
output "container_registry_name" { value = azurerm_container_registry.main.name }
output "container_registry_login_server" { value = azurerm_container_registry.main.login_server }
output "operator_default_hostname" { value = var.deploy_workloads ? azurerm_container_app.operator[0].ingress[0].fqdn : null }
output "tracking_default_hostname" { value = var.deploy_workloads ? azurerm_container_app.tracking[0].ingress[0].fqdn : null }
output "migration_job_name" { value = var.deploy_workloads ? azurerm_container_app_job.migration[0].name : null }
output "ai_gateway_internal_url" {
  description = "Internal base URL of the Qwen generation gateway. Set the reviewed ai_endpoint to this value so the worker /propose and operator /setup-assist reach it in-cluster."
  value       = var.deploy_workloads && var.deploy_ai_gateway ? "https://${azurerm_container_app.ai_gateway[0].ingress[0].fqdn}" : null
}
output "log_analytics_workspace_customer_id" {
  description = "Non-secret workspace identity used by the deployment workflow for bounded worker-readiness queries."
  value       = azurerm_log_analytics_workspace.main.workspace_id
}
output "managed_worker_health_targets" {
  description = "Exact Container App and role inventory that must report ready before a workload deployment is healthy."
  value = var.deploy_workloads ? {
    for deployment, roles in local.worker_deployment_roles : azurerm_container_app.worker[deployment].name => {
      roles = sort(tolist(roles))
    }
  } : {}
}
output "key_vault_name" { value = azurerm_key_vault.main.name }
output "key_vault_id" { value = azurerm_key_vault.main.id }
output "ciphertext_keyring" {
  description = "Non-secret keyring lifecycle metadata shared by the operator and workers."
  value = {
    active_key_id                       = trimspace(var.ciphertext_active_key_id)
    prior_key_ids                       = local.ciphertext_prior_key_ids
    prior_key_source                    = local.ciphertext_recovery_enabled ? "external_versionless_key_vault_reference" : "none"
    prior_material_exposed_to_terraform = false
  }
}
output "email_sender" { value = local.acs_sender_address }
output "acs_stage_contract" {
  description = "Non-secret Terraform enforcement state for the three-stage ACS deployment contract."
  value = {
    selected_stage                    = var.acs_deployment_stage
    binding_management_enabled        = local.acs_binding_management_enabled
    domain_live_ready                 = local.acs_domain_live_ready
    bootstrap_can_manage_binding      = false
    finalize_requires_live_readiness  = true
    workloads_require_finalized_state = true
  }
}
output "acs_control_plane_resources" {
  description = "Non-secret exact ARM identities used by the deployment workflow for live ACS readiness readback."
  value = {
    resource_group_name      = azurerm_resource_group.main.name
    communication_service_id = local.acs_communication_service_id
    email_domain_id          = local.acs_email_domain_id
    sender_username_id       = "${local.acs_email_domain_id}/senderUsernames/${lower(trimspace(var.acs_sender_local_part))}"
  }
}
output "acs_delivery_readiness" {
  description = "GUI-safe ACS setup/readiness plan. Workflow runs replace reviewed status strings with a fresh Azure control-plane readback before Terraform may act on them."
  value = {
    resource_mode       = var.acs_resource_mode
    sending_domain      = lower(trimspace(var.acs_sending_domain))
    sender_address      = local.acs_sender_address
    sender_display_name = trimspace(var.acs_sender_display_name)
    dns_status          = local.acs_provision ? (local.acs_dns_automation ? "azure_dns_records_managed_verification_pending" : "manual_dns_required") : "existing_domain_dns_external"
    dns_automation      = local.acs_dns_automation
    evidence_source     = "azure_control_plane_readback_in_deployment_workflow"
    evidence_checked_at = var.acs_readiness_checked_at
    evidence_current    = local.acs_readiness_current
    ready_for_workloads = (
      alltrue([
        for state in [var.acs_domain_verification_status, var.acs_spf_verification_status, var.acs_dkim_verification_status, var.acs_dkim2_verification_status] :
        lower(trimspace(state)) == "verified"
      ]) &&
      lower(trimspace(var.acs_sender_username_status)) == "verified" &&
      lower(trimspace(var.acs_domain_association_status)) == "verified" &&
      local.acs_readiness_current
    )
    verification = {
      domain = lower(trimspace(var.acs_domain_verification_status))
      spf    = lower(trimspace(var.acs_spf_verification_status))
      dkim   = lower(trimspace(var.acs_dkim_verification_status))
      dkim2  = lower(trimspace(var.acs_dkim2_verification_status))
      sender = local.acs_provision ? (
        local.acs_domain_live_ready ? "managed_by_verified_foundation" : "planned_after_domain_verification"
      ) : lower(trimspace(var.acs_sender_username_status))
      association = local.acs_provision ? (
        local.acs_domain_live_ready ? "managed_by_verified_foundation" : "planned_after_domain_verification"
      ) : lower(trimspace(var.acs_domain_association_status))
    }
    pacing = {
      daily_message_limit   = var.acs_daily_message_limit
      messages_per_minute   = var.acs_messages_per_minute
      ramp_batch_size       = var.acs_ramp_batch_size
      ramp_interval_seconds = var.acs_ramp_interval_seconds
    }
    dns_records = local.acs_provision ? concat(
      [for kind, record in local.acs_dns_txt_records : {
        purpose = kind
        name    = record.name
        type    = record.type
        value   = record.value
        ttl     = record.ttl
      }],
      [for kind, record in local.acs_dns_cname_records : {
        purpose = kind
        name    = record.name
        type    = record.type
        value   = record.value
        ttl     = record.ttl
      }],
    ) : []
    acceptance_semantics = "ACS send completion records provider acceptance; authenticated delivery reports separately record destination-MTA handoff or terminal failure, not inbox placement."
  }
}
output "acs_receipt_ingress" {
  description = "Non-secret ACS Event Grid receipt endpoint and authentication contract."
  value = {
    enabled           = var.deploy_workloads && var.enable_acs_event_subscription
    endpoint          = var.deploy_workloads ? "https://${azurerm_container_app.operator[0].ingress[0].fqdn}${local.acs_receipt_webhook_path}" : null
    system_topic      = var.deploy_workloads ? azurerm_eventgrid_system_topic.acs_delivery[0].name : null
    subscription_name = var.deploy_workloads && var.enable_acs_event_subscription ? local.acs_receipt_subscription_name : null
    event_type        = "Microsoft.Communication.EmailDeliveryReportReceived"
    authentication    = "Microsoft Entra bearer token plus private queue HMAC"
  }
}
output "enabled_worker_roles" {
  description = "Roles enabled inside the supervised worker topology after optional providers are resolved."
  value       = sort(tolist(local.worker_roles))
}

output "audit_anchor_readiness" {
  description = "Non-secret immutable audit-anchor configuration. Live proof is reported by the worker only after a successful create or idempotent read-back."
  value = {
    configured_for_worker = var.deploy_workloads
    static_status         = var.deploy_workloads ? "configured_unproven" : "worker_not_deployed"
    container_url         = azurerm_storage_container.audit_anchor.url
    retention_days        = local.audit_anchor_retention_days
    immutability_policy   = "locked_container_time_based_worm"
    versioning_enabled    = true
  }
}

output "microsoft_graph_identities" {
  description = "Non-secret provider identity IDs used by tenant administrators for reviewed consent."
  value = {
    for role, identity_name in local.provider_identity_names : role => {
      client_id    = azurerm_user_assigned_identity.workload[identity_name].client_id
      principal_id = azurerm_user_assigned_identity.workload[identity_name].principal_id
    }
  }
}

output "runtime_topology" {
  description = "GUI-safe deployable and replica summary for cost and topology review."
  value = {
    public_apps                 = var.deploy_workloads ? 2 : 0
    worker_apps                 = var.deploy_workloads ? length(local.worker_deployments) : 0
    continuously_running_apps   = var.deploy_workloads ? 2 + length(local.worker_deployments) : 0
    minimum_continuous_replicas = var.deploy_workloads ? (local.production ? 4 : 2) + length(local.worker_deployments) : 0
    maximum_continuous_replicas = var.deploy_workloads ? (local.production ? 30 : 6) + sum([for deployment in local.worker_deployments : deployment == "delivery" ? (local.production ? 5 : 2) : 1]) : 0
    manual_migration_jobs       = var.deploy_workloads ? 1 : 0
    delivery_isolated           = var.isolate_delivery_worker
    enabled_roles               = sort(tolist(local.worker_roles))
    worker_deployments = {
      for deployment, roles in local.worker_deployment_roles : deployment => {
        roles        = sort(tolist(roles))
        min_replicas = 1
        max_replicas = deployment == "delivery" ? (local.production ? 5 : 2) : 1
      }
    }
  }
}

output "recovery_readiness" {
  description = "GUI-safe recovery control inventory. Static controls are configuration facts; live recovery and rollback remain unproven until separate exercises produce evidence."
  value = {
    overall_status = "configured_unproven"
    postgresql = {
      backup_retention_days     = local.production ? 35 : 7
      point_in_time_restore     = "service_capability_not_exercised"
      geo_redundant_backup      = local.production
      zone_redundant_ha         = local.production
      storage_auto_grow         = true
      terraform_destroy_blocked = true
      live_restore_evidence     = "not_collected_by_terraform"
    }
    redis = {
      high_availability          = local.production
      encrypted_transport        = true
      eviction_policy            = "NoEviction"
      aof_persistence            = local.production ? "1s" : "disabled"
      access_key_stored_in_vault = true
      recovery_limit             = "AOF supports same-cache recovery only; it is not backup, export, or point-in-time restore"
      live_recovery_evidence     = "not_collected_by_terraform"
    }
    audit_witness = {
      replication               = local.production ? "GRS" : "LRS"
      blob_versioning           = true
      time_based_worm           = "locked"
      retention_days            = local.audit_anchor_retention_days
      legal_hold                = "not_configured_time_based_retention_only"
      writer_permissions        = "create_and_read_without_overwrite_or_delete"
      live_publication_evidence = "reported_by_worker_readiness_not_collected_by_terraform"
    }
    key_vault = {
      rbac_authorization         = true
      soft_delete_retention_days = local.production ? 90 : 30
      purge_protection           = local.production
      public_network_access      = local.public_data_plane
    }
    container_apps = {
      operator_revision_mode = "Multiple"
      tracking_revision_mode = "Multiple"
      traffic_policy         = "latest_revision_100_percent"
      rollback_capability    = "prior_revision_activation"
      live_rollback_evidence = "not_collected_by_terraform"
    }
    terraform_state = {
      contains_sensitive_values           = true
      backend_controls_managed_externally = true
      required_controls                   = "Azure AD authentication, encryption, private access, versioning, and tested state recovery"
    }
  }
}
