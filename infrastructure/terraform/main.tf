data "azurerm_client_config" "current" {}

variable "acs_deployment_stage" {
  description = "Fail-closed ACS orchestration stage selected by the reviewed deployment workflow."
  type        = string
  default     = "disabled"

  validation {
    condition = contains(
      ["disabled", "foundation_bootstrap", "foundation_finalize", "workloads"],
      var.acs_deployment_stage,
    )
    error_message = "acs_deployment_stage must be disabled, foundation_bootstrap, foundation_finalize, or workloads."
  }
}

locals {
  suffix                      = "${var.name_prefix}-${var.environment}"
  production                  = var.environment == "production"
  audit_anchor_retention_days = coalesce(var.audit_anchor_retention_days, var.environment == "production" ? 365 : 1)
  tags = merge(var.tags, {
    application = "kingphisher-phoenix"
    environment = var.environment
    managed-by  = "terraform"
    tenant-mode = "single-tenant"
  })
  core_worker_roles = toset(["ingestion", "delivery", "retention", "reminder", "alert", "audit-anchor"])
  provider_worker_env = {
    generation = trimspace(var.ai_endpoint) == "" ? {} : {
      KP_WORKER_AI_BASE_URL = trimspace(var.ai_endpoint)
      KP_WORKER_AI_MODEL_ID = local.ai_model_id
    }
    directory = trimspace(var.graph_endpoint) == "" ? {} : {
      KP_WORKER_GRAPH_BASE_URL      = trimspace(var.graph_endpoint)
      KP_WORKER_GRAPH_GROUP_IDS     = trimspace(var.directory_group_ids)
      KP_WORKER_MICROSOFT_TENANT_ID = trimspace(var.entra_tenant_id)
    }
    mailbox = trimspace(var.reported_mailbox_endpoint) == "" ? {} : {
      KP_WORKER_REPORTED_MAILBOX_URL       = trimspace(var.reported_mailbox_endpoint)
      KP_WORKER_REPORTED_MAILBOX_PROVIDER  = "microsoft365"
      KP_WORKER_REPORTED_MAILBOX_ID        = trimspace(var.reported_mailbox_address)
      KP_WORKER_REPORTED_MAILBOX_FOLDER_ID = trimspace(var.reported_mailbox_folder)
      KP_WORKER_MICROSOFT_TENANT_ID        = trimspace(var.entra_tenant_id)
    }
  }
  provider_worker_roles = toset([
    for role, environment in local.provider_worker_env : role if length(environment) > 0
  ])
  worker_roles = setunion(local.core_worker_roles, local.provider_worker_roles)
  worker_deployment_roles = merge(
    {
      worker = var.isolate_delivery_worker ? setsubtract(local.worker_roles, toset(["delivery"])) : local.worker_roles
    },
    var.isolate_delivery_worker ? { delivery = toset(["delivery"]) } : {},
  )
  worker_deployments = toset(keys(local.worker_deployment_roles))
  provider_identity_roles = setintersection(
    local.provider_worker_roles,
    toset(["directory", "mailbox"]),
  )
  provider_identity_names = {
    for role in local.provider_identity_roles : role => "provider-${role}"
  }
  workload_identities = setunion(
    toset(["operator", "tracking", "migration", "ai-gateway"]),
    local.worker_deployments,
    toset(values(local.provider_identity_names)),
  )
  image_pull_identities = setunion(
    toset(["operator", "tracking", "migration", "ai-gateway"]),
    local.worker_deployments,
  )
  runtime_database_roles = merge(
    {
      operator = "kp_operator"
      tracking = "kp_tracking"
    },
    {
      for role in local.worker_roles : role => "kp_worker_${replace(role, "-", "_")}"
    },
  )
  runtime_database_secret_names = merge(
    {
      operator = "operator-database-url"
      tracking = "tracking-database-url"
    },
    {
      for role in local.worker_roles : role => "worker-${role}-database-url"
    },
  )

  # Bake-off-selected model identity the generation worker pins; kept identical
  # to the ai-gateway's KP_AI_GATEWAY_MODEL_ID. Isolated on its own line so it
  # does not join the tracking/training alignment group the contract test pins.
  ai_model_id = "llama.cpp/Qwen2.5-7B-Instruct-Q4_K_M"

  tracking_base_url             = "https://${lower(trimspace(var.tracking_fqdn))}"
  training_base_url             = "${local.tracking_base_url}/v1/training/awareness"
  acs_receipt_subscription_name = "acs-delivery-receipts"
  acs_receipt_webhook_path      = "/api/v1/integrations/acs/events"
  acs_provision                 = var.acs_resource_mode == "provision"
  acs_dns_automation            = local.acs_provision && trimspace(var.acs_dns_zone_id) != ""
  acs_dns_zone_parts            = split("/", trimspace(var.acs_dns_zone_id))
  acs_dns_zone_name             = local.acs_dns_automation ? lower(try(local.acs_dns_zone_parts[8], "")) : ""
  acs_dns_zone_rg               = local.acs_dns_automation ? try(local.acs_dns_zone_parts[4], "") : ""
  acs_readiness_current = try(
    timecmp(var.acs_readiness_checked_at, timeadd(plantimestamp(), "-${var.acs_readiness_max_age_hours}h")) >= 0 &&
    timecmp(var.acs_readiness_checked_at, timeadd(plantimestamp(), "5m")) <= 0,
    false,
  )
  acs_domain_live_ready = alltrue([
    for state in [var.acs_domain_verification_status, var.acs_spf_verification_status, var.acs_dkim_verification_status, var.acs_dkim2_verification_status] :
    lower(trimspace(state)) == "verified"
  ]) && local.acs_readiness_current
  acs_binding_management_enabled = contains(
    ["foundation_finalize", "workloads"],
    var.acs_deployment_stage,
  )
  deployment_orchestration_enabled = var.deployment_orchestration_mode == "github_actions"
  ciphertext_prior_key_ids = trimspace(var.ciphertext_prior_key_ids) == "" ? [] : [
    for key_id in split(",", var.ciphertext_prior_key_ids) : trimspace(key_id)
  ]
  ciphertext_recovery_enabled     = length(local.ciphertext_prior_key_ids) > 0
  ciphertext_prior_keys_secret_id = trimspace(var.ciphertext_prior_keys_secret_id)
  ciphertext_prior_secret_parts   = split("/", local.ciphertext_prior_keys_secret_id)
  ciphertext_prior_secret_name    = try(local.ciphertext_prior_secret_parts[10], "")
  ciphertext_prior_keys_versionless_uri = local.ciphertext_recovery_enabled ? (
    "${trimsuffix(azurerm_key_vault.main.vault_uri, "/")}/secrets/${local.ciphertext_prior_secret_name}"
  ) : ""
  deployment_github_token_secret_parts = split("/", trimspace(var.deployment_github_token_secret_id))
  deployment_github_token_secret_name  = try(local.deployment_github_token_secret_parts[10], "")
  deployment_github_token_versionless_uri = local.deployment_orchestration_enabled ? (
    "${trimsuffix(azurerm_key_vault.main.vault_uri, "/")}/secrets/${local.deployment_github_token_secret_name}"
  ) : ""

  # Starter mode trades network isolation for hosted-runner bring-up in a new
  # tenant. Private endpoints and their DNS zones are skipped entirely, and the
  # data-plane services accept public traffic so a GitHub-hosted runner can
  # reach them. Everything else (managed identity, Key Vault references, TLS,
  # RBAC) is identical between modes.
  starter_network   = var.network_mode == "starter"
  private_network   = !local.starter_network
  public_data_plane = local.starter_network
}

# A starter-mode production environment would put real recipient data behind
# public endpoints. Fail the plan rather than let that happen quietly.
resource "terraform_data" "network_mode_guard" {
  lifecycle {
    precondition {
      condition     = !(local.production && local.starter_network) || var.allow_starter_in_production
      error_message = "network_mode=\"starter\" exposes Postgres, Redis, Key Vault and the registry to the public internet and must not be used for production. Use network_mode=\"private\", or set allow_starter_in_production=true if this is a deliberate, understood exception."
    }
  }
}

resource "terraform_data" "workload_config_guard" {
  lifecycle {
    precondition {
      condition = !var.deploy_workloads || alltrue([
        for image in [var.operator_image, var.tracking_image, var.worker_image, var.migration_image] :
        trimspace(image) != "" && !startswith(image, "bootstrap.invalid/")
      ])
      error_message = "deploy_workloads=true requires immutable, published operator, tracking, worker, and migration images; bootstrap.invalid placeholders cannot be deployed."
    }
    precondition {
      condition = !(var.deploy_workloads && var.deploy_ai_gateway) || alltrue([
        for image in [var.ai_gateway_image, var.ai_llama_image] :
        trimspace(image) != "" && !startswith(image, "bootstrap.invalid/")
      ])
      error_message = "deploy_ai_gateway=true requires immutable, published ai_gateway_image and ai_llama_image; bootstrap.invalid placeholders cannot be deployed."
    }
    precondition {
      condition     = !var.deploy_ci_runner || trimspace(var.ci_runner_registration_token) != ""
      error_message = "deploy_ci_runner=true requires ci_runner_registration_token (a fresh GitHub Actions runner registration token, supplied at apply time)."
    }
    precondition {
      condition     = !var.deploy_workloads || lower(trimspace(var.operator_fqdn)) != lower(trimspace(var.tracking_fqdn))
      error_message = "operator_fqdn and tracking_fqdn must be different so the public tracking boundary remains isolated from the operator console."
    }
    precondition {
      condition     = trimspace(var.graph_endpoint) == "" || trimspace(var.directory_group_ids) != ""
      error_message = "directory_group_ids is required when native Microsoft Graph directory synchronization is enabled."
    }
    precondition {
      condition     = trimspace(var.reported_mailbox_endpoint) == "" || trimspace(var.reported_mailbox_address) != ""
      error_message = "reported_mailbox_address is required when Microsoft 365 report ingestion is enabled."
    }
    precondition {
      condition = local.acs_provision || (
        can(regex("/providers/Microsoft.Communication/CommunicationServices/[^/]+$", var.acs_existing_communication_service_id)) &&
        trimspace(var.acs_existing_email_endpoint) != "" &&
        can(regex("/providers/Microsoft.Communication/emailServices/[^/]+/domains/[^/]+$", var.acs_existing_email_domain_id))
      )
      error_message = "acs_resource_mode=existing requires complete Communication Service and email-domain resource IDs plus the non-secret HTTPS email endpoint."
    }
    precondition {
      condition = !local.acs_dns_automation || (
        can(regex("^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft.Network/dnszones/[^/]+$", var.acs_dns_zone_id)) &&
        lower(try(local.acs_dns_zone_parts[2], "")) == lower(var.subscription_id) &&
        (lower(trimspace(var.acs_sending_domain)) == local.acs_dns_zone_name || endswith(lower(trimspace(var.acs_sending_domain)), ".${local.acs_dns_zone_name}"))
      )
      error_message = "acs_dns_zone_id must identify a same-subscription public Azure DNS zone containing acs_sending_domain."
    }
    precondition {
      condition = !var.deploy_workloads || (
        local.acs_domain_live_ready &&
        lower(trimspace(var.acs_sender_username_status)) == "verified" &&
        lower(trimspace(var.acs_domain_association_status)) == "verified"
      )
      error_message = "managed delivery is blocked until the deployment workflow reads back Domain, SPF, DKIM and DKIM2 as Verified, the exact sender username and domain association are live, and the control-plane observation is current."
    }
    precondition {
      condition = (
        var.acs_messages_per_minute <= var.acs_daily_message_limit &&
        var.acs_ramp_batch_size <= var.acs_messages_per_minute
      )
      error_message = "ACS pacing must keep the per-minute limit within the daily quota and ramp batch within the per-minute limit."
    }
    precondition {
      condition = !var.deploy_workloads || !local.deployment_orchestration_enabled || (
        can(regex("^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$", trimspace(var.deployment_github_repository))) &&
        can(regex("^[A-Za-z0-9._/-]{1,255}$", trimspace(var.deployment_github_ref))) &&
        !startswith(trimspace(var.deployment_github_ref), "/") &&
        !strcontains(trimspace(var.deployment_github_ref), "..") &&
        startswith(
          lower(trimspace(var.deployment_github_token_secret_id)),
          "${lower(azurerm_key_vault.main.id)}/secrets/"
        ) &&
        can(regex("/secrets/[A-Za-z0-9-]+$", trimspace(var.deployment_github_token_secret_id)))
      )
      error_message = "enabled GUI deployment orchestration requires a fixed repository/ref and a versionless token secret ID in this deployment's Key Vault."
    }
    precondition {
      condition = (
        !contains(local.ciphertext_prior_key_ids, trimspace(var.ciphertext_active_key_id)) &&
        (
          local.ciphertext_recovery_enabled ? (
            var.deploy_workloads &&
            startswith(
              lower(local.ciphertext_prior_keys_secret_id),
              "${lower(azurerm_key_vault.main.id)}/secrets/"
            ) &&
            can(regex("/secrets/[A-Za-z0-9-]+$", local.ciphertext_prior_keys_secret_id))
          ) : local.ciphertext_prior_keys_secret_id == ""
        )
      )
      error_message = "ciphertext recovery requires distinct active/prior key IDs and a versionless prior-key secret in this deployment's Key Vault; foundation plans cannot add recovery keys."
    }
  }
}

resource "azurerm_resource_group" "main" {
  name     = "rg-${local.suffix}"
  location = var.location
  tags     = local.tags
}

resource "azurerm_virtual_network" "main" {
  name                = "vnet-${local.suffix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  address_space       = ["10.42.0.0/16"]
  tags                = local.tags
}

resource "azurerm_subnet" "container_apps" {
  name                 = "snet-container-apps"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.42.0.0/23"]
  service_endpoint {
    service = "Microsoft.Storage"
  }
  delegation {
    name = "container-apps"
    service_delegation {
      name = "Microsoft.App/environments"
    }
  }
}

locals {
  # The public tracking service accepts X-Forwarded-For only from the exact
  # Container Apps infrastructure network or its in-pod loopback proxy. The
  # application validates these as bounded canonical CIDRs and owns proxy
  # parsing instead of delegating it to ambient uvicorn configuration.
  tracking_trusted_proxy_networks = sort(concat(
    azurerm_subnet.container_apps.address_prefixes,
    ["127.0.0.1/32", "::1/128"],
  ))
  tracking_trusted_proxies = join(",", local.tracking_trusted_proxy_networks)
}

resource "azurerm_subnet" "private_endpoints" {
  name                              = "snet-private-endpoints"
  resource_group_name               = azurerm_resource_group.main.name
  virtual_network_name              = azurerm_virtual_network.main.name
  address_prefixes                  = ["10.42.2.0/24"]
  private_endpoint_network_policies = "Disabled"
}

# --- Self-hosted GitHub Actions runner inside the VNet -----------------------
# Required before any private-mode deploy: the private data plane is unreachable
# from a hosted runner. Created from a starter-mode bootstrap, then used for the
# private bootstrap and workloads. No inbound; outbound to GitHub via a NAT
# gateway. Gated by deploy_ci_runner so it is absent from normal deploys.
locals {
  ci_runner = var.deploy_ci_runner ? 1 : 0
}

resource "azurerm_subnet" "ci_runner" {
  count                = local.ci_runner
  name                 = "snet-ci-runner"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.42.3.0/24"]
}

resource "azurerm_public_ip" "ci_runner_nat" {
  count               = local.ci_runner
  name                = "pip-${local.suffix}-runner-nat"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.tags
}

resource "azurerm_nat_gateway" "ci_runner" {
  count               = local.ci_runner
  name                = "nat-${local.suffix}-runner"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku_name            = "Standard"
  tags                = local.tags
}

resource "azurerm_nat_gateway_public_ip_association" "ci_runner" {
  count                = local.ci_runner
  nat_gateway_id       = azurerm_nat_gateway.ci_runner[0].id
  public_ip_address_id = azurerm_public_ip.ci_runner_nat[0].id
}

resource "azurerm_subnet_nat_gateway_association" "ci_runner" {
  count          = local.ci_runner
  subnet_id      = azurerm_subnet.ci_runner[0].id
  nat_gateway_id = azurerm_nat_gateway.ci_runner[0].id
}

resource "azurerm_network_security_group" "ci_runner" {
  count               = local.ci_runner
  name                = "nsg-${local.suffix}-runner"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  security_rule {
    name                       = "DenyAllInbound"
    priority                   = 4000
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  tags = local.tags
}

resource "azurerm_subnet_network_security_group_association" "ci_runner" {
  count                     = local.ci_runner
  subnet_id                 = azurerm_subnet.ci_runner[0].id
  network_security_group_id = azurerm_network_security_group.ci_runner[0].id
}

resource "azurerm_network_interface" "ci_runner" {
  count               = local.ci_runner
  name                = "nic-${local.suffix}-runner"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.ci_runner[0].id
    private_ip_address_allocation = "Dynamic"
  }
  tags = local.tags
}

resource "random_password" "ci_runner" {
  count            = local.ci_runner
  length           = 32
  special          = true
  override_special = "!@#%*-_=+"
  min_lower        = 2
  min_upper        = 2
  min_numeric      = 2
  min_special      = 2
}

resource "azurerm_linux_virtual_machine" "ci_runner" {
  count                 = local.ci_runner
  name                  = "vm-${local.suffix}-runner"
  location              = azurerm_resource_group.main.location
  resource_group_name   = azurerm_resource_group.main.name
  size                  = var.ci_runner_vm_size
  admin_username        = "runner"
  admin_password        = random_password.ci_runner[0].result
  network_interface_ids = [azurerm_network_interface.ci_runner[0].id]
  # No inbound reaches this VM (NSG denies it, no public IP); password auth is
  # acceptable and avoids provisioning an unused SSH key/provider.
  disable_password_authentication = false
  identity {
    type = "SystemAssigned"
  }
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }
  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }
  custom_data = base64encode(templatefile("${path.module}/ci-runner-cloud-init.yaml.tftpl", {
    repository_url     = var.ci_runner_repository_url
    registration_token = var.ci_runner_registration_token
    runner_name        = "vm-${local.suffix}-runner"
    runner_labels      = "self-hosted,linux,azure-vnet"
  }))
  tags = local.tags
  # The token in custom_data is short-lived and only used at first boot; ignore
  # it (and image "latest" drift) so a fresh token on a later run does not force
  # a replacement of the in-use runner, which the create/update-only guard would
  # block anyway.
  lifecycle {
    ignore_changes = [custom_data, source_image_reference]
  }
}

resource "azurerm_log_analytics_workspace" "main" {
  name                = "log-${local.suffix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days
  daily_quota_gb      = var.log_daily_quota_gb
  tags                = local.tags
}

resource "azurerm_application_insights" "main" {
  name                = "appi-${local.suffix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  workspace_id        = azurerm_log_analytics_workspace.main.id
  application_type    = "web"
  tags                = local.tags
}

resource "azurerm_communication_service" "main" {
  count               = local.acs_provision ? 1 : 0
  name                = "acs-${local.suffix}-${random_string.unique.result}"
  resource_group_name = azurerm_resource_group.main.name
  data_location       = var.communication_data_location
  tags                = local.tags
}

resource "azurerm_email_communication_service" "main" {
  count               = local.acs_provision ? 1 : 0
  name                = "email-${local.suffix}-${random_string.unique.result}"
  resource_group_name = azurerm_resource_group.main.name
  data_location       = var.communication_data_location
  tags                = local.tags
}

resource "azurerm_email_communication_service_domain" "main" {
  count                            = local.acs_provision ? 1 : 0
  name                             = lower(trimspace(var.acs_sending_domain))
  email_service_id                 = azurerm_email_communication_service.main[0].id
  domain_management                = "CustomerManaged"
  user_engagement_tracking_enabled = false
  tags                             = local.tags
}

locals {
  acs_communication_service_id = local.acs_provision ? azurerm_communication_service.main[0].id : trimspace(var.acs_existing_communication_service_id)
  acs_email_endpoint           = local.acs_provision ? "https://${azurerm_communication_service.main[0].hostname}" : trimsuffix(trimspace(var.acs_existing_email_endpoint), "/")
  acs_email_domain_id          = local.acs_provision ? azurerm_email_communication_service_domain.main[0].id : trimspace(var.acs_existing_email_domain_id)
  acs_sender_address           = "${lower(trimspace(var.acs_sender_local_part))}@${lower(trimspace(var.acs_sending_domain))}"
  acs_verification_records     = local.acs_provision ? azurerm_email_communication_service_domain.main[0].verification_records[0] : null
  acs_dns_txt_records = local.acs_provision ? {
    domain = local.acs_verification_records.domain[0]
    spf    = local.acs_verification_records.spf[0]
  } : {}
  acs_dns_cname_records = local.acs_provision ? {
    dkim  = local.acs_verification_records.dkim[0]
    dkim2 = local.acs_verification_records.dkim2[0]
  } : {}
}

resource "azurerm_communication_service_email_domain_association" "main" {
  # Bootstrap can never manage this link, even if a domain was already
  # verified. Only the explicit finalize/workloads stages may enable it after
  # the workflow has replaced reviewed status strings with fresh Azure state.
  count = (
    local.acs_provision && local.acs_binding_management_enabled && local.acs_domain_live_ready ? 1 : 0
  )
  communication_service_id = local.acs_communication_service_id
  email_service_domain_id  = local.acs_email_domain_id

  lifecycle {
    prevent_destroy = true
  }
}

resource "azurerm_email_communication_service_domain_sender_username" "main" {
  count = (
    local.acs_provision && local.acs_binding_management_enabled && local.acs_domain_live_ready ? 1 : 0
  )
  name                    = lower(trimspace(var.acs_sender_local_part))
  email_service_domain_id = local.acs_email_domain_id
  display_name            = trimspace(var.acs_sender_display_name)

  lifecycle {
    prevent_destroy = true
  }
}

resource "azurerm_eventgrid_system_topic" "acs_delivery" {
  count               = var.deploy_workloads ? 1 : 0
  name                = "evgt-${local.suffix}-acs-delivery"
  location            = "Global"
  resource_group_name = azurerm_resource_group.main.name
  source_resource_id  = local.acs_communication_service_id
  topic_type          = "Microsoft.Communication.CommunicationServices"
  tags                = local.tags
}

resource "azurerm_eventgrid_system_topic_event_subscription" "acs_delivery" {
  count                 = var.deploy_workloads && var.enable_acs_event_subscription ? 1 : 0
  name                  = local.acs_receipt_subscription_name
  system_topic          = azurerm_eventgrid_system_topic.acs_delivery[0].name
  resource_group_name   = azurerm_resource_group.main.name
  event_delivery_schema = "EventGridSchema"
  included_event_types = [
    "Microsoft.Communication.EmailDeliveryReportReceived",
  ]

  webhook_endpoint {
    url                               = "https://${azurerm_container_app.operator[0].ingress[0].fqdn}${local.acs_receipt_webhook_path}"
    max_events_per_batch              = 64
    preferred_batch_size_in_kilobytes = 256
    active_directory_tenant_id        = var.entra_tenant_id
    active_directory_app_id_or_uri    = var.entra_client_id
  }

  retry_policy {
    event_time_to_live    = 1440
    max_delivery_attempts = 30
  }
}

resource "azurerm_dns_txt_record" "acs_verification" {
  for_each = local.acs_dns_automation ? local.acs_dns_txt_records : {}

  name = lower(each.value.name) == local.acs_dns_zone_name ? "@" : trimsuffix(
    lower(each.value.name),
    ".${local.acs_dns_zone_name}",
  )
  zone_name           = local.acs_dns_zone_name
  resource_group_name = local.acs_dns_zone_rg
  ttl                 = each.value.ttl
  record {
    value = each.value.value
  }
  tags = local.tags
}

resource "azurerm_dns_cname_record" "acs_verification" {
  for_each = local.acs_dns_automation ? local.acs_dns_cname_records : {}

  name = lower(each.value.name) == local.acs_dns_zone_name ? "@" : trimsuffix(
    lower(each.value.name),
    ".${local.acs_dns_zone_name}",
  )
  zone_name           = local.acs_dns_zone_name
  resource_group_name = local.acs_dns_zone_rg
  ttl                 = each.value.ttl
  record              = trimsuffix(each.value.value, ".")
  tags                = local.tags
}

resource "azurerm_container_registry" "main" {
  name                          = replace("acr${local.suffix}", "-", "")
  resource_group_name           = azurerm_resource_group.main.name
  location                      = azurerm_resource_group.main.location
  sku                           = "Premium"
  admin_enabled                 = false
  public_network_access_enabled = local.public_data_plane
  zone_redundancy_enabled       = local.production
  retention_policy_in_days      = 30
  tags                          = local.tags
}

resource "azurerm_user_assigned_identity" "workload" {
  for_each            = local.workload_identities
  name                = "id-${local.suffix}-${each.key}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags
}

resource "azurerm_role_assignment" "acr_pull" {
  for_each             = local.image_pull_identities
  scope                = azurerm_container_registry.main.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_user_assigned_identity.workload[each.key].principal_id
}

resource "azurerm_key_vault" "main" {
  name                          = substr(replace("kv-${local.suffix}-${random_string.unique.result}", "-", ""), 0, 24)
  location                      = azurerm_resource_group.main.location
  resource_group_name           = azurerm_resource_group.main.name
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "standard"
  rbac_authorization_enabled    = true
  purge_protection_enabled      = local.production
  soft_delete_retention_days    = local.production ? 90 : 30
  public_network_access_enabled = local.public_data_plane
  network_acls {
    bypass         = "AzureServices"
    default_action = local.public_data_plane ? "Allow" : "Deny"
  }
  tags = local.tags
}

resource "random_string" "unique" {
  length  = 5
  upper   = false
  special = false
}

resource "random_password" "postgres" {
  length  = 40
  special = false
}
resource "random_password" "audit" {
  length  = 40
  special = false
}
resource "random_password" "runtime_database" {
  for_each = local.runtime_database_roles
  length   = 40
  special  = false
}
resource "random_password" "console" {
  length  = 40
  special = false
}
resource "random_id" "audit_hmac" { byte_length = 32 }
resource "random_id" "ciphertext_kek" {
  byte_length = 32
  keepers = {
    active_key_id = trimspace(var.ciphertext_active_key_id)
  }
  lifecycle {
    # Independent Container Apps cannot atomically promote a new key ID. Block
    # replacement until every old revision can be proven to know a staged
    # future key before any new revision writes with it.
    prevent_destroy = true
  }
}
resource "random_id" "console_jwt" { byte_length = 32 }
resource "random_id" "recipient_salt" { byte_length = 32 }
resource "random_id" "tracking_token_hmac" { byte_length = 32 }
resource "random_id" "training_token_hmac" { byte_length = 32 }
resource "random_id" "roe_signing" { byte_length = 32 }
resource "random_id" "domain_verification" { byte_length = 32 }
resource "random_id" "acs_receipt_signing" { byte_length = 32 }
resource "random_id" "awareness_pseudonym" {
  byte_length = 32
  keepers = {
    key_version = trimspace(var.awareness_pseudonym_key_version)
  }
  lifecycle {
    # Retained ledger rows require stable pseudonyms. Rotation needs a reviewed
    # re-projection/recovery procedure before this key may be replaced.
    prevent_destroy = true
  }
}

resource "azurerm_role_assignment" "deployer_secrets" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_postgresql_flexible_server" "main" {
  name                          = "psql-${local.suffix}-${random_string.unique.result}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = azurerm_resource_group.main.location
  version                       = "16"
  administrator_login           = "kpadmin"
  administrator_password        = random_password.postgres.result
  sku_name                      = var.postgres_sku
  storage_mb                    = var.postgres_storage_mb
  auto_grow_enabled             = true
  backup_retention_days         = local.production ? 35 : 7
  geo_redundant_backup_enabled  = local.production
  public_network_access_enabled = local.public_data_plane
  zone                          = "1"
  dynamic "high_availability" {
    for_each = local.production ? [1] : []
    content {
      mode                      = "ZoneRedundant"
      standby_availability_zone = "2"
    }
  }
  lifecycle { prevent_destroy = true }
  tags = local.tags
}

resource "azurerm_postgresql_flexible_server_database" "main" {
  name      = "kingphisher"
  server_id = azurerm_postgresql_flexible_server.main.id
  collation = "en_US.utf8"
  charset   = "UTF8"
}

# Azure Database for PostgreSQL Flexible Server refuses CREATE EXTENSION unless
# the extension is allow-listed here. Migration 0020 creates pgcrypto; this is a
# dynamic parameter, so the allowlist takes effect without a server restart.
resource "azurerm_postgresql_flexible_server_configuration" "extensions" {
  name      = "azure.extensions"
  server_id = azurerm_postgresql_flexible_server.main.id
  value     = "PGCRYPTO"
}

resource "azurerm_managed_redis" "main" {
  name                      = "redis-${local.suffix}-${random_string.unique.result}"
  resource_group_name       = azurerm_resource_group.main.name
  location                  = azurerm_resource_group.main.location
  sku_name                  = var.redis_sku
  high_availability_enabled = local.production
  public_network_access     = local.public_data_plane ? "Enabled" : "Disabled"
  default_database {
    # Runtime clients currently authenticate with the generated access key held
    # in Key Vault. AzureRM defaults this setting to false, in which case the
    # primary_access_key used by local.redis_url is not exported at all.
    access_keys_authentication_enabled            = true
    client_protocol                               = "Encrypted"
    clustering_policy                             = "OSSCluster"
    eviction_policy                               = "NoEviction"
    persistence_append_only_file_backup_frequency = local.production ? "1s" : null
  }
  tags = local.tags
}

# A separate account keeps the external audit witness outside the mutable
# application database. Shared keys are disabled: the worker can authenticate
# only as its managed identity and receives create/read data actions below.
resource "azurerm_storage_account" "audit_anchor" {
  name                              = substr(replace("st${local.suffix}audit${random_string.unique.result}", "-", ""), 0, 24)
  resource_group_name               = azurerm_resource_group.main.name
  location                          = azurerm_resource_group.main.location
  account_tier                      = "Standard"
  account_replication_type          = local.production ? "GRS" : "LRS"
  account_kind                      = "StorageV2"
  min_tls_version                   = "TLS1_2"
  https_traffic_only_enabled        = true
  shared_access_key_enabled         = false
  default_to_oauth_authentication   = true
  public_network_access_enabled     = local.public_data_plane
  allow_nested_items_to_be_public   = false
  cross_tenant_replication_enabled  = false
  infrastructure_encryption_enabled = true
  blob_properties {
    versioning_enabled = true
  }
  network_rules {
    default_action             = "Deny"
    bypass                     = ["AzureServices"]
    virtual_network_subnet_ids = [azurerm_subnet.container_apps.id]
  }
  tags = local.tags
}

resource "azurerm_storage_container" "audit_anchor" {
  name                  = "audit-head-anchors"
  storage_account_id    = azurerm_storage_account.audit_anchor.id
  container_access_type = "private"
}

# A locked container policy is irreversible: blobs and the container cannot be
# modified or deleted before retention expires. This is intentional for an
# external audit witness, including non-production deployments.
resource "azurerm_storage_container_immutability_policy" "audit_anchor" {
  storage_container_resource_manager_id = azurerm_storage_container.audit_anchor.id
  immutability_period_in_days           = local.audit_anchor_retention_days
  locked                                = true
  protected_append_writes_enabled       = false
  protected_append_writes_all_enabled   = false
}

resource "azurerm_role_definition" "audit_anchor_writer" {
  name        = "kp-audit-anchor-${local.suffix}-${random_string.unique.result}"
  scope       = azurerm_resource_group.main.id
  description = "Create and compare immutable audit head anchors; overwrite/delete are blocked by the container's locked immutability policy, not by omitting write."
  permissions {
    actions     = []
    not_actions = []
    # Azure gates create-block-blob (PUT Blob, used with If-None-Match:* for
    # create-only anchors) behind blobs/write, not blobs/add/action; the latter
    # only covers append operations. The container's locked immutability policy
    # is what actually prevents overwrite and delete.
    data_actions = [
      "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
      "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action",
      "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
    ]
    not_data_actions = []
  }
  assignable_scopes = [azurerm_resource_group.main.id]
}

resource "azurerm_role_assignment" "audit_anchor_writer" {
  scope              = azurerm_storage_container.audit_anchor.id
  role_definition_id = azurerm_role_definition.audit_anchor_writer.role_definition_resource_id
  principal_id       = azurerm_user_assigned_identity.workload["worker"].principal_id
}

resource "azurerm_private_dns_zone" "postgres" {
  count               = local.private_network ? 1 : 0
  name                = "privatelink.postgres.database.azure.com"
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags
}

resource "azurerm_private_dns_zone" "redis" {
  count               = local.private_network ? 1 : 0
  name                = "privatelink.redis.azure.net"
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags
}

resource "azurerm_private_dns_zone" "vault" {
  count               = local.private_network ? 1 : 0
  name                = "privatelink.vaultcore.azure.net"
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags
}

resource "azurerm_private_dns_zone" "acr" {
  count               = local.private_network ? 1 : 0
  name                = "privatelink.azurecr.io"
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags
}

resource "azurerm_private_dns_zone" "blob" {
  count               = local.private_network ? 1 : 0
  name                = "privatelink.blob.core.windows.net"
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "links" {
  for_each = local.private_network ? {
    postgres = azurerm_private_dns_zone.postgres[0].id
    redis    = azurerm_private_dns_zone.redis[0].id
    vault    = azurerm_private_dns_zone.vault[0].id
    acr      = azurerm_private_dns_zone.acr[0].id
    blob     = azurerm_private_dns_zone.blob[0].id
  } : {}
  name                = "${each.key}-vnet-link"
  private_dns_zone_id = each.value
  virtual_network_id  = azurerm_virtual_network.main.id
}

resource "azurerm_private_endpoint" "postgres" {
  count               = local.private_network ? 1 : 0
  name                = "pep-${local.suffix}-postgres"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  subnet_id           = azurerm_subnet.private_endpoints.id
  private_service_connection {
    name                           = "postgres"
    private_connection_resource_id = azurerm_postgresql_flexible_server.main.id
    subresource_names              = ["postgresqlServer"]
    is_manual_connection           = false
  }
  private_dns_zone_group {
    name                 = "postgres"
    private_dns_zone_ids = [azurerm_private_dns_zone.postgres[0].id]
  }
  tags = local.tags
}

resource "azurerm_private_endpoint" "redis" {
  count               = local.private_network ? 1 : 0
  name                = "pep-${local.suffix}-redis"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  subnet_id           = azurerm_subnet.private_endpoints.id
  private_service_connection {
    name                           = "redis"
    private_connection_resource_id = azurerm_managed_redis.main.id
    subresource_names              = ["redisEnterprise"]
    is_manual_connection           = false
  }
  private_dns_zone_group {
    name                 = "redis"
    private_dns_zone_ids = [azurerm_private_dns_zone.redis[0].id]
  }
  tags = local.tags
}

resource "azurerm_private_endpoint" "vault" {
  count               = local.private_network ? 1 : 0
  name                = "pep-${local.suffix}-vault"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  subnet_id           = azurerm_subnet.private_endpoints.id
  private_service_connection {
    name                           = "vault"
    private_connection_resource_id = azurerm_key_vault.main.id
    subresource_names              = ["vault"]
    is_manual_connection           = false
  }
  private_dns_zone_group {
    name                 = "vault"
    private_dns_zone_ids = [azurerm_private_dns_zone.vault[0].id]
  }
  tags = local.tags
}

resource "azurerm_private_endpoint" "acr" {
  count               = local.private_network ? 1 : 0
  name                = "pep-${local.suffix}-acr"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  subnet_id           = azurerm_subnet.private_endpoints.id
  private_service_connection {
    name                           = "acr"
    private_connection_resource_id = azurerm_container_registry.main.id
    subresource_names              = ["registry"]
    is_manual_connection           = false
  }
  private_dns_zone_group {
    name                 = "acr"
    private_dns_zone_ids = [azurerm_private_dns_zone.acr[0].id]
  }
  tags = local.tags
}

resource "azurerm_private_endpoint" "audit_anchor" {
  count               = local.private_network ? 1 : 0
  name                = "pep-${local.suffix}-audit-anchor"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  subnet_id           = azurerm_subnet.private_endpoints.id
  private_service_connection {
    name                           = "audit-anchor"
    private_connection_resource_id = azurerm_storage_account.audit_anchor.id
    subresource_names              = ["blob"]
    is_manual_connection           = false
  }
  private_dns_zone_group {
    name                 = "blob"
    private_dns_zone_ids = [azurerm_private_dns_zone.blob[0].id]
  }
  tags = local.tags
}

locals {
  migration_database_url = "postgresql+psycopg://kpadmin:${urlencode(random_password.postgres.result)}@${azurerm_postgresql_flexible_server.main.fqdn}:5432/kingphisher?sslmode=require"
  audit_database_url     = "postgresql+psycopg://audit_writer:${urlencode(random_password.audit.result)}@${azurerm_postgresql_flexible_server.main.fqdn}:5432/kingphisher?sslmode=require"
  runtime_database_urls = {
    for workload, role_name in local.runtime_database_roles : workload =>
    "postgresql+psycopg://${role_name}:${urlencode(random_password.runtime_database[workload].result)}@${azurerm_postgresql_flexible_server.main.fqdn}:5432/kingphisher?sslmode=require"
  }
  redis_url = "rediss://default:${urlencode(azurerm_managed_redis.main.default_database[0].primary_access_key)}@${azurerm_managed_redis.main.hostname}:10000/0"
  secret_values = merge({
    migration-database-url  = local.migration_database_url
    audit-database-url      = local.audit_database_url
    redis-url               = local.redis_url
    audit-password          = random_password.audit.result
    audit-hmac              = random_id.audit_hmac.hex
    ciphertext-kek          = random_id.ciphertext_kek.hex
    console-jwt             = random_id.console_jwt.hex
    console-password        = random_password.console.result
    recipient-salt          = random_id.recipient_salt.hex
    tracking-token-hmac     = random_id.tracking_token_hmac.hex
    training-token-hmac     = random_id.training_token_hmac.hex
    roe-signing-key         = random_id.roe_signing.hex
    domain-verify-key       = random_id.domain_verification.hex
    acs-receipt-signing-key = random_id.acs_receipt_signing.hex
    awareness-pseudonym-key = random_id.awareness_pseudonym.hex
    },
    {
      for workload, secret_name in local.runtime_database_secret_names :
      secret_name => local.runtime_database_urls[workload]
    },
    {
      for workload, password in random_password.runtime_database :
      "db-password-${workload}" => password.result
    }
  )
}

resource "azurerm_key_vault_secret" "runtime" {
  for_each     = local.secret_values
  name         = each.key
  value        = each.value
  key_vault_id = azurerm_key_vault.main.id
  depends_on   = [azurerm_role_assignment.deployer_secrets, azurerm_private_endpoint.vault]
}

locals {
  workload_secret_names = merge(
    {
      operator = toset([
        "operator-database-url",
        "audit-database-url",
        "redis-url",
        "ciphertext-kek",
        "recipient-salt",
        "console-jwt",
        "console-password",
        "roe-signing-key",
        "domain-verify-key",
        "tracking-token-hmac",
        "training-token-hmac",
        "acs-receipt-signing-key",
      ])
      tracking = toset([
        "tracking-database-url",
        "redis-url",
        "tracking-token-hmac",
        "training-token-hmac",
      ])
      migration = toset(concat(
        ["migration-database-url", "audit-password", "audit-hmac"],
        [for workload in keys(local.runtime_database_roles) : "db-password-${workload}"],
      ))
    },
    {
      for deployment, roles in local.worker_deployment_roles : deployment => setunion(
        toset([
          "audit-database-url",
          "redis-url",
          "ciphertext-kek",
        ]),
        toset([for role in roles : local.runtime_database_secret_names[role]]),
        contains(roles, "directory") ? toset(["recipient-salt"]) : toset([]),
        contains(roles, "delivery") ? toset(["roe-signing-key", "acs-receipt-signing-key"]) : toset([]),
        contains(roles, "reminder") ? toset(["training-token-hmac"]) : toset([]),
        contains(roles, "retention") ? toset(["awareness-pseudonym-key"]) : toset([]),
      )
    },
  )
  workload_secret_access = merge([
    for workload, secret_names in local.workload_secret_names : {
      for secret_name in secret_names : "${workload}:${secret_name}" => {
        workload    = workload
        secret_name = secret_name
      }
    }
  ]...)
}

resource "azurerm_role_assignment" "workload_secret" {
  for_each             = local.workload_secret_access
  scope                = azurerm_key_vault_secret.runtime[each.value.secret_name].resource_versionless_id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.workload[each.value.workload].principal_id
}

# The GitHub credential is inserted by a platform administrator after the
# foundation phase. Terraform receives only its versionless Key Vault resource
# ID, grants the operator identity access to that one secret, and never handles
# the credential value or stores it in state.
resource "azurerm_role_assignment" "deployment_github_token_reader" {
  count                = var.deploy_workloads && local.deployment_orchestration_enabled ? 1 : 0
  scope                = trimspace(var.deployment_github_token_secret_id)
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.workload["operator"].principal_id
}

# The composite prior-key value is inserted directly into Key Vault by a
# platform administrator. Terraform handles only its versionless reference;
# Container Apps resolves the value at runtime for the operator and workers.
resource "azurerm_role_assignment" "ciphertext_prior_key_reader" {
  for_each = var.deploy_workloads && local.ciphertext_recovery_enabled ? setunion(
    toset(["operator"]),
    local.worker_deployments,
  ) : toset([])
  scope                = local.ciphertext_prior_keys_secret_id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.workload[each.value].principal_id
}

resource "azurerm_container_app_environment" "main" {
  name                       = "cae-${local.suffix}"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  # azurerm 5.x defaults logs_destination to "azure-monitor"; a workspace id may
  # only be set when it is "log-analytics" (or ""). Pin it to route container
  # app logs to the Log Analytics workspace created above.
  logs_destination               = "log-analytics"
  infrastructure_subnet_id       = azurerm_subnet.container_apps.id
  internal_load_balancer_enabled = false
  zone_redundancy_enabled        = local.production
  tags                           = local.tags
}

locals {
  common_secrets = {
    audit-database-url = azurerm_key_vault_secret.runtime["audit-database-url"].versionless_id
    redis-url          = azurerm_key_vault_secret.runtime["redis-url"].versionless_id
    ciphertext-kek     = azurerm_key_vault_secret.runtime["ciphertext-kek"].versionless_id
    recipient-salt     = azurerm_key_vault_secret.runtime["recipient-salt"].versionless_id
  }
}

resource "azurerm_container_app" "ai_gateway" {
  count                        = var.deploy_workloads && var.deploy_ai_gateway ? 1 : 0
  name                         = "ca-${local.suffix}-ai-gateway"
  container_app_environment_id = azurerm_container_app_environment.main.id
  resource_group_name          = azurerm_resource_group.main.name
  revision_mode                = "Single"
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.workload["ai-gateway"].id]
  }
  registry {
    server   = azurerm_container_registry.main.login_server
    identity = azurerm_user_assigned_identity.workload["ai-gateway"].id
  }
  # Internal only: reached in-cluster by the worker (/propose) and operator-api
  # (/setup-assist). No external ingress and no stored secrets (the gateway
  # holds none; the model is baked into the ai-llama sidecar image).
  ingress {
    external_enabled = false
    target_port      = 8090
    transport        = "http"
    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }
  template {
    min_replicas = 1
    max_replicas = 1
    # Pinned llama.cpp Qwen server; the digest-verified GGUF is baked into the
    # image. Serves an OpenAI-compatible API on loopback :18081 that only the
    # gateway sidecar calls (no ingress target). CPU inference for Qwen2.5-7B
    # Q4_K_M is memory-heavy; ACA Consumption caps a replica at 4 vCPU / 8 GiB,
    # so llama takes 3.5/7Gi and the gateway 0.5/1Gi (4.0 vCPU / 8 GiB total).
    # The long liveness grace tolerates the multi-second model load on start.
    container {
      name   = "ai-llama"
      image  = var.ai_llama_image
      cpu    = 3.5
      memory = "7Gi"
      liveness_probe {
        transport               = "HTTP"
        path                    = "/health"
        port                    = 18081
        initial_delay           = 30
        interval_seconds        = 30
        failure_count_threshold = 30
      }
      readiness_probe {
        transport        = "HTTP"
        path             = "/health"
        port             = 18081
        interval_seconds = 10
      }
    }
    container {
      name   = "ai-gateway"
      image  = var.ai_gateway_image
      cpu    = 0.5
      memory = "1Gi"
      env {
        name  = "KP_AI_GATEWAY_HOST"
        value = "0.0.0.0"
      }
      env {
        name  = "KP_AI_GATEWAY_PORT"
        value = "8090"
      }
      env {
        name  = "KP_AI_GATEWAY_MODEL_ID"
        value = local.ai_model_id
      }
      env {
        name  = "KP_AI_GATEWAY_LLAMA_BASE_URL"
        value = "http://localhost:18081/v1"
      }
      env {
        name  = "APPLICATIONINSIGHTS_CONNECTION_STRING"
        value = azurerm_application_insights.main.connection_string
      }
      liveness_probe {
        transport        = "HTTP"
        path             = "/livez"
        port             = 8090
        interval_seconds = 30
      }
      readiness_probe {
        transport        = "HTTP"
        path             = "/readyz"
        port             = 8090
        interval_seconds = 10
      }
    }
  }
  tags       = local.tags
  depends_on = [azurerm_role_assignment.acr_pull]
}

resource "azurerm_container_app" "operator" {
  count                        = var.deploy_workloads ? 1 : 0
  name                         = "ca-${local.suffix}-operator"
  container_app_environment_id = azurerm_container_app_environment.main.id
  resource_group_name          = azurerm_resource_group.main.name
  revision_mode                = "Multiple"
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.workload["operator"].id]
  }
  registry {
    server   = azurerm_container_registry.main.login_server
    identity = azurerm_user_assigned_identity.workload["operator"].id
  }
  dynamic "secret" {
    for_each = merge(
      local.common_secrets,
      {
        operator-database-url   = azurerm_key_vault_secret.runtime["operator-database-url"].versionless_id
        console-jwt             = azurerm_key_vault_secret.runtime["console-jwt"].versionless_id
        console-password        = azurerm_key_vault_secret.runtime["console-password"].versionless_id
        roe-signing-key         = azurerm_key_vault_secret.runtime["roe-signing-key"].versionless_id
        domain-verify-key       = azurerm_key_vault_secret.runtime["domain-verify-key"].versionless_id
        tracking-token-hmac     = azurerm_key_vault_secret.runtime["tracking-token-hmac"].versionless_id
        training-token-hmac     = azurerm_key_vault_secret.runtime["training-token-hmac"].versionless_id
        acs-receipt-signing-key = azurerm_key_vault_secret.runtime["acs-receipt-signing-key"].versionless_id
      },
      local.deployment_orchestration_enabled ? {
        deployment-github-token = local.deployment_github_token_versionless_uri
      } : {},
      local.ciphertext_recovery_enabled ? {
        ciphertext-prior-keys = local.ciphertext_prior_keys_versionless_uri
      } : {},
    )
    content {
      name                = secret.key
      key_vault_secret_id = secret.value
      identity            = azurerm_user_assigned_identity.workload["operator"].id
    }
  }
  ingress {
    external_enabled = true
    target_port      = 8000
    transport        = "http"
    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }
  template {
    min_replicas = local.production ? 2 : 1
    max_replicas = local.production ? 10 : 3
    container {
      name   = "operator"
      image  = var.operator_image
      cpu    = 0.5
      memory = "1Gi"
      dynamic "env" {
        for_each = merge({
          OPERATOR_API_HOST            = { value = "0.0.0.0", secret = null }
          OPERATOR_API_PORT            = { value = "8000", secret = null }
          OPERATOR_API_DEPLOYMENT_MODE = { value = "single_tenant", secret = null }
          OPERATOR_API_DEPLOYMENT_ORCHESTRATION_MODE = {
            value  = var.deployment_orchestration_mode
            secret = null
          }
          OPERATOR_API_DEPLOYMENT_GITHUB_REPOSITORY = {
            value  = var.deployment_github_repository
            secret = null
          }
          OPERATOR_API_DEPLOYMENT_GITHUB_REF = {
            value  = var.deployment_github_ref
            secret = null
          }
          OPERATOR_API_DATABASE_URL                 = { value = null, secret = "operator-database-url" }
          OPERATOR_API_AUDIT_DATABASE_URL           = { value = null, secret = "audit-database-url" }
          OPERATOR_API_REDIS_URL                    = { value = null, secret = "redis-url" }
          OPERATOR_API_CIPHERTEXT_KEK               = { value = null, secret = "ciphertext-kek" }
          OPERATOR_API_CIPHERTEXT_KEY_ID            = { value = trimspace(var.ciphertext_active_key_id), secret = null }
          OPERATOR_API_RECIPIENT_HASH_SALT          = { value = null, secret = "recipient-salt" }
          OPERATOR_API_CONSOLE_JWT_SECRET           = { value = null, secret = "console-jwt" }
          OPERATOR_API_ROE_SIGNING_KEY              = { value = null, secret = "roe-signing-key" }
          OPERATOR_API_DOMAIN_VERIFY_KEY            = { value = null, secret = "domain-verify-key" }
          OPERATOR_API_TRACKING_TOKEN_HMAC_KEY      = { value = null, secret = "tracking-token-hmac" }
          OPERATOR_API_TRAINING_TOKEN_HMAC_KEY      = { value = null, secret = "training-token-hmac" }
          OPERATOR_API_ACS_RECEIPT_SIGNING_KEY      = { value = null, secret = "acs-receipt-signing-key" }
          KP_CONSOLE_PASSWORD                       = { value = null, secret = "console-password" }
          OPERATOR_API_OIDC_MODE                    = { value = "oidc", secret = null }
          OPERATOR_API_OIDC_ISSUER                  = { value = "https://login.microsoftonline.com/${var.entra_tenant_id}/v2.0", secret = null }
          OPERATOR_API_OIDC_CLIENT_ID               = { value = var.entra_client_id, secret = null }
          OPERATOR_API_OIDC_AUDIENCE                = { value = var.oidc_audience, secret = null }
          OPERATOR_API_OIDC_REDIRECT_URI            = { value = "https://${var.operator_fqdn}/api/v1/console/oidc/callback", secret = null }
          OPERATOR_API_EVENT_GRID_TENANT_ID         = { value = var.entra_tenant_id, secret = null }
          OPERATOR_API_EVENT_GRID_AUDIENCE          = { value = var.entra_client_id, secret = null }
          OPERATOR_API_EVENT_GRID_SUBSCRIPTION_NAME = { value = local.acs_receipt_subscription_name, secret = null }
          OPERATOR_API_EVENT_GRID_TOPIC             = { value = local.acs_communication_service_id, secret = null }
          OPERATOR_API_TRACKING_BASE_URL            = { value = local.tracking_base_url, secret = null }
          OPERATOR_API_TRAINING_BASE_URL            = { value = local.training_base_url, secret = null }
          OPERATOR_API_TRAINING_DOMAINS             = { value = lower(trimspace(var.tracking_fqdn)), secret = null }
          KP_WORKER_ALERT_WEBHOOK_DOMAINS           = { value = var.alert_webhook_domains, secret = null }
          # OIDC mode refuses "single-admin" at startup, so this must be set
          # explicitly here or the container crash-loops on boot.
          OPERATOR_APPROVAL_POLICY     = { value = "enforce", secret = null }
          KP_ALLOWED_RECIPIENT_DOMAINS = { value = var.allowed_recipient_domains, secret = null }
          # Container Apps filesystems are ephemeral and there is no local
          # supervisor: console endpoints that would edit .env or signal
          # processes refuse rather than appear to succeed.
          OPERATOR_API_CONFIG_STORE             = { value = "managed", secret = null }
          OPERATOR_API_RATE_LIMIT_BACKEND       = { value = "redis", secret = null }
          OPERATOR_API_CONSOLE_STATIC_DIR       = { value = "/app/apps/operator-ui/src/console", secret = null }
          APPLICATIONINSIGHTS_CONNECTION_STRING = { value = azurerm_application_insights.main.connection_string, secret = null }
          },
          local.deployment_orchestration_enabled ? {
            OPERATOR_API_DEPLOYMENT_GITHUB_TOKEN = { value = null, secret = "deployment-github-token" }
          } : {},
          local.ciphertext_recovery_enabled ? {
            OPERATOR_API_CIPHERTEXT_PRIOR_KEYS = { value = null, secret = "ciphertext-prior-keys" }
          } : {},
        )
        content {
          name        = env.key
          value       = env.value.value
          secret_name = env.value.secret
        }
      }
      liveness_probe {
        transport        = "HTTP"
        path             = "/livez"
        port             = 8000
        interval_seconds = 30
      }
      readiness_probe {
        transport        = "HTTP"
        path             = "/readyz"
        port             = 8000
        interval_seconds = 10
      }
    }
  }
  tags = local.tags
  depends_on = [
    azurerm_role_assignment.acr_pull,
    azurerm_role_assignment.workload_secret,
    azurerm_role_assignment.deployment_github_token_reader,
    azurerm_role_assignment.ciphertext_prior_key_reader,
  ]
}

resource "azurerm_container_app" "tracking" {
  count                        = var.deploy_workloads ? 1 : 0
  name                         = "ca-${local.suffix}-tracking"
  container_app_environment_id = azurerm_container_app_environment.main.id
  resource_group_name          = azurerm_resource_group.main.name
  revision_mode                = "Multiple"
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.workload["tracking"].id]
  }
  registry {
    server   = azurerm_container_registry.main.login_server
    identity = azurerm_user_assigned_identity.workload["tracking"].id
  }
  dynamic "secret" {
    for_each = {
      tracking-database-url = azurerm_key_vault_secret.runtime["tracking-database-url"].versionless_id
      redis-url             = local.common_secrets["redis-url"]
      tracking-token-hmac   = azurerm_key_vault_secret.runtime["tracking-token-hmac"].versionless_id
      training-token-hmac   = azurerm_key_vault_secret.runtime["training-token-hmac"].versionless_id
    }
    content {
      name                = secret.key
      key_vault_secret_id = secret.value
      identity            = azurerm_user_assigned_identity.workload["tracking"].id
    }
  }
  ingress {
    external_enabled = true
    target_port      = 8001
    transport        = "http"
    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }
  template {
    min_replicas = local.production ? 2 : 1
    max_replicas = local.production ? 20 : 3
    container {
      name   = "tracking"
      image  = var.tracking_image
      cpu    = 0.5
      memory = "1Gi"
      dynamic "env" {
        for_each = {
          TRACKING_API_HOST                     = { value = "0.0.0.0", secret = null }
          TRACKING_API_PORT                     = { value = "8001", secret = null }
          TRACKING_API_DATABASE_URL             = { value = null, secret = "tracking-database-url" }
          TRACKING_API_REDIS_URL                = { value = null, secret = "redis-url" }
          TRACKING_API_RATE_LIMIT_BACKEND       = { value = "redis", secret = null }
          TRACKING_API_TRUSTED_PROXIES          = { value = local.tracking_trusted_proxies, secret = null }
          TRACKING_API_TRACKING_TOKEN_HMAC_KEY  = { value = null, secret = "tracking-token-hmac" }
          TRACKING_API_TRAINING_TOKEN_HMAC_KEY  = { value = null, secret = "training-token-hmac" }
          TRACKING_API_TRAINING_BASE_URL        = { value = local.training_base_url, secret = null }
          APPLICATIONINSIGHTS_CONNECTION_STRING = { value = azurerm_application_insights.main.connection_string, secret = null }
        }
        content {
          name        = env.key
          value       = env.value.value
          secret_name = env.value.secret
        }
      }
      liveness_probe {
        transport        = "HTTP"
        path             = "/livez"
        port             = 8001
        interval_seconds = 30
      }
      readiness_probe {
        transport        = "HTTP"
        path             = "/readyz"
        port             = 8001
        interval_seconds = 10
      }
    }
  }
  tags       = local.tags
  depends_on = [azurerm_role_assignment.acr_pull, azurerm_role_assignment.workload_secret]
}

resource "azurerm_container_app" "worker" {
  for_each                     = var.deploy_workloads ? local.worker_deployments : toset([])
  name                         = "ca-${local.suffix}-${each.key}"
  container_app_environment_id = azurerm_container_app_environment.main.id
  resource_group_name          = azurerm_resource_group.main.name
  revision_mode                = "Single"
  identity {
    type = "UserAssigned"
    identity_ids = concat(
      [azurerm_user_assigned_identity.workload[each.key].id],
      [
        for role in sort(tolist(local.provider_identity_roles)) :
        azurerm_user_assigned_identity.workload[local.provider_identity_names[role]].id
        if contains(local.worker_deployment_roles[each.key], role)
      ],
    )
  }
  registry {
    server   = azurerm_container_registry.main.login_server
    identity = azurerm_user_assigned_identity.workload[each.key].id
  }
  dynamic "secret" {
    for_each = local.worker_deployment_roles[each.key]
    content {
      name                = "worker-${secret.value}-database-url"
      key_vault_secret_id = azurerm_key_vault_secret.runtime[local.runtime_database_secret_names[secret.value]].versionless_id
      identity            = azurerm_user_assigned_identity.workload[each.key].id
    }
  }
  secret {
    name                = "audit-database-url"
    key_vault_secret_id = local.common_secrets["audit-database-url"]
    identity            = azurerm_user_assigned_identity.workload[each.key].id
  }
  secret {
    name                = "redis-url"
    key_vault_secret_id = local.common_secrets["redis-url"]
    identity            = azurerm_user_assigned_identity.workload[each.key].id
  }
  secret {
    name                = "ciphertext-kek"
    key_vault_secret_id = local.common_secrets["ciphertext-kek"]
    identity            = azurerm_user_assigned_identity.workload[each.key].id
  }
  dynamic "secret" {
    for_each = local.ciphertext_recovery_enabled ? [1] : []
    content {
      name                = "ciphertext-prior-keys"
      key_vault_secret_id = local.ciphertext_prior_keys_versionless_uri
      identity            = azurerm_user_assigned_identity.workload[each.key].id
    }
  }
  dynamic "secret" {
    for_each = merge(
      contains(local.worker_deployment_roles[each.key], "delivery") ? {
        roe-signing-key         = azurerm_key_vault_secret.runtime["roe-signing-key"].versionless_id
        acs-receipt-signing-key = azurerm_key_vault_secret.runtime["acs-receipt-signing-key"].versionless_id
      } : {},
      contains(local.worker_deployment_roles[each.key], "directory") ? {
        recipient-salt = azurerm_key_vault_secret.runtime["recipient-salt"].versionless_id
      } : {},
      contains(local.worker_deployment_roles[each.key], "reminder") ? {
        training-token-hmac = azurerm_key_vault_secret.runtime["training-token-hmac"].versionless_id
      } : {},
      contains(local.worker_deployment_roles[each.key], "retention") ? {
        awareness-pseudonym-key = azurerm_key_vault_secret.runtime["awareness-pseudonym-key"].versionless_id
      } : {},
    )
    content {
      name                = secret.key
      key_vault_secret_id = secret.value
      identity            = azurerm_user_assigned_identity.workload[each.key].id
    }
  }
  template {
    min_replicas = 1
    max_replicas = each.key == "delivery" ? (local.production ? 5 : 2) : 1
    container {
      name    = each.key
      image   = var.worker_image
      command = each.key == "worker" ? ["kp-worker", "supervise"] : ["kp-worker", "delivery"]
      cpu     = 0.5
      memory  = "1Gi"
      dynamic "env" {
        for_each = each.key == "worker" ? local.worker_deployment_roles[each.key] : toset([])
        content {
          name        = "KP_WORKER_DATABASE_URL_${upper(replace(env.value, "-", "_"))}"
          secret_name = "worker-${env.value}-database-url"
        }
      }
      dynamic "env" {
        for_each = each.key == "delivery" ? [1] : []
        content {
          name        = "KP_WORKER_DATABASE_URL"
          secret_name = "worker-delivery-database-url"
        }
      }
      env {
        name        = "KP_WORKER_AUDIT_DATABASE_URL"
        secret_name = "audit-database-url"
      }
      env {
        name        = "KP_WORKER_REDIS_URL"
        secret_name = "redis-url"
      }
      env {
        name        = "KP_WORKER_CIPHERTEXT_KEK"
        secret_name = "ciphertext-kek"
      }
      env {
        name  = "KP_WORKER_CIPHERTEXT_KEY_ID"
        value = trimspace(var.ciphertext_active_key_id)
      }
      dynamic "env" {
        for_each = local.ciphertext_recovery_enabled ? [1] : []
        content {
          name        = "KP_WORKER_CIPHERTEXT_PRIOR_KEYS"
          secret_name = "ciphertext-prior-keys"
        }
      }
      dynamic "env" {
        for_each = contains(local.worker_deployment_roles[each.key], "directory") ? [1] : []
        content {
          name        = "KP_WORKER_RECIPIENT_HASH_SALT"
          secret_name = "recipient-salt"
        }
      }
      dynamic "env" {
        for_each = contains(local.worker_deployment_roles[each.key], "delivery") ? [1] : []
        content {
          name        = "KP_WORKER_ROE_SIGNING_KEY"
          secret_name = "roe-signing-key"
        }
      }
      dynamic "env" {
        for_each = contains(local.worker_deployment_roles[each.key], "delivery") ? [1] : []
        content {
          name        = "KP_WORKER_ACS_RECEIPT_SIGNING_KEY"
          secret_name = "acs-receipt-signing-key"
        }
      }
      dynamic "env" {
        for_each = contains(local.worker_deployment_roles[each.key], "reminder") ? [1] : []
        content {
          name        = "KP_WORKER_TRAINING_TOKEN_HMAC_KEY"
          secret_name = "training-token-hmac"
        }
      }
      dynamic "env" {
        for_each = contains(local.worker_deployment_roles[each.key], "retention") ? [1] : []
        content {
          name        = "KP_WORKER_AWARENESS_PSEUDONYM_KEY"
          secret_name = "awareness-pseudonym-key"
        }
      }
      dynamic "env" {
        for_each = contains(local.worker_deployment_roles[each.key], "retention") ? [1] : []
        content {
          name  = "KP_WORKER_AWARENESS_PSEUDONYM_KEY_VERSION"
          value = trimspace(var.awareness_pseudonym_key_version)
        }
      }
      env {
        name  = "KP_WORKER_RUNTIME_MODE"
        value = "managed"
      }
      dynamic "env" {
        for_each = each.key == "worker" ? [1] : []
        content {
          name  = "KP_WORKER_ROLES"
          value = join(",", sort(tolist(local.worker_deployment_roles[each.key])))
        }
      }
      env {
        name  = "KP_WORKER_EMAIL_PROVIDER"
        value = "azure_communication_services"
      }
      env {
        name  = "KP_WORKER_ACS_EMAIL_ENDPOINT"
        value = local.acs_email_endpoint
      }
      env {
        name  = "KP_WORKER_ACS_CLIENT_ID"
        value = azurerm_user_assigned_identity.workload[each.key].client_id
      }
      dynamic "env" {
        for_each = contains(local.worker_deployment_roles[each.key], "audit-anchor") ? [1] : []
        content {
          name  = "KP_WORKER_AUDIT_ANCHOR_CONTAINER_URL"
          value = azurerm_storage_container.audit_anchor.url
        }
      }
      dynamic "env" {
        for_each = contains(local.worker_deployment_roles[each.key], "audit-anchor") ? [1] : []
        content {
          name  = "KP_WORKER_AUDIT_ANCHOR_CLIENT_ID"
          value = azurerm_user_assigned_identity.workload[each.key].client_id
        }
      }
      dynamic "env" {
        for_each = contains(local.worker_deployment_roles[each.key], "audit-anchor") ? [1] : []
        content {
          name  = "KP_WORKER_AUDIT_ANCHOR_INTERVAL_SECONDS"
          value = tostring(var.audit_anchor_interval_seconds)
        }
      }
      dynamic "env" {
        for_each = setintersection(
          local.worker_deployment_roles[each.key],
          toset(["directory", "mailbox"]),
        )
        content {
          name = env.value == "directory" ? "KP_WORKER_GRAPH_CLIENT_ID" : "KP_WORKER_REPORTED_MAILBOX_CLIENT_ID"
          value = azurerm_user_assigned_identity.workload[
            local.provider_identity_names[env.value]
          ].client_id
        }
      }
      env {
        name  = "KP_WORKER_SMTP_SENDER"
        value = local.acs_sender_address
      }
      env {
        name  = "KP_WORKER_REMINDER_SENDER"
        value = local.acs_sender_address
      }
      dynamic "env" {
        for_each = length(setintersection(local.worker_deployment_roles[each.key], toset(["delivery", "reminder"]))) > 0 ? {
          KP_WORKER_ACS_SENDING_DOMAIN             = lower(trimspace(var.acs_sending_domain))
          KP_WORKER_ACS_SENDER_LOCAL_PART          = lower(trimspace(var.acs_sender_local_part))
          KP_WORKER_ACS_SENDER_DISPLAY_NAME        = trimspace(var.acs_sender_display_name)
          KP_WORKER_ACS_DOMAIN_VERIFICATION_STATUS = lower(trimspace(var.acs_domain_verification_status))
          KP_WORKER_ACS_SPF_VERIFICATION_STATUS    = lower(trimspace(var.acs_spf_verification_status))
          KP_WORKER_ACS_DKIM_VERIFICATION_STATUS   = lower(trimspace(var.acs_dkim_verification_status))
          KP_WORKER_ACS_DKIM2_VERIFICATION_STATUS  = lower(trimspace(var.acs_dkim2_verification_status))
          KP_WORKER_ACS_SENDER_USERNAME_STATUS     = local.acs_provision ? "verified" : lower(trimspace(var.acs_sender_username_status))
          KP_WORKER_ACS_READINESS_CHECKED_AT       = trimspace(var.acs_readiness_checked_at)
          KP_WORKER_ACS_READINESS_MAX_AGE_HOURS    = tostring(var.acs_readiness_max_age_hours)
          KP_WORKER_ACS_DAILY_MESSAGE_LIMIT        = tostring(var.acs_daily_message_limit)
          KP_WORKER_ACS_MESSAGES_PER_MINUTE        = tostring(var.acs_messages_per_minute)
          KP_WORKER_ACS_RAMP_BATCH_SIZE            = tostring(var.acs_ramp_batch_size)
          KP_WORKER_ACS_RAMP_INTERVAL_SECONDS      = tostring(var.acs_ramp_interval_seconds)
          KP_WORKER_DELIVERY_BATCH_SIZE            = tostring(var.acs_ramp_batch_size)
        } : {}
        content {
          name  = env.key
          value = env.value
        }
      }
      env {
        name  = "KP_WORKER_TRACKING_BASE_URL"
        value = local.tracking_base_url
      }
      env {
        name  = "KP_WORKER_TRAINING_BASE_URL"
        value = local.training_base_url
      }
      env {
        name  = "KP_WORKER_TRAINING_DOMAINS"
        value = lower(trimspace(var.tracking_fqdn))
      }
      dynamic "env" {
        for_each = merge([
          for role in local.worker_deployment_roles[each.key] : lookup(local.provider_worker_env, role, {})
        ]...)
        content {
          name  = env.key
          value = env.value
        }
      }
      env {
        name  = "KP_WORKER_ALERT_WEBHOOK_DOMAINS"
        value = var.alert_webhook_domains
      }
      # The workers re-check both send-safety controls independently of the API,
      # so they must agree on the same values.
      env {
        name  = "OPERATOR_APPROVAL_POLICY"
        value = "enforce"
      }
      env {
        name  = "KP_ALLOWED_RECIPIENT_DOMAINS"
        value = var.allowed_recipient_domains
      }
      env {
        name  = "APPLICATIONINSIGHTS_CONNECTION_STRING"
        value = azurerm_application_insights.main.connection_string
      }
    }
  }
  tags = local.tags
  depends_on = [
    azurerm_role_assignment.acr_pull,
    azurerm_role_assignment.workload_secret,
    azurerm_role_assignment.ciphertext_prior_key_reader,
    azurerm_communication_service_email_domain_association.main,
    azurerm_email_communication_service_domain_sender_username.main,
    azurerm_role_assignment.audit_anchor_writer,
    azurerm_private_endpoint.audit_anchor,
  ]
}

# Least-privilege custom role for Entra-ID (managed identity) ACS email sending.
# Azure has no built-in "Email Sender" data role for ACS; per Microsoft's managed-
# identity guidance, Entra data-plane email access is authorized by the
# Microsoft.Communication/CommunicationServices read+write management actions.
# This grants exactly those (no ListKeys/RegenerateKey, no delete) and is only
# assignable to the one Communication Service the workloads use.
resource "azurerm_role_definition" "acs_email_sender" {
  count       = var.deploy_workloads ? 1 : 0
  name        = "kp-acs-email-sender-${local.suffix}-${random_string.unique.result}"
  scope       = azurerm_resource_group.main.id
  description = "Send email through Azure Communication Services via managed identity (read+write only, no key access)."
  permissions {
    actions = [
      "Microsoft.Communication/CommunicationServices/read",
      "Microsoft.Communication/CommunicationServices/write",
    ]
    not_actions      = []
    data_actions     = []
    not_data_actions = []
  }
  assignable_scopes = [local.acs_communication_service_id]
}

resource "azurerm_role_assignment" "communication_sender" {
  for_each = var.deploy_workloads ? (
    var.isolate_delivery_worker ? toset(["worker", "delivery"]) : toset(["worker"])
  ) : toset([])
  scope              = local.acs_communication_service_id
  role_definition_id = azurerm_role_definition.acs_email_sender[0].role_definition_resource_id
  principal_id       = azurerm_user_assigned_identity.workload[each.key].principal_id
}

resource "azurerm_container_app_job" "migration" {
  count                        = var.deploy_workloads ? 1 : 0
  name                         = "caj-${local.suffix}-migration"
  location                     = azurerm_resource_group.main.location
  resource_group_name          = azurerm_resource_group.main.name
  container_app_environment_id = azurerm_container_app_environment.main.id
  replica_timeout_in_seconds   = 1800
  replica_retry_limit          = 1
  workload_profile_name        = "Consumption"
  manual_trigger_config {
    parallelism              = 1
    replica_completion_count = 1
  }
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.workload["migration"].id]
  }
  registry {
    server   = azurerm_container_registry.main.login_server
    identity = azurerm_user_assigned_identity.workload["migration"].id
  }
  dynamic "secret" {
    for_each = merge(
      {
        migration-database-url = azurerm_key_vault_secret.runtime["migration-database-url"].versionless_id
        audit-password         = azurerm_key_vault_secret.runtime["audit-password"].versionless_id
        audit-hmac             = azurerm_key_vault_secret.runtime["audit-hmac"].versionless_id
      },
      {
        for workload in keys(local.runtime_database_roles) :
        "db-password-${workload}" => azurerm_key_vault_secret.runtime["db-password-${workload}"].versionless_id
      },
    )
    content {
      name                = secret.key
      key_vault_secret_id = secret.value
      identity            = azurerm_user_assigned_identity.workload["migration"].id
    }
  }
  template {
    container {
      name    = "migration"
      image   = var.migration_image
      command = ["python", "/app/scripts/azure_migrate.py"]
      cpu     = 0.5
      memory  = "1Gi"
      dynamic "env" {
        for_each = merge({
          DATABASE_URL          = "migration-database-url"
          AUDIT_WRITER_PASSWORD = "audit-password"
          AUDIT_ROOT_KEY        = "audit-hmac"
          },
          {
            for workload in keys(local.runtime_database_roles) :
            "KP_DB_PASSWORD_${upper(replace(workload, "-", "_"))}" => "db-password-${workload}"
          },
        )
        content {
          name        = env.key
          secret_name = env.value
        }
      }
    }
  }
  tags       = local.tags
  depends_on = [azurerm_role_assignment.acr_pull, azurerm_role_assignment.workload_secret]
}
