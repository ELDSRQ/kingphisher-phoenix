variable "subscription_id" {
  description = "Azure subscription receiving this single-tenant deployment."
  type        = string
}

variable "environment" {
  description = "Deployment environment. Production enables protective defaults."
  type        = string
  default     = "staging"
  validation {
    condition     = contains(["development", "staging", "production"], var.environment)
    error_message = "environment must be development, staging, or production"
  }
}

variable "location" {
  type    = string
  default = "eastus2"
}

variable "name_prefix" {
  type    = string
  default = "kp"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,10}$", var.name_prefix))
    error_message = "name_prefix must be 2-11 lowercase letters, numbers, or hyphens"
  }
}

variable "operator_image" {
  type    = string
  default = "bootstrap.invalid/operator:pending"
}
variable "tracking_image" {
  type    = string
  default = "bootstrap.invalid/tracking:pending"
}
variable "worker_image" {
  type    = string
  default = "bootstrap.invalid/worker:pending"
}
variable "deploy_ci_runner" {
  description = <<-EOT
    Provision the self-hosted GitHub Actions runner VM inside the VNet. This is
    required before any private-mode deploy (the private data plane is
    unreachable from a hosted runner). Create it from a starter-mode bootstrap
    (a hosted runner can create the VM even though it lives inside the VNet),
    then switch to private mode. Off by default.
  EOT
  type        = bool
  default     = false
}
variable "ci_runner_registration_token" {
  description = <<-EOT
    Short-lived GitHub Actions runner registration token (expires ~1h). Supplied
    only at apply time via TF_VAR_ci_runner_registration_token from a secret set
    right before the run; never committed. Required when deploy_ci_runner=true.
  EOT
  type        = string
  default     = ""
  sensitive   = true
}
variable "ci_runner_repository_url" {
  description = "GitHub repository URL the self-hosted runner registers against."
  type        = string
  default     = "https://github.com/ELDSRQ/kingphisher-phoenix"
}
variable "ci_runner_vm_size" {
  description = "VM size for the self-hosted CI runner. This subscription's eastus2 only offers v7-generation sizes (B2s, D2s_v3, D2s_v5 are all capacity-restricted); Standard_D2s_v7 is available (confirmed via az vm list-skus)."
  type        = string
  default     = "Standard_D2s_v7"
}
variable "deploy_ai_gateway" {
  description = <<-EOT
    Deploy the internal Qwen generation gateway (kp-ai-gateway + baked-model
    ai-llama sidecar) as a workload. Requires deploy_workloads and real,
    digest-pinned ai_gateway_image and ai_llama_image. Off by default so a
    workloads deploy that does not use the internal gateway is not forced to
    build the large ai-llama image.
  EOT
  type        = bool
  default     = false
}
variable "ai_gateway_image" {
  description = "Immutable digest-pinned ACR reference for the kp-ai-gateway image."
  type        = string
  default     = "bootstrap.invalid/ai-gateway:pending"
}
variable "ai_llama_image" {
  description = <<-EOT
    Immutable digest-pinned ACR reference for the ai-llama sidecar image (a
    pinned llama.cpp server with the sha256-verified Qwen2.5-7B-Instruct-Q4_K_M
    GGUF baked in). Built out-of-band by the operator on a host holding the
    digest-pinned weights (the CI release loop cannot build it: the ~4.7 GB
    weights are not in the checkout and are never auto-downloaded), then pushed
    to ACR and pinned here by digest.
  EOT
  type        = string
  default     = "bootstrap.invalid/ai-llama:pending"
}

variable "isolate_delivery_worker" {
  description = "Run delivery in one dedicated Container App and identity; false keeps the default three-app runtime."
  type        = bool
  default     = false
}

variable "audit_anchor_interval_seconds" {
  description = "How often the worker publishes a newly verified signed audit-chain head."
  type        = number
  default     = 3600
  validation {
    condition     = var.audit_anchor_interval_seconds >= 60 && var.audit_anchor_interval_seconds <= 86400
    error_message = "audit_anchor_interval_seconds must be between 60 and 86,400."
  }
}

variable "audit_anchor_retention_days" {
  description = "Optional locked WORM retention override for external audit-head anchors. Defaults to 365 days in production and 1 day elsewhere; the lock cannot be removed or shortened."
  type        = number
  default     = null
  nullable    = true
  validation {
    condition = var.audit_anchor_retention_days == null ? true : (
      var.audit_anchor_retention_days >= 1 &&
      var.audit_anchor_retention_days <= 146000 &&
      floor(var.audit_anchor_retention_days) == var.audit_anchor_retention_days
    )
    error_message = "audit_anchor_retention_days must be null or a whole number between 1 and 146,000."
  }
}

variable "migration_image" {
  type    = string
  default = "bootstrap.invalid/migration:pending"
}

variable "deploy_workloads" {
  description = "Create workload resources after images have been pushed to the provisioned registry."
  type        = bool
  default     = true
}

variable "enable_acs_event_subscription" {
  description = "Activate the ACS Event Grid webhook only after migrations and operator audit readiness have passed."
  type        = bool
  default     = false
}

variable "operator_fqdn" {
  description = "Public operator hostname. DNS/certificate binding is a post-provision release step."
  type        = string
  validation {
    condition = (
      can(regex("^[A-Za-z0-9][A-Za-z0-9.-]*\\.[A-Za-z]{2,63}$", trimspace(var.operator_fqdn))) &&
      !strcontains(lower(var.operator_fqdn), "localhost")
    )
    error_message = "operator_fqdn must be a public DNS hostname without a scheme or path."
  }
}

variable "tracking_fqdn" {
  description = "Public tracking hostname used in generated awareness messages."
  type        = string
  validation {
    condition = (
      can(regex("^[A-Za-z0-9][A-Za-z0-9.-]*\\.[A-Za-z]{2,63}$", trimspace(var.tracking_fqdn))) &&
      !strcontains(lower(var.tracking_fqdn), "localhost")
    )
    error_message = "tracking_fqdn must be a public DNS hostname without a scheme or path."
  }
}

variable "entra_tenant_id" { type = string }
variable "entra_client_id" { type = string }
variable "oidc_audience" {
  type    = string
  default = "kp-operator-api"
}

variable "communication_data_location" {
  description = "ACS data residency geography."
  type        = string
  default     = "United States"
}

variable "acs_resource_mode" {
  description = "Provision a dedicated ACS/Email service, or associate an existing ACS resource and customer-managed email domain."
  type        = string
  default     = "provision"
  validation {
    condition     = contains(["provision", "existing"], var.acs_resource_mode)
    error_message = "acs_resource_mode must be provision or existing."
  }
}

variable "acs_existing_communication_service_id" {
  description = "Complete resource ID of an existing Communication Service; required only in existing mode."
  type        = string
  default     = ""
}

variable "acs_existing_email_endpoint" {
  description = "Non-secret HTTPS endpoint of the existing Communication Service. Connection strings are never accepted."
  type        = string
  default     = ""
  validation {
    condition = trimspace(var.acs_existing_email_endpoint) == "" || can(
      regex("^https://[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.communication\\.azure\\.com(?::443)?/?$", trimspace(var.acs_existing_email_endpoint))
    )
    error_message = "acs_existing_email_endpoint must be the non-secret HTTPS Communication Service endpoint."
  }
}

variable "acs_existing_email_domain_id" {
  description = "Resource ID of an existing customer-managed Email Communication Service domain. Never supply a connection string."
  type        = string
  default     = ""
}

variable "acs_sending_domain" {
  description = "Customer-managed public DNS domain dedicated to authorized simulation delivery. Azure-managed test domains are rejected."
  type        = string
  validation {
    condition = (
      can(regex("^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$", lower(trimspace(var.acs_sending_domain)))) &&
      lower(trimspace(var.acs_sending_domain)) != "azurecomm.net" &&
      !endswith(lower(trimspace(var.acs_sending_domain)), ".azurecomm.net")
    )
    error_message = "acs_sending_domain must be a customer-managed public DNS domain, not an Azure-managed test domain."
  }
}

variable "acs_sender_local_part" {
  description = "Provisioned ACS sender username/local part."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9._+-]{0,63}$", lower(trimspace(var.acs_sender_local_part))))
    error_message = "acs_sender_local_part must be 1-64 lowercase mailbox characters."
  }
}

variable "acs_sender_display_name" {
  description = "Human-readable sender name registered with ACS."
  type        = string
  validation {
    condition = (
      length(trimspace(var.acs_sender_display_name)) >= 1 &&
      length(trimspace(var.acs_sender_display_name)) <= 64 &&
      !strcontains(var.acs_sender_display_name, "\n") &&
      !strcontains(var.acs_sender_display_name, "\r")
    )
    error_message = "acs_sender_display_name must be 1-64 characters without line breaks."
  }
}

variable "acs_dns_zone_id" {
  description = "Optional same-subscription public Azure DNS zone resource ID. Empty leaves the exact ACS records as manual GUI work."
  type        = string
  default     = ""
}

variable "acs_domain_verification_status" {
  type    = string
  default = "unverified"
}
variable "acs_spf_verification_status" {
  type    = string
  default = "unverified"
}
variable "acs_dkim_verification_status" {
  type    = string
  default = "unverified"
}
variable "acs_dkim2_verification_status" {
  type    = string
  default = "unverified"
}
variable "acs_sender_username_status" {
  type    = string
  default = "unverified"
}
variable "acs_domain_association_status" {
  description = "For existing mode, confirms the verified email domain is linked to the selected Communication Service."
  type        = string
  default     = "unverified"
}

variable "acs_readiness_checked_at" {
  description = "RFC 3339 time when an operator last confirmed Domain, SPF, DKIM and DKIM2 are Verified in Azure. Required and time-bounded for workload deployment."
  type        = string
  default     = ""
}

variable "acs_readiness_max_age_hours" {
  type    = number
  default = 24
  validation {
    condition     = var.acs_readiness_max_age_hours >= 1 && var.acs_readiness_max_age_hours <= 168
    error_message = "acs_readiness_max_age_hours must be between 1 and 168."
  }
}

variable "acs_daily_message_limit" {
  description = "Reviewed ACS daily quota used by delivery planning; this lane does not claim provider delivery confirmation."
  type        = number
  validation {
    condition     = var.acs_daily_message_limit >= 1 && var.acs_daily_message_limit <= 1000000
    error_message = "acs_daily_message_limit must be between 1 and 1,000,000."
  }
}

variable "acs_messages_per_minute" {
  type = number
  validation {
    condition     = var.acs_messages_per_minute >= 1 && var.acs_messages_per_minute <= 10000
    error_message = "acs_messages_per_minute must be between 1 and 10,000."
  }
}

variable "acs_ramp_batch_size" {
  type = number
  validation {
    condition     = var.acs_ramp_batch_size >= 1 && var.acs_ramp_batch_size <= 2000
    error_message = "acs_ramp_batch_size must be between 1 and 2,000."
  }
}

variable "acs_ramp_interval_seconds" {
  type = number
  validation {
    condition     = var.acs_ramp_interval_seconds >= 1 && var.acs_ramp_interval_seconds <= 3600
    error_message = "acs_ramp_interval_seconds must be between 1 and 3,600."
  }
}

variable "ai_endpoint" {
  description = "Optional non-local HTTPS AI gateway implementing the platform /propose contract. Empty disables the generation worker."
  type        = string
  default     = ""
  validation {
    condition = trimspace(var.ai_endpoint) == "" || (
      startswith(lower(trimspace(var.ai_endpoint)), "https://") &&
      can(regex("^https://[A-Za-z0-9]", trimspace(var.ai_endpoint))) &&
      !strcontains(lower(var.ai_endpoint), "localhost") &&
      !strcontains(var.ai_endpoint, "127.0.0.1") &&
      !strcontains(var.ai_endpoint, "@") &&
      !strcontains(var.ai_endpoint, "?") &&
      !strcontains(var.ai_endpoint, "#")
    )
    error_message = "ai_endpoint must be empty or a non-local HTTPS URL without userinfo or a fragment."
  }
}

variable "graph_endpoint" {
  description = "Native Microsoft Graph v1.0 endpoint. Empty disables selected-group directory synchronization."
  type        = string
  default     = ""
  validation {
    condition = trimspace(var.graph_endpoint) == "" || (
      lower(trimsuffix(trimspace(var.graph_endpoint), "/")) == "https://graph.microsoft.com/v1.0"
    )
    error_message = "graph_endpoint must be empty or the native https://graph.microsoft.com/v1.0 endpoint."
  }
}

variable "directory_group_ids" {
  description = "Comma-separated Entra group object IDs selected for directory synchronization."
  type        = string
  default     = ""
  validation {
    condition = trimspace(var.directory_group_ids) == "" || alltrue([
      for group_id in split(",", var.directory_group_ids) :
      can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", trimspace(group_id)))
    ])
    error_message = "directory_group_ids must contain comma-separated Entra group object UUIDs."
  }
}

variable "reported_mailbox_endpoint" {
  description = "Native Microsoft Graph v1.0 endpoint. Empty disables Microsoft 365 report-mailbox ingestion."
  type        = string
  default     = ""
  validation {
    condition = trimspace(var.reported_mailbox_endpoint) == "" || (
      lower(trimsuffix(trimspace(var.reported_mailbox_endpoint), "/")) == "https://graph.microsoft.com/v1.0"
    )
    error_message = "reported_mailbox_endpoint must be empty or the native https://graph.microsoft.com/v1.0 endpoint."
  }
}

variable "reported_mailbox_address" {
  description = "Dedicated Microsoft 365 mailbox that receives reported simulation messages."
  type        = string
  default     = ""
  validation {
    condition = trimspace(var.reported_mailbox_address) == "" || can(
      regex("^[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$", trimspace(var.reported_mailbox_address))
    )
    error_message = "reported_mailbox_address must be empty or a complete mailbox address."
  }
}

variable "reported_mailbox_folder" {
  description = "Microsoft 365 mail folder ID or well-known name containing reported messages."
  type        = string
  default     = "inbox"
  validation {
    condition = (
      length(trimspace(var.reported_mailbox_folder)) >= 1 &&
      length(trimspace(var.reported_mailbox_folder)) <= 256 &&
      !strcontains(var.reported_mailbox_folder, "\n") &&
      !strcontains(var.reported_mailbox_folder, "\r")
    )
    error_message = "reported_mailbox_folder must be 1-256 characters without line breaks."
  }
}

variable "alert_webhook_domains" {
  description = "Comma-separated exact HTTPS host allowlist; use the Azure-hosted ntfy hostname when enabled."
  type        = string
  default     = ""
}

variable "log_retention_days" {
  type    = number
  default = 30
  validation {
    condition     = var.log_retention_days >= 30 && var.log_retention_days <= 90
    error_message = "log retention must be between 30 and 90 days"
  }
}

variable "log_daily_quota_gb" {
  type    = number
  default = 1
  validation {
    condition     = var.log_daily_quota_gb > 0 && var.log_daily_quota_gb <= 5
    error_message = "daily log quota must be greater than zero and no more than 5 GB"
  }
}

variable "postgres_sku" {
  type    = string
  default = "GP_Standard_D2ds_v5"
}

variable "postgres_storage_mb" {
  type    = number
  default = 65536
}

variable "redis_sku" {
  type    = string
  default = "Balanced_B0"
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "network_mode" {
  description = <<-EOT
    How the data-plane services are reachable.

    "private" (default) keeps Postgres, Redis, Key Vault and the registry on
    private endpoints with public access disabled. Deploying it requires a
    runner inside the VNet, because Terraform and the image build must reach
    those private endpoints.

    "starter" leaves them publicly reachable so a brand-new tenant can be stood
    up from a GitHub-hosted runner, with no pre-existing VNet or self-hosted
    runner. It is intended for evaluation and first-run
    bring-up, NOT for a deployment that holds real recipient data — production
    rejects it (see the validation below).
  EOT
  type        = string
  default     = "private"
  validation {
    condition     = contains(["private", "starter"], var.network_mode)
    error_message = "network_mode must be either \"private\" or \"starter\"."
  }
}

variable "allow_starter_in_production" {
  description = <<-EOT
    Escape hatch for the production guard on network_mode. Left false so that
    "starter" cannot reach a production environment by accident; a deliberate
    operator decision is required to override it.
  EOT
  type        = bool
  default     = false
}

variable "allowed_recipient_domains" {
  description = <<-EOT
    Comma-separated mail domains this deployment may target; subdomains are
    included. Required, because the platform runs under OIDC on Azure and the
    recipient allowlist fails closed there: with this empty, recipient import
    is refused and no campaign can be delivered.
  EOT
  type        = string
  validation {
    condition     = length(trimspace(var.allowed_recipient_domains)) > 0
    error_message = "allowed_recipient_domains must list at least one domain; the platform refuses to import or deliver to recipients otherwise."
  }
}

variable "ciphertext_active_key_id" {
  description = "Non-secret identifier authenticated into new ciphertext and shared by the operator and all workers. It is immutable after foundation until rolling pre-stage/promotion exists."
  type        = string
  default     = "primary"
  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$", trimspace(var.ciphertext_active_key_id)))
    error_message = "ciphertext_active_key_id must be 1-32 ASCII letters, digits, underscores, or hyphens."
  }
}

variable "awareness_pseudonym_key_version" {
  description = "Governed non-secret version for the stable retention-worker awareness-ledger pseudonym key. Rotation requires reviewed ledger re-projection/recovery."
  type        = string
  default     = "v1"
  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$", trimspace(var.awareness_pseudonym_key_version)))
    error_message = "awareness_pseudonym_key_version must be 1-32 ASCII letters, digits, dots, underscores, or hyphens."
  }
}

variable "ciphertext_prior_key_ids" {
  description = "Comma-separated non-secret identifiers in the external decrypt-only recovery keyring; empty disables legacy recovery."
  type        = string
  default     = ""
  validation {
    condition = trimspace(var.ciphertext_prior_key_ids) == "" || (
      length([for key_id in split(",", var.ciphertext_prior_key_ids) : trimspace(key_id)]) <= 4 &&
      alltrue([
        for key_id in split(",", var.ciphertext_prior_key_ids) :
        can(regex("^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$", trimspace(key_id)))
      ]) &&
      length(distinct([for key_id in split(",", var.ciphertext_prior_key_ids) : trimspace(key_id)])) ==
      length([for key_id in split(",", var.ciphertext_prior_key_ids) : trimspace(key_id)])
    )
    error_message = "ciphertext_prior_key_ids must contain at most four unique, comma-separated key identifiers."
  }
}

variable "ciphertext_prior_keys_secret_id" {
  description = <<-EOT
    Versionless resource ID of an externally populated Key Vault secret whose value is the bounded
    key-id=64-hex decrypt-only keyring. Terraform receives only this reference and never reads or stores
    the secret value. The protected workflow verifies resource lifecycle metadata before a workload plan.
    This is for legacy recovery only and does not permit active-key rotation.
  EOT
  type        = string
  default     = ""
}

variable "deployment_orchestration_mode" {
  description = "Optional managed GUI deployment connector. Disabled is the fail-closed default."
  type        = string
  default     = "disabled"
  validation {
    condition     = contains(["disabled", "github_actions"], var.deployment_orchestration_mode)
    error_message = "deployment_orchestration_mode must be disabled or github_actions."
  }
}

variable "deployment_github_repository" {
  description = "Fixed owner/repository used only when managed GUI deployment orchestration is enabled."
  type        = string
  default     = ""
}

variable "deployment_github_ref" {
  description = "Fixed reviewed branch or tag used only when managed GUI deployment orchestration is enabled."
  type        = string
  default     = "main"
}

variable "deployment_github_token_secret_id" {
  description = <<-EOT
    Versionless Key Vault secret resource ID containing the externally supplied GitHub credential.
    Terraform never receives the credential value. Create this secret after the foundation phase and
    before enabling github_actions for the workloads phase.
  EOT
  type        = string
  default     = ""
}
