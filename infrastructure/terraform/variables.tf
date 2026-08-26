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
variable "migration_image" {
  type    = string
  default = "bootstrap.invalid/migration:pending"
}

variable "deploy_workloads" {
  description = "Create workload resources after images have been pushed to the provisioned registry."
  type        = bool
  default     = true
}

variable "operator_fqdn" {
  description = "Public operator hostname. DNS/certificate binding is a post-provision release step."
  type        = string
}

variable "tracking_fqdn" {
  description = "Public tracking hostname used in generated awareness messages."
  type        = string
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

variable "ai_endpoint" {
  description = "Azure OpenAI-compatible HTTPS endpoint. Leave empty to use deterministic local guidance."
  type        = string
  default     = ""
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
    up from a GitHub-hosted runner in a single dispatch, with no pre-existing
    VNet or self-hosted runner. It is intended for evaluation and first-run
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
