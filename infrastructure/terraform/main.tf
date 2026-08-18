data "azurerm_client_config" "current" {}

locals {
  suffix     = "${var.name_prefix}-${var.environment}"
  production = var.environment == "production"
  tags = merge(var.tags, {
    application = "kingphisher-phoenix"
    environment = var.environment
    managed-by  = "terraform"
    tenant-mode = "single-tenant"
  })
  worker_roles = toset(["ingestion", "generation", "delivery", "retention", "mailbox", "reminder", "alert", "directory"])
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
  delegation {
    name = "container-apps"
    service_delegation {
      name = "Microsoft.App/environments"
    }
  }
}

resource "azurerm_subnet" "private_endpoints" {
  name                              = "snet-private-endpoints"
  resource_group_name               = azurerm_resource_group.main.name
  virtual_network_name              = azurerm_virtual_network.main.name
  address_prefixes                  = ["10.42.2.0/24"]
  private_endpoint_network_policies = "Disabled"
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
  name                = "acs-${local.suffix}-${random_string.unique.result}"
  resource_group_name = azurerm_resource_group.main.name
  data_location       = var.communication_data_location
  tags                = local.tags
}

resource "azurerm_email_communication_service" "main" {
  name                = "email-${local.suffix}-${random_string.unique.result}"
  resource_group_name = azurerm_resource_group.main.name
  data_location       = var.communication_data_location
  tags                = local.tags
}

resource "azurerm_email_communication_service_domain" "main" {
  name                             = "AzureManagedDomain"
  email_service_id                 = azurerm_email_communication_service.main.id
  domain_management                = "AzureManaged"
  user_engagement_tracking_enabled = false
  tags                             = local.tags
}

resource "azurerm_communication_service_email_domain_association" "main" {
  communication_service_id = azurerm_communication_service.main.id
  email_service_domain_id  = azurerm_email_communication_service_domain.main.id
}

resource "azurerm_container_registry" "main" {
  name                          = replace("acr${local.suffix}", "-", "")
  resource_group_name           = azurerm_resource_group.main.name
  location                      = azurerm_resource_group.main.location
  sku                           = "Premium"
  admin_enabled                 = false
  public_network_access_enabled = false
  zone_redundancy_enabled       = local.production
  retention_policy_in_days      = 30
  tags                          = local.tags
}

resource "azurerm_user_assigned_identity" "runtime" {
  name                = "id-${local.suffix}-runtime"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags
}

resource "azurerm_role_assignment" "acr_pull" {
  scope                = azurerm_container_registry.main.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_user_assigned_identity.runtime.principal_id
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
  public_network_access_enabled = false
  network_acls {
    bypass         = "AzureServices"
    default_action = "Deny"
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
resource "random_password" "console" {
  length  = 40
  special = false
}
resource "random_id" "audit_hmac" { byte_length = 32 }
resource "random_id" "ciphertext_kek" { byte_length = 32 }
resource "random_id" "console_jwt" { byte_length = 32 }
resource "random_id" "recipient_salt" { byte_length = 32 }
resource "random_id" "corrections" { byte_length = 32 }

resource "azurerm_role_assignment" "runtime_secrets" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.runtime.principal_id
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
  backup_retention_days         = local.production ? 35 : 7
  geo_redundant_backup_enabled  = local.production
  public_network_access_enabled = false
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

resource "azurerm_managed_redis" "main" {
  name                      = "redis-${local.suffix}-${random_string.unique.result}"
  resource_group_name       = azurerm_resource_group.main.name
  location                  = azurerm_resource_group.main.location
  sku_name                  = var.redis_sku
  high_availability_enabled = local.production
  public_network_access     = "Disabled"
  default_database {
    client_protocol   = "Encrypted"
    clustering_policy = "OSSCluster"
    eviction_policy   = "NoEviction"
  }
  tags = local.tags
}

resource "azurerm_private_dns_zone" "postgres" {
  name                = "privatelink.postgres.database.azure.com"
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags
}

resource "azurerm_private_dns_zone" "redis" {
  name                = "privatelink.redis.azure.net"
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags
}

resource "azurerm_private_dns_zone" "vault" {
  name                = "privatelink.vaultcore.azure.net"
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags
}

resource "azurerm_private_dns_zone" "acr" {
  name                = "privatelink.azurecr.io"
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "links" {
  for_each = {
    postgres = azurerm_private_dns_zone.postgres.id
    redis    = azurerm_private_dns_zone.redis.id
    vault    = azurerm_private_dns_zone.vault.id
    acr      = azurerm_private_dns_zone.acr.id
  }
  name                = "${each.key}-vnet-link"
  private_dns_zone_id = each.value
  virtual_network_id  = azurerm_virtual_network.main.id
}

resource "azurerm_private_endpoint" "postgres" {
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
    private_dns_zone_ids = [azurerm_private_dns_zone.postgres.id]
  }
  tags = local.tags
}

resource "azurerm_private_endpoint" "redis" {
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
    private_dns_zone_ids = [azurerm_private_dns_zone.redis.id]
  }
  tags = local.tags
}

resource "azurerm_private_endpoint" "vault" {
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
    private_dns_zone_ids = [azurerm_private_dns_zone.vault.id]
  }
  tags = local.tags
}

resource "azurerm_private_endpoint" "acr" {
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
    private_dns_zone_ids = [azurerm_private_dns_zone.acr.id]
  }
  tags = local.tags
}

locals {
  database_url       = "postgresql+psycopg://kpadmin:${urlencode(random_password.postgres.result)}@${azurerm_postgresql_flexible_server.main.fqdn}:5432/kingphisher?sslmode=require"
  audit_database_url = "postgresql+psycopg://audit_writer:${urlencode(random_password.audit.result)}@${azurerm_postgresql_flexible_server.main.fqdn}:5432/kingphisher?sslmode=require"
  redis_url          = "rediss://default:${urlencode(azurerm_managed_redis.main.default_database[0].primary_access_key)}@${azurerm_managed_redis.main.hostname}:10000/0"
  secret_values = {
    database-url       = local.database_url
    audit-database-url = local.audit_database_url
    redis-url          = local.redis_url
    postgres-password  = random_password.postgres.result
    audit-password     = random_password.audit.result
    audit-hmac         = random_id.audit_hmac.hex
    ciphertext-kek     = random_id.ciphertext_kek.hex
    console-jwt        = random_id.console_jwt.hex
    console-password   = random_password.console.result
    recipient-salt     = random_id.recipient_salt.hex
    corrections-secret = random_id.corrections.hex
  }
}

resource "azurerm_key_vault_secret" "runtime" {
  for_each     = local.secret_values
  name         = each.key
  value        = each.value
  key_vault_id = azurerm_key_vault.main.id
  depends_on   = [azurerm_role_assignment.deployer_secrets, azurerm_private_endpoint.vault]
}

resource "azurerm_container_app_environment" "main" {
  name                           = "cae-${local.suffix}"
  location                       = azurerm_resource_group.main.location
  resource_group_name            = azurerm_resource_group.main.name
  log_analytics_workspace_id     = azurerm_log_analytics_workspace.main.id
  infrastructure_subnet_id       = azurerm_subnet.container_apps.id
  internal_load_balancer_enabled = false
  zone_redundancy_enabled        = local.production
  tags                           = local.tags
}

locals {
  common_secrets = {
    database-url       = azurerm_key_vault_secret.runtime["database-url"].versionless_id
    audit-database-url = azurerm_key_vault_secret.runtime["audit-database-url"].versionless_id
    redis-url          = azurerm_key_vault_secret.runtime["redis-url"].versionless_id
    audit-hmac         = azurerm_key_vault_secret.runtime["audit-hmac"].versionless_id
    ciphertext-kek     = azurerm_key_vault_secret.runtime["ciphertext-kek"].versionless_id
    recipient-salt     = azurerm_key_vault_secret.runtime["recipient-salt"].versionless_id
  }
}

resource "azurerm_container_app" "operator" {
  count                        = var.deploy_workloads ? 1 : 0
  name                         = "ca-${local.suffix}-operator"
  container_app_environment_id = azurerm_container_app_environment.main.id
  resource_group_name          = azurerm_resource_group.main.name
  revision_mode                = "Multiple"
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.runtime.id]
  }
  registry {
    server   = azurerm_container_registry.main.login_server
    identity = azurerm_user_assigned_identity.runtime.id
  }
  dynamic "secret" {
    for_each = merge(local.common_secrets, {
      console-jwt      = azurerm_key_vault_secret.runtime["console-jwt"].versionless_id
      console-password = azurerm_key_vault_secret.runtime["console-password"].versionless_id
    })
    content {
      name                = secret.key
      key_vault_secret_id = secret.value
      identity            = azurerm_user_assigned_identity.runtime.id
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
        for_each = {
          OPERATOR_API_HOST                     = { value = "0.0.0.0", secret = null }
          OPERATOR_API_PORT                     = { value = "8000", secret = null }
          OPERATOR_API_DEPLOYMENT_MODE          = { value = "single_tenant", secret = null }
          OPERATOR_API_DATABASE_URL             = { value = null, secret = "database-url" }
          OPERATOR_API_AUDIT_DATABASE_URL       = { value = null, secret = "audit-database-url" }
          OPERATOR_API_REDIS_URL                = { value = null, secret = "redis-url" }
          OPERATOR_API_AUDIT_HMAC_KEY           = { value = null, secret = "audit-hmac" }
          OPERATOR_API_CIPHERTEXT_KEK           = { value = null, secret = "ciphertext-kek" }
          OPERATOR_API_RECIPIENT_HASH_SALT      = { value = null, secret = "recipient-salt" }
          OPERATOR_API_CONSOLE_JWT_SECRET       = { value = null, secret = "console-jwt" }
          KP_CONSOLE_PASSWORD                   = { value = null, secret = "console-password" }
          OPERATOR_API_OIDC_MODE                = { value = "oidc", secret = null }
          OPERATOR_API_OIDC_ISSUER              = { value = "https://login.microsoftonline.com/${var.entra_tenant_id}/v2.0", secret = null }
          OPERATOR_API_OIDC_CLIENT_ID           = { value = var.entra_client_id, secret = null }
          OPERATOR_API_OIDC_AUDIENCE            = { value = var.oidc_audience, secret = null }
          OPERATOR_API_OIDC_REDIRECT_URI        = { value = "https://${var.operator_fqdn}/api/v1/console/oidc/callback", secret = null }
          OPERATOR_API_TRACKING_BASE_URL        = { value = "https://${var.tracking_fqdn}", secret = null }
          OPERATOR_API_CONSOLE_STATIC_DIR       = { value = "/app/apps/operator-ui/src/console", secret = null }
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
        path             = "/healthz"
        port             = 8000
        interval_seconds = 30
      }
      readiness_probe {
        transport        = "HTTP"
        path             = "/healthz"
        port             = 8000
        interval_seconds = 10
      }
    }
  }
  tags       = local.tags
  depends_on = [azurerm_role_assignment.acr_pull, azurerm_role_assignment.runtime_secrets]
}

resource "azurerm_container_app" "tracking" {
  count                        = var.deploy_workloads ? 1 : 0
  name                         = "ca-${local.suffix}-tracking"
  container_app_environment_id = azurerm_container_app_environment.main.id
  resource_group_name          = azurerm_resource_group.main.name
  revision_mode                = "Multiple"
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.runtime.id]
  }
  registry {
    server   = azurerm_container_registry.main.login_server
    identity = azurerm_user_assigned_identity.runtime.id
  }
  dynamic "secret" {
    for_each = {
      database-url       = local.common_secrets["database-url"]
      corrections-secret = azurerm_key_vault_secret.runtime["corrections-secret"].versionless_id
    }
    content {
      name                = secret.key
      key_vault_secret_id = secret.value
      identity            = azurerm_user_assigned_identity.runtime.id
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
          TRACKING_API_DATABASE_URL             = { value = null, secret = "database-url" }
          TRACKING_API_CORRECTIONS_SECRET       = { value = null, secret = "corrections-secret" }
          TRACKING_API_TRAINING_BASE_URL        = { value = "https://${var.operator_fqdn}/training", secret = null }
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
        path             = "/healthz"
        port             = 8001
        interval_seconds = 30
      }
      readiness_probe {
        transport        = "HTTP"
        path             = "/healthz"
        port             = 8001
        interval_seconds = 10
      }
    }
  }
  tags = local.tags
}

resource "azurerm_container_app" "worker" {
  for_each                     = var.deploy_workloads ? local.worker_roles : toset([])
  name                         = "ca-${local.suffix}-${each.key}"
  container_app_environment_id = azurerm_container_app_environment.main.id
  resource_group_name          = azurerm_resource_group.main.name
  revision_mode                = "Single"
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.runtime.id]
  }
  registry {
    server   = azurerm_container_registry.main.login_server
    identity = azurerm_user_assigned_identity.runtime.id
  }
  secret {
    name                = "database-url"
    key_vault_secret_id = local.common_secrets["database-url"]
    identity            = azurerm_user_assigned_identity.runtime.id
  }
  secret {
    name                = "audit-database-url"
    key_vault_secret_id = local.common_secrets["audit-database-url"]
    identity            = azurerm_user_assigned_identity.runtime.id
  }
  secret {
    name                = "redis-url"
    key_vault_secret_id = local.common_secrets["redis-url"]
    identity            = azurerm_user_assigned_identity.runtime.id
  }
  secret {
    name                = "audit-hmac"
    key_vault_secret_id = local.common_secrets["audit-hmac"]
    identity            = azurerm_user_assigned_identity.runtime.id
  }
  secret {
    name                = "ciphertext-kek"
    key_vault_secret_id = local.common_secrets["ciphertext-kek"]
    identity            = azurerm_user_assigned_identity.runtime.id
  }
  secret {
    name                = "recipient-salt"
    key_vault_secret_id = local.common_secrets["recipient-salt"]
    identity            = azurerm_user_assigned_identity.runtime.id
  }
  template {
    min_replicas = 1
    max_replicas = each.key == "delivery" ? (local.production ? 5 : 2) : 1
    container {
      name    = each.key
      image   = var.worker_image
      command = ["kp-worker", each.key]
      cpu     = 0.5
      memory  = "1Gi"
      env {
        name        = "KP_WORKER_DATABASE_URL"
        secret_name = "database-url"
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
        name        = "KP_WORKER_AUDIT_HMAC_KEY"
        secret_name = "audit-hmac"
      }
      env {
        name        = "KP_WORKER_CIPHERTEXT_KEK"
        secret_name = "ciphertext-kek"
      }
      env {
        name        = "KP_WORKER_RECIPIENT_HASH_SALT"
        secret_name = "recipient-salt"
      }
      env {
        name  = "KP_WORKER_EMAIL_PROVIDER"
        value = "azure_communication_services"
      }
      env {
        name  = "KP_WORKER_ACS_EMAIL_ENDPOINT"
        value = "https://${azurerm_communication_service.main.name}.communication.azure.com"
      }
      env {
        name  = "AZURE_CLIENT_ID"
        value = azurerm_user_assigned_identity.runtime.client_id
      }
      env {
        name  = "KP_WORKER_SMTP_SENDER"
        value = "DoNotReply@${azurerm_email_communication_service_domain.main.from_sender_domain}"
      }
      env {
        name  = "KP_WORKER_REMINDER_SENDER"
        value = "DoNotReply@${azurerm_email_communication_service_domain.main.from_sender_domain}"
      }
      env {
        name  = "KP_WORKER_TRACKING_BASE_URL"
        value = "https://${var.tracking_fqdn}"
      }
      env {
        name  = "KP_WORKER_AI_BASE_URL"
        value = var.ai_endpoint
      }
      env {
        name  = "KP_WORKER_ALERT_WEBHOOK_DOMAINS"
        value = var.alert_webhook_domains
      }
      env {
        name  = "APPLICATIONINSIGHTS_CONNECTION_STRING"
        value = azurerm_application_insights.main.connection_string
      }
    }
  }
  tags = local.tags
}

resource "azurerm_role_assignment" "communication_sender" {
  scope                = azurerm_communication_service.main.id
  role_definition_name = "Azure Communication Services Email Sender"
  principal_id         = azurerm_user_assigned_identity.runtime.principal_id
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
    identity_ids = [azurerm_user_assigned_identity.runtime.id]
  }
  registry {
    server   = azurerm_container_registry.main.login_server
    identity = azurerm_user_assigned_identity.runtime.id
  }
  dynamic "secret" {
    for_each = {
      database-url      = local.common_secrets["database-url"]
      postgres-password = azurerm_key_vault_secret.runtime["postgres-password"].versionless_id
      audit-password    = azurerm_key_vault_secret.runtime["audit-password"].versionless_id
    }
    content {
      name                = secret.key
      key_vault_secret_id = secret.value
      identity            = azurerm_user_assigned_identity.runtime.id
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
        for_each = {
          DATABASE_URL          = "database-url"
          POSTGRES_PASSWORD     = "postgres-password"
          AUDIT_WRITER_PASSWORD = "audit-password"
        }
        content {
          name        = env.key
          secret_name = env.value
        }
      }
    }
  }
  tags = local.tags
}
