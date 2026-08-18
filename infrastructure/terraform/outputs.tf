output "resource_group_name" { value = azurerm_resource_group.main.name }
output "container_registry_name" { value = azurerm_container_registry.main.name }
output "container_registry_login_server" { value = azurerm_container_registry.main.login_server }
output "operator_default_hostname" { value = var.deploy_workloads ? azurerm_container_app.operator[0].ingress[0].fqdn : null }
output "tracking_default_hostname" { value = var.deploy_workloads ? azurerm_container_app.tracking[0].ingress[0].fqdn : null }
output "migration_job_name" { value = var.deploy_workloads ? azurerm_container_app_job.migration[0].name : null }
output "key_vault_name" { value = azurerm_key_vault.main.name }
output "email_sender" { value = "DoNotReply@${azurerm_email_communication_service_domain.main.from_sender_domain}" }
