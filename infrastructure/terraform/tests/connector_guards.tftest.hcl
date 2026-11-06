# Mock providers keep these saved-plan precondition tests offline and read-only.
mock_provider "azurerm" {
  mock_data "azurerm_client_config" {
    defaults = {
      tenant_id       = "00000000-0000-0000-0000-000000000001"
      subscription_id = "00000000-0000-0000-0000-000000000000"
      object_id       = "00000000-0000-0000-0000-000000000003"
      client_id       = "00000000-0000-0000-0000-000000000002"
    }
  }
}
mock_provider "random" {}

variables {
  deploy_workloads          = false
  subscription_id           = "00000000-0000-0000-0000-000000000000"
  entra_tenant_id           = "00000000-0000-0000-0000-000000000001"
  entra_client_id           = "00000000-0000-0000-0000-000000000002"
  operator_fqdn             = "console.example.com"
  tracking_fqdn             = "tracking.example.com"
  acs_sending_domain        = "training.example.com"
  acs_sender_local_part     = "awareness"
  acs_sender_display_name   = "Synthetic qualification"
  acs_daily_message_limit   = 1250
  acs_messages_per_minute   = 20
  acs_ramp_batch_size       = 10
  acs_ramp_interval_seconds = 30
  allowed_recipient_domains = "example.com"
}

run "disabled_connectors" {
  command = plan
  plan_options {
    target = [terraform_data.workload_config_guard]
  }
}

run "reply_endpoint_requires_address" {
  command = plan
  plan_options {
    target = [terraform_data.workload_config_guard]
  }
  variables {
    reply_mailbox_endpoint = "https://graph.microsoft.com/v1.0"
    reply_mailbox_address  = "   "
  }
  expect_failures = [terraform_data.workload_config_guard]
}

run "curation_requires_report_endpoint" {
  command = plan
  plan_options {
    target = [terraform_data.workload_config_guard]
  }
  variables {
    curation_mailbox_address  = "curate@example.com"
    reported_mailbox_address  = "reports@example.com"
    reported_mailbox_endpoint = ""
  }
  expect_failures = [terraform_data.workload_config_guard]
}

run "curation_requires_report_address" {
  command = plan
  plan_options {
    target = [terraform_data.workload_config_guard]
  }
  variables {
    curation_mailbox_address  = "curate@example.com"
    reported_mailbox_endpoint = "https://graph.microsoft.com/v1.0"
    reported_mailbox_address  = ""
  }
  expect_failures = [terraform_data.workload_config_guard]
}

run "complete_connectors" {
  command = plan
  plan_options {
    target = [terraform_data.workload_config_guard]
  }
  variables {
    reply_mailbox_endpoint    = "https://graph.microsoft.com/v1.0"
    reply_mailbox_address     = "replies@example.com"
    curation_mailbox_address  = "curate@example.com"
    reported_mailbox_endpoint = "https://graph.microsoft.com/v1.0"
    reported_mailbox_address  = "reports@example.com"
  }
}
