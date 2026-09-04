#!/usr/bin/env bash
# One-shot: dispatch the staging WORKLOADS phase (PRIVATE network mode) on the
# self-hosted VNet runner. This builds the 5 immutable images in ACR, scans +
# SBOMs + attests them, runs the DB migration, converts the foundation to
# private networking, deploys the operator/tracking/worker/migration (and, when
# enabled, ai-gateway) container apps, and activates Event Grid receipts.
#
# Prerequisites:
#   - The self-hosted VNet runner must be online (provision-ci-runner workflow).
#   - Set DEPLOY_CI_RUNNER=true so the workloads plan keeps the runner:
#       gh variable set DEPLOY_CI_RUNNER --env staging --repo ELDSRQ/kingphisher-phoenix --body true
#
# Runs CI qualification, then PAUSES at the required-reviewer approval.
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

CONFIG='{"acs_daily_message_limit":"1000","acs_dkim2_verification_status":"","acs_dkim_verification_status":"","acs_dns_zone_id":"","acs_domain_association_status":"","acs_domain_verification_status":"","acs_existing_communication_service_id":"","acs_existing_email_domain_id":"","acs_existing_email_endpoint":"","acs_messages_per_minute":"20","acs_ramp_batch_size":"10","acs_ramp_interval_seconds":"60","acs_readiness_checked_at":"","acs_resource_mode":"provision","acs_sender_display_name":"Security Awareness","acs_sender_local_part":"awareness","acs_sender_username_status":"","acs_sending_domain":"mail.floridamanevolved.us","acs_spf_verification_status":"","ai_endpoint":"https://ca-kp-staging-ai-gateway.internal.calmflower-9463bfc2.eastus2.azurecontainerapps.io","alert_webhook_domains":"","allowed_recipient_domains":"erikdierksgmail.onmicrosoft.com,gmail.com","ciphertext_active_key_id":"primary","ciphertext_prior_key_ids":"","ciphertext_prior_keys_secret_id":"","communication_data_location":"United States","directory_group_ids":"","enable_directory_sync":"false","enable_reported_mailbox":"false","entra_client_id":"97466174-d0ac-460c-94e8-7b6ff3c83da5","entra_tenant_id":"808f2f63-5b2c-46e6-ace7-d133a2df35f8","location":"eastus2","name_prefix":"kp","operator_fqdn":"kp-admin.erikdierksgmail.onmicrosoft.com","reported_mailbox_address":"","reported_mailbox_folder":"inbox","subscription_id":"169644fd-c81d-4935-af55-5770f8271022","tracking_fqdn":"kp-link.erikdierksgmail.onmicrosoft.com"}'

SHA="$(git rev-parse origin/main)"
LOCAL="$(git rev-parse HEAD)"
if [ "$SHA" != "$LOCAL" ]; then
  echo "error: local HEAD ($LOCAL) != origin/main ($SHA); push or pull first" >&2
  exit 1
fi
REQID="kp-$(python3 -c 'import secrets;print(secrets.token_hex(16))')-1"

echo "dispatching: staging / PRIVATE / workloads (on the self-hosted VNet runner)"
echo "  request_id  : $REQID"
echo "  reviewed_sha: $SHA"
gh workflow run azure-deploy.yml --repo ELDSRQ/kingphisher-phoenix --ref main \
  -f environment=staging \
  -f network_mode=private \
  -f deployment_phase=workloads \
  -f deployment_config="$CONFIG" \
  -f deployment_request_id="$REQID" \
  -f reviewed_commit_sha="$SHA"
sleep 8
echo "--- queued run ---"
gh run list --repo ELDSRQ/kingphisher-phoenix --workflow azure-deploy.yml --limit 1
