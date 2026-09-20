#!/usr/bin/env bash
# One-shot: FINALIZE the staging ACS sender binding for mail.floridamanevolved.us.
#
# Run this ONLY after the four DNS records are added and Azure shows Domain,
# SPF, DKIM and DKIM2 as Verified. Finalize reads those live Verified states
# from the ACS control plane and then creates the verified sender username and
# domain association. If the states are not yet Verified it fails closed and is
# safe to re-run later.
#
# Runs CI qualification, then PAUSES at the required-reviewer approval in GitHub
# before ANY Azure mutation. Approve at:
#   https://github.com/ELDSRQ/kingphisher-phoenix/actions
#
# Overrides:
#   PHASE=workloads   dispatch a later phase with this same reviewed config
#                     (default: foundation_finalize). The deployment guard
#                     requires every phase of one deployment to present an
#                     identical deployment_config, so reuse this script rather
#                     than hand-assembling the 38-key JSON.
#   NETWORK_MODE=private
#                     Run in private mode (default: starter). This also selects
#                     the runner: azure-deploy.yml sends starter to a
#                     GitHub-hosted ubuntu-latest and private to the self-hosted
#                     azure-vnet runner (vm-kp-staging-runner), which must be
#                     started first:
#                       az vm start -g rg-kp-staging -n vm-kp-staging-runner
#                     Private mode additionally provisions the private DNS zones
#                     and private endpoints that starter omits, and turns off
#                     public access on the data plane.
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

PHASE="${PHASE:-foundation_finalize}"
NETWORK_MODE="${NETWORK_MODE:-starter}"

# Same reviewed config as the rotation (sending domain mail.floridamanevolved.us).
CONFIG='{"acs_daily_message_limit":"1000","acs_dkim2_verification_status":"","acs_dkim_verification_status":"","acs_dns_zone_id":"","acs_domain_association_status":"","acs_domain_verification_status":"","acs_existing_communication_service_id":"","acs_existing_email_domain_id":"","acs_existing_email_endpoint":"","acs_messages_per_minute":"20","acs_ramp_batch_size":"10","acs_ramp_interval_seconds":"60","acs_readiness_checked_at":"","acs_resource_mode":"provision","acs_sender_display_name":"Security Awareness","acs_sender_local_part":"awareness","acs_sender_username_status":"","acs_sending_domain":"mail.floridamanevolved.us","acs_spf_verification_status":"","ai_endpoint":"https://kp-ai.erikdierksgmail.onmicrosoft.com","alert_webhook_domains":"","allowed_recipient_domains":"erikdierksgmail.onmicrosoft.com","ciphertext_active_key_id":"primary","ciphertext_prior_key_ids":"","ciphertext_prior_keys_secret_id":"","communication_data_location":"United States","directory_group_ids":"","enable_directory_sync":"false","enable_reported_mailbox":"false","entra_client_id":"97466174-d0ac-460c-94e8-7b6ff3c83da5","entra_tenant_id":"808f2f63-5b2c-46e6-ace7-d133a2df35f8","location":"eastus2","name_prefix":"kp","operator_fqdn":"kp-admin.erikdierksgmail.onmicrosoft.com","reported_mailbox_address":"","reported_mailbox_folder":"inbox","subscription_id":"169644fd-c81d-4935-af55-5770f8271022","tracking_fqdn":"kp-link.erikdierksgmail.onmicrosoft.com"}'

SHA="$(git rev-parse origin/main)"
LOCAL="$(git rev-parse HEAD)"
if [ "$SHA" != "$LOCAL" ]; then
  echo "error: local HEAD ($LOCAL) != origin/main ($SHA); push or pull first" >&2
  exit 1
fi
REQID="kp-$(python3 -c 'import secrets;print(secrets.token_hex(16))')-1"

echo "dispatching: staging / $NETWORK_MODE / $PHASE (mail.floridamanevolved.us)"
echo "  request_id  : $REQID"
echo "  reviewed_sha: $SHA"
gh workflow run azure-deploy.yml --repo ELDSRQ/kingphisher-phoenix --ref main \
  -f environment=staging \
  -f network_mode="$NETWORK_MODE" \
  -f deployment_phase="$PHASE" \
  -f deployment_config="$CONFIG" \
  -f deployment_request_id="$REQID" \
  -f reviewed_commit_sha="$SHA"
sleep 8
echo "--- queued run ---"
gh run list --repo ELDSRQ/kingphisher-phoenix --workflow azure-deploy.yml --limit 1
