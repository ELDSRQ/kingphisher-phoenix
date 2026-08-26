#!/usr/bin/env bash
#
# Day-zero bootstrap for a brand-new Azure tenant.
#
# The deployment workflow needs several things to already exist before it can
# run even once: somewhere to keep Terraform state, an Entra application that
# GitHub can log in as without a stored secret, and a set of repository
# variables. Creating those by hand in the portal is the step that made this
# platform hard to stand up. This script does all of it, and is safe to re-run.
#
# It deliberately creates NO application infrastructure — that stays the
# workflow's job, so there is exactly one path that provisions the platform.
#
# Usage:
#   scripts/azure_bootstrap.sh --subscription <id> --repo <owner/name> \
#       [--environment staging] [--location eastus2] [--prefix kp] [--dry-run]
#
# Requires: az (logged in), gh (logged in). Both are checked before any change.

set -euo pipefail

SUBSCRIPTION=""
REPO=""
ENVIRONMENT="staging"
LOCATION="eastus2"
PREFIX="kp"
OPERATOR_FQDN=""
ALLOWED_DOMAINS=""
DRY_RUN=0

die() { printf '\nerror: %s\n' "$*" >&2; exit 1; }
log() { printf '  %s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
run() {
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '  [dry-run] %s\n' "$*"
  else
    "$@"
  fi
}

while [ $# -gt 0 ]; do
  case "$1" in
    --subscription) SUBSCRIPTION="${2:-}"; shift 2 ;;
    --repo)         REPO="${2:-}"; shift 2 ;;
    --environment)  ENVIRONMENT="${2:-}"; shift 2 ;;
    --location)     LOCATION="${2:-}"; shift 2 ;;
    --prefix)       PREFIX="${2:-}"; shift 2 ;;
    --operator-fqdn) OPERATOR_FQDN="${2:-}"; shift 2 ;;
    --allowed-domains) ALLOWED_DOMAINS="${2:-}"; shift 2 ;;
    --dry-run)      DRY_RUN=1; shift ;;
    -h|--help)      sed -n '2,20p' "$0"; exit 0 ;;
    *)              die "unknown argument: $1" ;;
  esac
done

[ -n "$SUBSCRIPTION" ] || die "--subscription is required"
[ -n "$REPO" ] || die "--repo is required (owner/name)"
case "$ENVIRONMENT" in
  staging|production) ;;
  *) die "--environment must be 'staging' or 'production'" ;;
esac

step "Checking prerequisites"
command -v az >/dev/null 2>&1 || die "the Azure CLI (az) is not installed"
command -v gh >/dev/null 2>&1 || die "the GitHub CLI (gh) is not installed"
az account show >/dev/null 2>&1 || die "not logged in to Azure; run: az login"
gh auth status >/dev/null 2>&1 || die "not logged in to GitHub; run: gh auth login"
if ! gh repo view "$REPO" >/dev/null 2>&1; then
  if [ "$DRY_RUN" -eq 1 ]; then
    log "[dry-run] repository '$REPO' not visible; continuing so the plan can be previewed"
  else
    die "cannot see repository '$REPO' with the current gh login"
  fi
fi
log "az and gh are ready"

TENANT_ID="$(az account show --subscription "$SUBSCRIPTION" --query tenantId -o tsv 2>/dev/null || true)"
if [ -z "$TENANT_ID" ]; then
  if [ "$DRY_RUN" -eq 1 ]; then
    TENANT_ID="<tenant-id>"
    log "[dry-run] subscription not visible; continuing with a placeholder tenant"
  else
    die "could not resolve the tenant for subscription $SUBSCRIPTION (is it the right id, and is your az login scoped to it?)"
  fi
fi
log "tenant $TENANT_ID"

# Storage account names are globally unique, 3-24 chars, lowercase alphanumeric.
# Derive one deterministically from the subscription so re-runs converge on the
# same account instead of littering the tenant with new ones.
HASH="$(printf '%s' "$SUBSCRIPTION$PREFIX$ENVIRONMENT" | shasum -a 256 | cut -c1-8)"
STATE_RG="rg-${PREFIX}-tfstate-${ENVIRONMENT}"
STATE_SA="st${PREFIX}tf${HASH}"
STATE_CONTAINER="tfstate"
APP_NAME="${PREFIX}-phoenix-deploy-${ENVIRONMENT}"

step "Terraform state backend"
log "resource group : $STATE_RG"
log "storage account: $STATE_SA"
log "container      : $STATE_CONTAINER"
run az group create --name "$STATE_RG" --location "$LOCATION" --subscription "$SUBSCRIPTION" --output none
# Versioning + no public blob access: Terraform state contains generated
# credentials, so it must never be world-readable and must be recoverable.
run az storage account create \
  --name "$STATE_SA" --resource-group "$STATE_RG" --location "$LOCATION" \
  --subscription "$SUBSCRIPTION" --sku Standard_LRS --kind StorageV2 \
  --allow-blob-public-access false --min-tls-version TLS1_2 --output none
run az storage account blob-service-properties update \
  --account-name "$STATE_SA" --resource-group "$STATE_RG" \
  --subscription "$SUBSCRIPTION" --enable-versioning true --output none
run az storage container create \
  --name "$STATE_CONTAINER" --account-name "$STATE_SA" \
  --subscription "$SUBSCRIPTION" --auth-mode login --output none

step "Entra application for GitHub OIDC"
# Federated credentials mean GitHub authenticates with a short-lived token; no
# client secret is ever created, stored, or rotated.
APP_ID="$(az ad app list --display-name "$APP_NAME" --query '[0].appId' -o tsv 2>/dev/null || true)"
if [ -z "$APP_ID" ] || [ "$APP_ID" = "null" ]; then
  if [ "$DRY_RUN" -eq 1 ]; then
    log "[dry-run] would create application $APP_NAME"
    APP_ID="00000000-0000-0000-0000-000000000000"
  else
    APP_ID="$(az ad app create --display-name "$APP_NAME" --query appId -o tsv)"
    log "created application $APP_NAME"
  fi
else
  log "reusing existing application $APP_NAME"
fi
log "client id $APP_ID"

if [ "$DRY_RUN" -eq 0 ]; then
  az ad sp show --id "$APP_ID" >/dev/null 2>&1 || az ad sp create --id "$APP_ID" --output none
fi

# One credential per subject. The environment subject is what the deploy job
# presents, because that job declares `environment:`.
add_federated_credential() {
  local name="$1" subject="$2"
  if [ "$DRY_RUN" -eq 1 ]; then
    log "[dry-run] federated credential $name -> $subject"
    return 0
  fi
  if az ad app federated-credential list --id "$APP_ID" --query "[?name=='$name']" -o tsv | grep -q .; then
    log "federated credential $name already present"
    return 0
  fi
  az ad app federated-credential create --id "$APP_ID" --parameters "$(cat <<JSON
{
  "name": "$name",
  "issuer": "https://token.actions.githubusercontent.com",
  "subject": "$subject",
  "description": "KingPhisher-Phoenix deployment from $REPO",
  "audiences": ["api://AzureADTokenExchange"]
}
JSON
)" --output none
  log "added federated credential $name"
}
add_federated_credential "${ENVIRONMENT}-environment" "repo:${REPO}:environment:${ENVIRONMENT}"

step "Entra application for operator sign-in"
# Distinct from the deployment application above: this is the app humans
# authenticate against in the console. Conflating the two would give the
# deployment principal the console's identity and vice versa.
CONSOLE_APP_NAME="${PREFIX}-phoenix-console-${ENVIRONMENT}"
CONSOLE_APP_ID="$(az ad app list --display-name "$CONSOLE_APP_NAME" --query '[0].appId' -o tsv 2>/dev/null || true)"

# The platform maps Entra app roles onto its RBAC roles; every role it knows
# about is declared so an administrator can assign them in the portal without
# hand-editing a manifest.
build_app_roles() {
  python3 - <<'PYROLES'
import json, uuid
roles = [
    ("source_curator", "Source curator", "Curate threat-intelligence sources."),
    ("campaign_author", "Campaign author", "Draft awareness campaigns."),
    ("security_approver", "Security approver", "Give the security approval required to schedule."),
    ("privacy_approver", "Privacy approver", "Give the privacy approval required to schedule."),
    ("campaign_operator", "Campaign operator", "Schedule and run approved campaigns."),
    ("auditor", "Auditor", "Read audit history and reports."),
    ("administrator", "Administrator", "Full administrative access."),
]
print(json.dumps([
    {
        "allowedMemberTypes": ["User"],
        "description": description,
        "displayName": display,
        "id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"kingphisher-phoenix/role/{value}")),
        "isEnabled": True,
        "value": value,
    }
    for value, display, description in roles
]))
PYROLES
}

if [ -z "$CONSOLE_APP_ID" ] || [ "$CONSOLE_APP_ID" = "null" ]; then
  if [ "$DRY_RUN" -eq 1 ]; then
    log "[dry-run] would create sign-in application $CONSOLE_APP_NAME with 7 app roles"
    CONSOLE_APP_ID="00000000-0000-0000-0000-000000000001"
  else
    CONSOLE_APP_ID="$(az ad app create --display-name "$CONSOLE_APP_NAME" \
      --sign-in-audience AzureADMyOrg \
      --app-roles "$(build_app_roles)" \
      --query appId -o tsv)"
    log "created sign-in application $CONSOLE_APP_NAME with 7 app roles"
  fi
else
  log "reusing existing sign-in application $CONSOLE_APP_NAME"
  if [ "$DRY_RUN" -eq 0 ]; then
    az ad app update --id "$CONSOLE_APP_ID" --app-roles "$(build_app_roles)" --output none
    log "app roles reconciled"
  fi
fi
log "console client id $CONSOLE_APP_ID"

if [ -n "$OPERATOR_FQDN" ]; then
  REDIRECT="https://${OPERATOR_FQDN}/api/v1/console/oidc/callback"
  if [ "$DRY_RUN" -eq 1 ]; then
    log "[dry-run] would set redirect URI $REDIRECT"
  else
    az ad app update --id "$CONSOLE_APP_ID" --web-redirect-uris "$REDIRECT" --output none
    log "redirect URI $REDIRECT"
  fi
else
  log "no --operator-fqdn given; set the redirect URI once the hostname is known"
fi

step "Role assignments"
SP_OBJECT_ID="$(az ad sp show --id "$APP_ID" --query id -o tsv 2>/dev/null || echo "")"
if [ "$DRY_RUN" -eq 1 ]; then
  log "[dry-run] would grant Contributor + User Access Administrator on the subscription"
elif [ -n "$SP_OBJECT_ID" ]; then
  # Contributor provisions the resources; User Access Administrator is required
  # because Terraform assigns AcrPull and Key Vault roles to the runtime
  # managed identity. Scoped to this subscription only.
  for role in "Contributor" "User Access Administrator"; do
    if az role assignment list --assignee "$APP_ID" --role "$role" \
        --scope "/subscriptions/$SUBSCRIPTION" --query '[0]' -o tsv 2>/dev/null | grep -q .; then
      log "$role already assigned"
    else
      az role assignment create --assignee-object-id "$SP_OBJECT_ID" \
        --assignee-principal-type ServicePrincipal --role "$role" \
        --scope "/subscriptions/$SUBSCRIPTION" --output none
      log "granted $role"
    fi
  done
else
  die "could not resolve the service principal object id for $APP_ID"
fi

step "GitHub repository variables"
set_var() {
  local key="$1" value="$2"
  if [ -z "$value" ]; then
    log "skipping $key (no value; set it before deploying)"
    return 0
  fi
  run gh variable set "$key" --repo "$REPO" --body "$value"
  log "$key"
}
set_var AZURE_SUBSCRIPTION_ID "$SUBSCRIPTION"
set_var AZURE_TENANT_ID "$TENANT_ID"
set_var AZURE_CLIENT_ID "$APP_ID"
set_var ENTRA_APPLICATION_CLIENT_ID "$CONSOLE_APP_ID"
set_var TF_STATE_RESOURCE_GROUP "$STATE_RG"
set_var TF_STATE_STORAGE_ACCOUNT "$STATE_SA"
set_var TF_STATE_CONTAINER "$STATE_CONTAINER"
set_var ALLOWED_RECIPIENT_DOMAINS "$ALLOWED_DOMAINS"
set_var OPERATOR_FQDN "$OPERATOR_FQDN"

step "Done"
cat <<SUMMARY

Bootstrap complete for '$ENVIRONMENT'.

  subscription   $SUBSCRIPTION
  tenant         $TENANT_ID
  client id      $APP_ID
  state backend  $STATE_RG / $STATE_SA / $STATE_CONTAINER

Still required before the first deploy:

  1. Create the '$ENVIRONMENT' environment in GitHub with required reviewers:
       https://github.com/$REPO/settings/environments
     The deploy job runs as that environment and the federated credential is
     bound to it, so deployment fails until it exists.

  2. Assign console roles to your people in the portal (App registrations ->
     $CONSOLE_APP_NAME -> Enterprise application -> Users and groups). The
     platform requires SEPARATE security_approver and privacy_approver
     holders: one person cannot approve their own campaign, and on Azure the
     two-person rule is enforced and cannot be switched off.

  3. Any variable reported as skipped above must be set, in particular:
       gh variable set OPERATOR_FQDN --repo $REPO --body awareness.example.com
       gh variable set TRACKING_FQDN --repo $REPO --body awareness-track.example.com
       gh variable set ALLOWED_RECIPIENT_DOMAINS --repo $REPO --body corp.example
     ALLOWED_RECIPIENT_DOMAINS is mandatory: the allowlist fails closed under
     OIDC, so with it empty no recipient can be imported or mailed.

  Optional:
       gh variable set AI_GATEWAY_ENDPOINT   --repo $REPO --body https://<name>.openai.azure.com
       gh variable set ALERT_WEBHOOK_DOMAINS --repo $REPO --body ntfy.example.com

Then deploy:

       gh workflow run "Azure deployment" --repo $REPO \\
         -f environment=$ENVIRONMENT -f network_mode=starter

  starter = public endpoints, deployable from a hosted runner, for first
  bring-up only. Move to network_mode=private before the platform holds real
  recipient data; production refuses starter outright.

SUMMARY
