#!/usr/bin/env bash
#
# Day-zero bootstrap for a brand-new Azure tenant.
#
# The deployment workflow needs several things to already exist before it can
# run even once: somewhere to keep Terraform state, an Entra application that
# GitHub can log in as without a stored secret, and a small set of protected
# GitHub environment variables. Creating those by hand in the portal made the
# platform hard to stand up. This script does all of it, and is safe to re-run.
#
# It deliberately creates NO application infrastructure — that stays the
# workflow's job, so there is exactly one path that provisions the platform.
#
# Usage:
#   scripts/azure_bootstrap.sh --subscription <id> --repo <owner/name> \
#       [--environment staging] [--location eastus2] [--prefix kp] \
#       [--operator-fqdn awareness.example] \
#       [--deployment-orchestration-mode disabled|github_actions] \
#       [--deployment-github-repository owner/name] \
#       [--deployment-github-ref main] \
#       [--deployment-github-token-secret-id <versionless-key-vault-id>] \
#       [--dry-run]
#
# Requires: az (logged in), gh (logged in). Both are checked before any change.

set -euo pipefail

# Azure CLI command logging can copy control-plane arguments into a per-user
# file and also makes otherwise read-only commands fail in locked-down runners.
# The scripts emit their own bounded, non-secret status output instead.
export AZURE_LOGGING_ENABLE_LOG_FILE=false

SUBSCRIPTION=""
REPO=""
ENVIRONMENT="staging"
LOCATION="eastus2"
PREFIX="kp"
OPERATOR_FQDN=""
DEPLOYMENT_ORCHESTRATION_MODE="disabled"
DEPLOYMENT_ORCHESTRATION_MODE_EXPLICIT=0
DEPLOYMENT_CONNECTOR_FIELDS_EXPLICIT=0
DEPLOYMENT_GITHUB_REPOSITORY=""
DEPLOYMENT_GITHUB_REF="main"
DEPLOYMENT_GITHUB_TOKEN_SECRET_ID=""
DRY_RUN=0
COMMAND_TIMEOUT_SECONDS="${KP_AZURE_COMMAND_TIMEOUT_SECONDS:-60}"

die() { printf '\nerror: %s\n' "$*" >&2; exit 1; }
log() { printf '  %s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
require_argument() {
  [ "$#" -ge 2 ] && [ -n "$2" ] && [ "${2#--}" = "$2" ] || die "$1 requires a value"
}
run() {
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '  [dry-run] %s\n' "$*"
  else
    "$@"
  fi
}

bounded() {
  python3 - "$COMMAND_TIMEOUT_SECONDS" "$@" <<'PYTIMEOUT'
import subprocess
import sys

try:
    result = subprocess.run(sys.argv[2:], timeout=int(sys.argv[1]), check=False)
except subprocess.TimeoutExpired:
    print(f"error: command timed out after {sys.argv[1]} seconds", file=sys.stderr)
    raise SystemExit(124)
raise SystemExit(result.returncode)
PYTIMEOUT
}

while [ $# -gt 0 ]; do
  case "$1" in
    --subscription) require_argument "$@"; SUBSCRIPTION="$2"; shift 2 ;;
    --repo) require_argument "$@"; REPO="$2"; shift 2 ;;
    --environment) require_argument "$@"; ENVIRONMENT="$2"; shift 2 ;;
    --location) require_argument "$@"; LOCATION="$2"; shift 2 ;;
    --prefix) require_argument "$@"; PREFIX="$2"; shift 2 ;;
    --operator-fqdn) require_argument "$@"; OPERATOR_FQDN="$2"; shift 2 ;;
    --deployment-orchestration-mode) require_argument "$@"; DEPLOYMENT_ORCHESTRATION_MODE="$2"; DEPLOYMENT_ORCHESTRATION_MODE_EXPLICIT=1; shift 2 ;;
    --deployment-github-repository) require_argument "$@"; DEPLOYMENT_GITHUB_REPOSITORY="$2"; DEPLOYMENT_CONNECTOR_FIELDS_EXPLICIT=1; shift 2 ;;
    --deployment-github-ref) require_argument "$@"; DEPLOYMENT_GITHUB_REF="$2"; DEPLOYMENT_CONNECTOR_FIELDS_EXPLICIT=1; shift 2 ;;
    --deployment-github-token-secret-id) require_argument "$@"; DEPLOYMENT_GITHUB_TOKEN_SECRET_ID="$2"; DEPLOYMENT_CONNECTOR_FIELDS_EXPLICIT=1; shift 2 ;;
    --dry-run)      DRY_RUN=1; shift ;;
    -h|--help)      sed -n '2,20p' "$0"; exit 0 ;;
    *)              die "unknown argument; use --help" ;;
  esac
done

[ -n "$SUBSCRIPTION" ] || die "--subscription is required"
[ -n "$REPO" ] || die "--repo is required (owner/name)"
UUID_PATTERN='^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$'
[[ "$SUBSCRIPTION" =~ $UUID_PATTERN ]] || die "--subscription must be a UUID"
case "$ENVIRONMENT" in
  staging|production) ;;
  *) die "--environment must be 'staging' or 'production'" ;;
esac
case "$DEPLOYMENT_ORCHESTRATION_MODE" in
  disabled|github_actions) ;;
  *) die "--deployment-orchestration-mode must be 'disabled' or 'github_actions'" ;;
esac
if [ "$DEPLOYMENT_CONNECTOR_FIELDS_EXPLICIT" -eq 1 ] \
  && [ "$DEPLOYMENT_ORCHESTRATION_MODE_EXPLICIT" -eq 0 ]; then
  die "--deployment-orchestration-mode is required when connector fields are supplied"
fi
REPOSITORY_PATTERN='^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$'
[[ "$REPO" =~ $REPOSITORY_PATTERN ]] || die "--repo must use a valid owner/name format"
[ -z "$DEPLOYMENT_GITHUB_REPOSITORY" ] || \
  [[ "$DEPLOYMENT_GITHUB_REPOSITORY" =~ $REPOSITORY_PATTERN ]] || \
  die "--deployment-github-repository must use a valid owner/name format"
[[ "$LOCATION" =~ ^[a-z0-9]+$ ]] || die "--location must be an Azure region code such as eastus2"
[[ "$PREFIX" =~ ^[a-z][a-z0-9]{1,8}$ ]] || \
  die "--prefix must be 2-9 lowercase letters or numbers and start with a letter"
if [ -n "$OPERATOR_FQDN" ]; then
  [[ "$OPERATOR_FQDN" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] || \
    die "--operator-fqdn must be a lowercase public hostname without a scheme or path"
fi
[[ "$DEPLOYMENT_GITHUB_REF" =~ ^[A-Za-z0-9._/-]{1,255}$ ]] && \
  [[ "$DEPLOYMENT_GITHUB_REF" != /* ]] && \
  [[ "$DEPLOYMENT_GITHUB_REF" != */ ]] && \
  [[ "$DEPLOYMENT_GITHUB_REF" != *. ]] && \
  [[ "$DEPLOYMENT_GITHUB_REF" != *.lock ]] && \
  [[ "$DEPLOYMENT_GITHUB_REF" != *..* ]] && \
  [[ "$DEPLOYMENT_GITHUB_REF" != *//* ]] && \
  [[ ! "$DEPLOYMENT_GITHUB_REF" =~ (^|/)\. ]] || \
  die "--deployment-github-ref is invalid"
if [ "$DEPLOYMENT_ORCHESTRATION_MODE" = "github_actions" ]; then
  [ -n "$DEPLOYMENT_GITHUB_REPOSITORY" ] || \
    die "--deployment-github-repository is required when GUI orchestration is enabled"
  [ "$DEPLOYMENT_GITHUB_REPOSITORY" = "$REPO" ] || \
    die "--deployment-github-repository must match --repo when GUI orchestration is enabled"
  [ -n "$DEPLOYMENT_GITHUB_TOKEN_SECRET_ID" ] || \
    die "--deployment-github-token-secret-id is required when GUI orchestration is enabled"
fi
if [ -n "$DEPLOYMENT_GITHUB_TOKEN_SECRET_ID" ]; then
  KEY_VAULT_SECRET_ID_PATTERN='^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.KeyVault/vaults/[A-Za-z0-9-]{3,24}/secrets/[A-Za-z0-9-]{1,127}$'
  [[ "$DEPLOYMENT_GITHUB_TOKEN_SECRET_ID" =~ $KEY_VAULT_SECRET_ID_PATTERN ]] || \
    die "--deployment-github-token-secret-id must be a complete versionless Key Vault secret resource ID"
fi
case "$COMMAND_TIMEOUT_SECONDS" in
  ''|*[!0-9]*) die "KP_AZURE_COMMAND_TIMEOUT_SECONDS must be an integer" ;;
esac
[ "$COMMAND_TIMEOUT_SECONDS" -ge 5 ] && [ "$COMMAND_TIMEOUT_SECONDS" -le 300 ] || \
  die "KP_AZURE_COMMAND_TIMEOUT_SECONDS must be between 5 and 300"

step "Checking prerequisites"
if [ "$DRY_RUN" -eq 1 ]; then
  # The preview prints command arguments but never executes either CLI. Keep it
  # usable on a review workstation before Azure/GitHub tooling is installed.
  AZ_BIN="az"
  GH_BIN="gh"
else
  command -v az >/dev/null 2>&1 || die "the Azure CLI (az) is not installed"
  command -v gh >/dev/null 2>&1 || die "the GitHub CLI (gh) is not installed"
  AZ_BIN="$(command -v az)"
  GH_BIN="$(command -v gh)"
fi
az() { bounded "$AZ_BIN" "$@"; }
gh() { bounded "$GH_BIN" "$@"; }
if [ "$DRY_RUN" -eq 1 ]; then
  # A dry run is an offline plan. It must remain useful when credentials are
  # missing or expired and must never make even an accidental mutating call.
  TENANT_ID="<tenant-id>"
  log "[dry-run] offline preview; Azure and GitHub authentication were not used"
else
  az account show >/dev/null 2>&1 || die "Azure authentication failed; run: az login"
  gh auth status >/dev/null 2>&1 || die "GitHub authentication failed; run: gh auth login"
  gh repo view "$REPO" >/dev/null 2>&1 || die "cannot see repository '$REPO' with the current gh login"
  log "az and gh are authenticated"
  TENANT_ID="$(az account show --subscription "$SUBSCRIPTION" --query tenantId -o tsv 2>/dev/null || true)"
  [ -n "$TENANT_ID" ] && [ "$TENANT_ID" != "null" ] || \
    die "could not resolve the tenant for subscription $SUBSCRIPTION (is it the right id, and is your az login scoped to it?)"
fi
log "tenant $TENANT_ID"

step "Protected GitHub environment"
if [ "$DRY_RUN" -eq 1 ]; then
  log "[dry-run] would require '$ENVIRONMENT' to disable administrator bypass and require at least one reviewer"
else
  ENVIRONMENT_JSON="$(gh api "repos/$REPO/environments/$ENVIRONMENT" 2>/dev/null || true)"
  if ! ENVIRONMENT_JSON="$ENVIRONMENT_JSON" python3 - "$ENVIRONMENT" <<'PYENV'
import json
import os
import sys

expected = sys.argv[1]
try:
    payload = json.loads(os.environ["ENVIRONMENT_JSON"])
except (json.JSONDecodeError, UnicodeDecodeError):
    raise SystemExit(1)
rules = payload.get("protection_rules")
reviewers = 0
if isinstance(rules, list):
    for rule in rules:
        if isinstance(rule, dict) and rule.get("type") == "required_reviewers":
            configured = rule.get("reviewers")
            if isinstance(configured, list):
                reviewers += len(configured)
if payload.get("name") != expected or payload.get("can_admins_bypass") is not False or reviewers < 1:
    raise SystemExit(1)
PYENV
  then
    die "GitHub environment '$ENVIRONMENT' must exist, require at least one reviewer, and disable administrator bypass before bootstrap"
  fi
  log "environment '$ENVIRONMENT' has required-reviewer protection and administrator bypass disabled"
fi

# Storage account names are globally unique, 3-24 chars, lowercase alphanumeric.
# Derive one deterministically from the subscription so re-runs converge on the
# same account instead of littering the tenant with new ones.
HASH="$(printf '%s' "$SUBSCRIPTION$PREFIX$ENVIRONMENT" | shasum -a 256 | cut -c1-8)"
STATE_RG="rg-${PREFIX}-tfstate-${ENVIRONMENT}"
STATE_SA="st${PREFIX}tf${HASH}"
STATE_CONTAINER="tfstate"
APP_NAME="${PREFIX}-phoenix-deploy-${ENVIRONMENT}"
CONSOLE_APP_NAME="${PREFIX}-phoenix-console-${ENVIRONMENT}"

# The platform maps Entra app roles onto its RBAC roles. Keep this contract
# available to the read-only inspection phase so a drifted existing console
# application is rejected before the state backend or any identity is changed.
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
app_roles = [
    {
        "allowedMemberTypes": ["User"],
        "description": description,
        "displayName": display,
        "id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"kingphisher-phoenix/role/{value}")),
        "isEnabled": True,
        "value": value,
    }
    for value, display, description in roles
]
app_roles.append({
    "allowedMemberTypes": ["Application"],
    "description": "Allow Microsoft.EventGrid to deliver authenticated ACS receipts.",
    "displayName": "Azure Event Grid secure webhook subscriber",
    "id": str(uuid.uuid5(uuid.NAMESPACE_URL, "kingphisher-phoenix/role/AzureEventGridSecureWebhookSubscriber")),
    "isEnabled": True,
    "value": "AzureEventGridSecureWebhookSubscriber",
})
print(json.dumps(app_roles))
PYROLES
}

validate_app_role_contract() {
  local existing_roles="$1" expected_roles
  expected_roles="$(build_app_roles)"
  EXPECTED_APP_ROLES="$expected_roles" EXISTING_APP_ROLES="$existing_roles" python3 <<'PYROLECONTRACT'
import json
import os

try:
    expected = json.loads(os.environ["EXPECTED_APP_ROLES"])
    existing = json.loads(os.environ["EXISTING_APP_ROLES"])
except (json.JSONDecodeError, UnicodeDecodeError):
    raise SystemExit(1)

fields = ("allowedMemberTypes", "description", "displayName", "id", "isEnabled", "value")

def normalize(rows):
    if not isinstance(rows, list) or len(rows) != len(expected):
        raise SystemExit(1)
    normalized = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("value"), str) or not row["value"]:
            raise SystemExit(1)
        value = row["value"]
        if value in normalized:
            raise SystemExit(1)
        normalized[value] = {field: row.get(field) for field in fields}
    return normalized

raise SystemExit(0 if normalize(existing) == normalize(expected) else 1)
PYROLECONTRACT
}

# Refuse ambiguous pre-existing identities before the first cloud mutation.
# They are queried again at point of use so concurrent identity drift also
# fails closed.
assert_unique_entra_app() {
  local display_name="$1" rows
  rows="$(az ad app list --display-name "$display_name" -o json 2>/dev/null)" || \
    die "could not inspect an existing Entra application before bootstrap"
  if ! APP_ROWS="$rows" python3 <<'PYUNIQUE'
import json
import os

rows = json.loads(os.environ["APP_ROWS"])
if not isinstance(rows, list):
    raise SystemExit(2)
matches = [row for row in rows if isinstance(row, dict) and row.get("appId")]
raise SystemExit(0 if len(matches) <= 1 else 2)
PYUNIQUE
  then
    die "multiple Entra applications share a required display name; refusing any bootstrap mutation"
  fi
}

validate_existing_console_app_before_mutation() {
  local rows console_app_id existing_roles
  rows="$(az ad app list --display-name "$CONSOLE_APP_NAME" -o json 2>/dev/null)" || \
    die "could not inspect the operator application before bootstrap"
  if ! console_app_id="$(CONSOLE_APP_ROWS="$rows" python3 - "$CONSOLE_APP_NAME" <<'PYCONSOLEPRECHECK'
import json
import os
import sys
import uuid

try:
    rows = json.loads(os.environ["CONSOLE_APP_ROWS"])
except (json.JSONDecodeError, UnicodeDecodeError):
    raise SystemExit(1)
if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
    raise SystemExit(1)
if any(row.get("displayName") != sys.argv[1] for row in rows):
    raise SystemExit(1)
matches = rows
if len(matches) > 1:
    raise SystemExit(1)
if not matches:
    print("")
    raise SystemExit(0)
app_id = matches[0].get("appId")
if not isinstance(app_id, str):
    raise SystemExit(1)
try:
    uuid.UUID(app_id)
except ValueError:
    raise SystemExit(1)
print(app_id)
PYCONSOLEPRECHECK
)"; then
    die "existing operator application identity is malformed or ambiguous; refusing any bootstrap mutation"
  fi
  [ -n "$console_app_id" ] || return 0
  existing_roles="$(az ad app show --id "$console_app_id" --query appRoles -o json 2>/dev/null)" || \
    die "could not inspect existing operator app roles; refusing any bootstrap mutation"
  validate_app_role_contract "$existing_roles" || \
    die "existing operator app roles differ from the current contract; refusing any bootstrap mutation"
  log "existing operator app role contract verified before mutation"
}

if [ "$DRY_RUN" -eq 0 ]; then
  assert_unique_entra_app "$APP_NAME"
  assert_unique_entra_app "$CONSOLE_APP_NAME"
  validate_existing_console_app_before_mutation
fi

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
  --allow-blob-public-access false --allow-shared-key-access false \
  --https-only true --min-tls-version TLS1_2 --output none
run az storage account blob-service-properties update \
  --account-name "$STATE_SA" --resource-group "$STATE_RG" \
  --subscription "$SUBSCRIPTION" --enable-versioning true \
  --enable-delete-retention true --delete-retention-days 30 \
  --enable-container-delete-retention true --container-delete-retention-days 30 \
  --output none
# Use the ARM control plane, not a storage key or the caller's implicit blob
# data-plane rights. The deployment identity receives its own narrow data role.
run az storage container-rm create \
  --name "$STATE_CONTAINER" --storage-account "$STATE_SA" \
  --resource-group "$STATE_RG" --subscription "$SUBSCRIPTION" \
  --public-access off --output none

step "Entra application for GitHub OIDC"
# Federated credentials mean GitHub authenticates with a short-lived token; no
# client secret is ever created, stored, or rotated.
if [ "$DRY_RUN" -eq 1 ]; then
  APP_ID=""
else
  APP_ROWS="$(az ad app list --display-name "$APP_NAME" -o json 2>/dev/null)" || \
    die "could not inspect the deployment application in Entra"
  if ! APP_ID="$(APP_ROWS="$APP_ROWS" python3 <<'PYAPP'
import json
import os

rows = json.loads(os.environ["APP_ROWS"])
matches = [str(row.get("appId", "")) for row in rows if isinstance(row, dict) and row.get("appId")]
if len(matches) > 1:
    raise SystemExit(2)
print(matches[0] if matches else "")
PYAPP
)"; then
    die "multiple Entra applications are named $APP_NAME; refusing an ambiguous bootstrap"
  fi
fi
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
if [ "$DRY_RUN" -eq 1 ]; then
  CONSOLE_APP_ID=""
else
  CONSOLE_APP_ROWS="$(az ad app list --display-name "$CONSOLE_APP_NAME" -o json 2>/dev/null)" || \
    die "could not inspect the operator application in Entra"
  if ! CONSOLE_APP_ID="$(CONSOLE_APP_ROWS="$CONSOLE_APP_ROWS" python3 <<'PYCONSOLEAPP'
import json
import os

rows = json.loads(os.environ["CONSOLE_APP_ROWS"])
matches = [str(row.get("appId", "")) for row in rows if isinstance(row, dict) and row.get("appId")]
if len(matches) > 1:
    raise SystemExit(2)
print(matches[0] if matches else "")
PYCONSOLEAPP
)"; then
    die "multiple Entra applications are named $CONSOLE_APP_NAME; refusing an ambiguous bootstrap"
  fi
fi

if [ -z "$CONSOLE_APP_ID" ] || [ "$CONSOLE_APP_ID" = "null" ]; then
  if [ "$DRY_RUN" -eq 1 ]; then
    log "[dry-run] would create sign-in application $CONSOLE_APP_NAME with 8 app roles"
    CONSOLE_APP_ID="00000000-0000-0000-0000-000000000001"
  else
    CONSOLE_APP_ID="$(az ad app create --display-name "$CONSOLE_APP_NAME" \
      --sign-in-audience AzureADMyOrg \
      --app-roles "$(build_app_roles)" \
      --query appId -o tsv)"
    log "created sign-in application $CONSOLE_APP_NAME with 8 app roles"
  fi
else
  log "reusing existing sign-in application $CONSOLE_APP_NAME"
  if [ "$DRY_RUN" -eq 0 ]; then
    EXISTING_APP_ROLES="$(az ad app show --id "$CONSOLE_APP_ID" --query appRoles -o json)"
    if ! validate_app_role_contract "$EXISTING_APP_ROLES"; then
      die "existing operator app roles differ from the current contract; refusing to overwrite assigned or unrecognized roles"
    fi
    log "existing app role contract verified without mutation"
  fi
fi
log "console client id $CONSOLE_APP_ID"

step "Event Grid secure-webhook authorization"
# Event Grid obtains a bearer token for the operator application. Azure also
# requires both Microsoft.EventGrid and the event-subscription writer to hold
# an application role on that destination app before it will create/update the
# subscription. The role IDs are deterministic, so re-running converges.
EVENT_GRID_APP_ID="4962773b-9cdb-44cf-a8bf-237846a00ab7"
EVENT_GRID_ROLE_VALUE="AzureEventGridSecureWebhookSubscriber"
EVENT_GRID_ROLE_ID="$(python3 - <<'PYROLEID'
import uuid
print(uuid.uuid5(uuid.NAMESPACE_URL, "kingphisher-phoenix/role/AzureEventGridSecureWebhookSubscriber"))
PYROLEID
)"

assign_event_grid_webhook_role() {
  local principal_app_id="$1" principal_label="$2" principal_object_id existing
  if [ "$DRY_RUN" -eq 1 ]; then
    log "[dry-run] would assign $EVENT_GRID_ROLE_VALUE to $principal_label"
    return 0
  fi
  principal_object_id="$(az ad sp show --id "$principal_app_id" --query id -o tsv 2>/dev/null || true)"
  if [ -z "$principal_object_id" ] || [ "$principal_object_id" = "null" ]; then
    principal_object_id="$(az ad sp create --id "$principal_app_id" --query id -o tsv)"
  fi
  [ -n "$principal_object_id" ] && [ "$principal_object_id" != "null" ] || \
    die "could not resolve the $principal_label service principal"
  existing="$(az rest --method GET \
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${principal_object_id}/appRoleAssignments" \
    --query "length(value[?resourceId=='${CONSOLE_SP_OBJECT_ID}' && appRoleId=='${EVENT_GRID_ROLE_ID}'])" -o tsv)"
  if [ "$existing" != "0" ]; then
    log "$principal_label already has $EVENT_GRID_ROLE_VALUE"
    return 0
  fi
  az rest --method POST \
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${principal_object_id}/appRoleAssignments" \
    --headers Content-Type=application/json \
    --body "{\"principalId\":\"${principal_object_id}\",\"resourceId\":\"${CONSOLE_SP_OBJECT_ID}\",\"appRoleId\":\"${EVENT_GRID_ROLE_ID}\"}" \
    --output none
  log "assigned $EVENT_GRID_ROLE_VALUE to $principal_label"
}

if [ "$DRY_RUN" -eq 1 ]; then
  log "[dry-run] would verify the console service principal and deterministic Event Grid app role"
  assign_event_grid_webhook_role "$EVENT_GRID_APP_ID" "Microsoft.EventGrid"
  assign_event_grid_webhook_role "$APP_ID" "deployment application"
else
  CONSOLE_SP_OBJECT_ID="$(az ad sp show --id "$CONSOLE_APP_ID" --query id -o tsv 2>/dev/null || true)"
  if [ -z "$CONSOLE_SP_OBJECT_ID" ] || [ "$CONSOLE_SP_OBJECT_ID" = "null" ]; then
    CONSOLE_SP_OBJECT_ID="$(az ad sp create --id "$CONSOLE_APP_ID" --query id -o tsv)"
  fi
  [ -n "$CONSOLE_SP_OBJECT_ID" ] && [ "$CONSOLE_SP_OBJECT_ID" != "null" ] || \
    die "could not resolve the operator console service principal"
  CONFIGURED_EVENT_GRID_ROLE_ID="$(az ad app show --id "$CONSOLE_APP_ID" \
    --query "appRoles[?value=='${EVENT_GRID_ROLE_VALUE}'] | [0].id" -o tsv)"
  [ "$CONFIGURED_EVENT_GRID_ROLE_ID" = "$EVENT_GRID_ROLE_ID" ] || \
    die "operator app has a missing or mismatched $EVENT_GRID_ROLE_VALUE role"
  CONFIGURED_EVENT_GRID_ROLE_MEMBERS="$(az ad app show --id "$CONSOLE_APP_ID" \
    --query "join(',', appRoles[?value=='${EVENT_GRID_ROLE_VALUE}'].allowedMemberTypes | [0])" -o tsv)"
  [ "$CONFIGURED_EVENT_GRID_ROLE_MEMBERS" = "Application" ] || \
    die "$EVENT_GRID_ROLE_VALUE must allow only application principals"
  CONFIGURED_EVENT_GRID_ROLE_ENABLED="$(az ad app show --id "$CONSOLE_APP_ID" \
    --query "appRoles[?value=='${EVENT_GRID_ROLE_VALUE}'] | [0].isEnabled" -o tsv)"
  [ "$CONFIGURED_EVENT_GRID_ROLE_ENABLED" = "true" ] || \
    die "$EVENT_GRID_ROLE_VALUE must be enabled"
  assign_event_grid_webhook_role "$EVENT_GRID_APP_ID" "Microsoft.EventGrid"
  assign_event_grid_webhook_role "$APP_ID" "deployment application"
fi

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
if [ "$DRY_RUN" -eq 1 ]; then
  log "[dry-run] would grant Contributor + User Access Administrator on the subscription"
  log "[dry-run] would grant Storage Blob Data Contributor on the exact state account"
else
  SP_OBJECT_ID="$(az ad sp show --id "$APP_ID" --query id -o tsv 2>/dev/null || echo "")"
  [ -n "$SP_OBJECT_ID" ] || die "could not resolve the service principal object id for $APP_ID"
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
  STATE_ACCOUNT_ID="$(az storage account show --name "$STATE_SA" --resource-group "$STATE_RG" \
    --subscription "$SUBSCRIPTION" --query id -o tsv)"
  [ -n "$STATE_ACCOUNT_ID" ] || die "could not resolve the Terraform state storage account"
  if az role assignment list --assignee "$APP_ID" --role "Storage Blob Data Contributor" \
      --scope "$STATE_ACCOUNT_ID" --query '[0]' -o tsv 2>/dev/null | grep -q .; then
    log "Storage Blob Data Contributor already assigned on the state account"
  else
    az role assignment create --assignee-object-id "$SP_OBJECT_ID" \
      --assignee-principal-type ServicePrincipal --role "Storage Blob Data Contributor" \
      --scope "$STATE_ACCOUNT_ID" --output none
    log "granted Storage Blob Data Contributor on the state account"
  fi
fi

step "Protected GitHub environment variables"
set_var() {
  local key="$1" value="$2"
  run gh variable set "$key" --repo "$REPO" --env "$ENVIRONMENT" --body "$value"
  log "$key"
}
set_var AZURE_SUBSCRIPTION_ID "$SUBSCRIPTION"
set_var AZURE_TENANT_ID "$TENANT_ID"
set_var AZURE_CLIENT_ID "$APP_ID"
set_var TF_STATE_RESOURCE_GROUP "$STATE_RG"
set_var TF_STATE_STORAGE_ACCOUNT "$STATE_SA"
set_var TF_STATE_CONTAINER "$STATE_CONTAINER"
if [ "$DEPLOYMENT_ORCHESTRATION_MODE_EXPLICIT" -eq 1 ]; then
  set_var DEPLOYMENT_ORCHESTRATION_MODE "$DEPLOYMENT_ORCHESTRATION_MODE"
  set_var DEPLOYMENT_GITHUB_REPOSITORY "$DEPLOYMENT_GITHUB_REPOSITORY"
  set_var DEPLOYMENT_GITHUB_REF "$DEPLOYMENT_GITHUB_REF"
  set_var DEPLOYMENT_GITHUB_TOKEN_SECRET_ID "$DEPLOYMENT_GITHUB_TOKEN_SECRET_ID"
else
  log "preserved existing deployment orchestration variables; pass --deployment-orchestration-mode explicitly to change them"
fi

step "Done"
if [ "$DRY_RUN" -eq 1 ]; then
  log "Dry-run preview only: no cloud command was executed and no readiness claim is made."
  COMPLETION_HEADING="Bootstrap complete is not claimed: dry-run preview finished"
else
  COMPLETION_HEADING="Bootstrap complete"
fi
cat <<SUMMARY

$COMPLETION_HEADING for '$ENVIRONMENT'.

  subscription   $SUBSCRIPTION
  tenant         $TENANT_ID
  client id      $APP_ID
  console app id $CONSOLE_APP_ID
  state backend  $STATE_RG / $STATE_SA / $STATE_CONTAINER

Still required before the first deploy:

  1. Recheck the '$ENVIRONMENT' environment and its required reviewers:
       https://github.com/$REPO/settings/environments
     Bootstrap refused to continue unless required-reviewer protection was
     present and administrator bypass was disabled.

  2. Assign console roles to your people in the portal (App registrations ->
     $CONSOLE_APP_NAME -> Enterprise application -> Users and groups). The
     platform requires SEPARATE security_approver and privacy_approver
     holders: one person cannot approve their own campaign, and on Azure the
     two-person rule is enforced and cannot be switched off.

  3. Enter the console app id, hostnames, recipient allowlist, customer-managed
     ACS sender, reviewed quota/pacing, and optional Microsoft 365 roles in the
     Azure deployment GUI. Those values belong to the reviewed non-secret
     deployment_config input, not mutable repository variables.

  4. If GUI orchestration is enabled after the foundation phase, insert the
     externally issued GitHub credential directly into the deployment Key Vault.
     Configure only its versionless secret resource ID in the protected GitHub
     environment. This script never accepts or prints the credential value.

The workflow input contract is shown below for break-glass review only. Normal
deployment is dispatched from the GUI, which creates the opaque request id,
canonical deployment configuration, and reviewed commit binding:

       gh workflow run "Azure deployment" --repo $REPO \\
         --ref '<reviewed-ref>' \\
         -f environment=$ENVIRONMENT \\
         -f network_mode=private \\
         -f deployment_phase=foundation_bootstrap \\
         -f deployment_config='<canonical-json-from-reviewed-gui-plan>' \\
         -f deployment_request_id='kp-<32-lowercase-hex>-<attempt>' \\
         -f reviewed_commit_sha='<40-lowercase-commit-sha>'

Do not invent those reviewed values by hand. A direct command is not equivalent
to the GUI's review digest, source-drift check, audit record, or protected-
environment preflight, and is never production/RSA evidence.

SUMMARY
