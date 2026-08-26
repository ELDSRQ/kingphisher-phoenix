#!/usr/bin/env bash
#
# Pre-deployment readiness check for a new Azure tenant.
#
# The deployment workflow takes roughly twenty minutes and provisions real
# infrastructure. Almost everything that makes a FIRST deployment fail is
# knowable in seconds beforehand: an unregistered resource provider, a missing
# role, a region that does not offer Azure Communication Services, a GitHub
# variable nobody set. This checks those, changes nothing, and exits non-zero if
# the tenant is not ready.
#
# Usage:
#   scripts/azure_preflight.sh --subscription <id> [--repo owner/name]
#       [--environment staging] [--location eastus2] [--json]
#
# Exit codes: 0 ready, 1 blocked, 2 could not check (not logged in, bad args).

set -euo pipefail

SUBSCRIPTION=""
REPO=""
ENVIRONMENT="staging"
LOCATION="eastus2"
JSON=0

PASS=0
WARN=0
FAIL=0
RESULTS=()

die() { printf '\nerror: %s\n' "$*" >&2; exit 2; }

record() { # kind name detail
  RESULTS+=("$1|$2|$3")
  case "$1" in
    pass) PASS=$((PASS + 1)); [ "$JSON" -eq 1 ] || printf '  \033[32m✓\033[0m %-34s %s\n' "$2" "$3" ;;
    warn) WARN=$((WARN + 1)); [ "$JSON" -eq 1 ] || printf '  \033[33m!\033[0m %-34s %s\n' "$2" "$3" ;;
    fail) FAIL=$((FAIL + 1)); [ "$JSON" -eq 1 ] || printf '  \033[31m✗\033[0m %-34s %s\n' "$2" "$3" ;;
  esac
}

section() { [ "$JSON" -eq 1 ] || printf '\n== %s\n' "$1"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --subscription) SUBSCRIPTION="${2:-}"; shift 2 ;;
    --repo)         REPO="${2:-}"; shift 2 ;;
    --environment)  ENVIRONMENT="${2:-}"; shift 2 ;;
    --location)     LOCATION="${2:-}"; shift 2 ;;
    --json)         JSON=1; shift ;;
    -h|--help)      sed -n '2,17p' "$0"; exit 0 ;;
    *)              die "unknown argument: $1" ;;
  esac
done

[ -n "$SUBSCRIPTION" ] || die "--subscription is required"

# --- tooling -----------------------------------------------------------------
section "Tooling"
command -v az >/dev/null 2>&1 || die "the Azure CLI (az) is not installed"
record pass "azure cli" "$(az version --query '"azure-cli"' -o tsv 2>/dev/null || echo present)"

if command -v gh >/dev/null 2>&1; then
  record pass "github cli" "installed"
else
  record warn "github cli" "not installed; repository variables cannot be checked"
fi

az account show >/dev/null 2>&1 || die "not logged in to Azure; run: az login"

# --- subscription and identity ----------------------------------------------
section "Subscription"
if ! ACCOUNT_JSON="$(az account show --subscription "$SUBSCRIPTION" -o json 2>/dev/null)"; then
  record fail "subscription" "not visible to this login"
  ACCOUNT_JSON=""
else
  TENANT_ID="$(printf '%s' "$ACCOUNT_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["tenantId"])')"
  STATE="$(printf '%s' "$ACCOUNT_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("state",""))')"
  record pass "subscription" "$SUBSCRIPTION"
  record pass "tenant" "$TENANT_ID"
  if [ "$STATE" = "Enabled" ]; then
    record pass "subscription state" "$STATE"
  else
    record fail "subscription state" "$STATE (must be Enabled)"
  fi
fi

# Terraform assigns roles to a managed identity, which plain Contributor cannot
# do. Missing this is the single most common first-deploy failure.
section "Permissions"
SIGNED_IN="$(az ad signed-in-user show --query id -o tsv 2>/dev/null || echo "")"
if [ -z "$SIGNED_IN" ]; then
  record warn "role assignments" "cannot read the signed-in principal (service principal login?); check roles manually"
else
  ROLES="$(az role assignment list --assignee "$SIGNED_IN" --scope "/subscriptions/$SUBSCRIPTION" \
    --include-inherited --query '[].roleDefinitionName' -o tsv 2>/dev/null || echo "")"
  if printf '%s' "$ROLES" | grep -qx "Owner"; then
    record pass "role assignments" "Owner"
  elif printf '%s' "$ROLES" | grep -qx "User Access Administrator" && printf '%s' "$ROLES" | grep -qx "Contributor"; then
    record pass "role assignments" "Contributor + User Access Administrator"
  else
    record fail "role assignments" "need Owner, or Contributor + User Access Administrator (found: ${ROLES//$'\n'/, })"
  fi
fi

# --- resource providers ------------------------------------------------------
# An unregistered provider fails the apply several minutes in, with an error
# that does not obviously mean "run az provider register".
section "Resource providers"
for provider in \
  Microsoft.App \
  Microsoft.ContainerRegistry \
  Microsoft.DBforPostgreSQL \
  Microsoft.Cache \
  Microsoft.KeyVault \
  Microsoft.Communication \
  Microsoft.OperationalInsights \
  Microsoft.Insights \
  Microsoft.Network \
  Microsoft.Storage ; do
  state="$(az provider show --namespace "$provider" --subscription "$SUBSCRIPTION" \
    --query registrationState -o tsv 2>/dev/null || echo "Unknown")"
  case "$state" in
    Registered)   record pass "$provider" "registered" ;;
    Registering)  record warn "$provider" "still registering" ;;
    *)            record fail "$provider" "$state — run: az provider register --namespace $provider" ;;
  esac
done

# --- region capability -------------------------------------------------------
section "Region"
if az account list-locations --subscription "$SUBSCRIPTION" --query "[?name=='$LOCATION'].name" -o tsv 2>/dev/null | grep -q .; then
  record pass "location" "$LOCATION"
else
  record fail "location" "$LOCATION is not available to this subscription"
fi

if az provider show --namespace Microsoft.App --subscription "$SUBSCRIPTION" \
    --query "resourceTypes[?resourceType=='managedEnvironments'].locations[]" -o tsv 2>/dev/null \
    | tr '[:upper:]' '[:lower:]' | tr -d ' ' | grep -qx "$(printf '%s' "$LOCATION" | tr -d ' ')"; then
  record pass "container apps in region" "$LOCATION"
else
  record warn "container apps in region" "could not confirm Container Apps in $LOCATION"
fi

# --- email -------------------------------------------------------------------
# Simulated phishing must not go out from corporate mail. The deployment
# provisions an Azure-managed sending domain, which is a separate domain that
# needs no DNS work; this confirms the tenant can create one.
section "Email (Azure Communication Services)"
COMM_STATE="$(az provider show --namespace Microsoft.Communication --subscription "$SUBSCRIPTION" \
  --query registrationState -o tsv 2>/dev/null || echo Unknown)"
if [ "$COMM_STATE" = "Registered" ]; then
  record pass "communication provider" "registered"
  record pass "sending domain" "AzureManaged — a separate domain, no DNS records required"
else
  record fail "communication provider" "$COMM_STATE — email cannot be provisioned"
fi
record warn "send limits" "Azure-managed domains are rate limited and intended for testing; use a custom domain for volume"

# --- GitHub variables --------------------------------------------------------
if [ -n "$REPO" ] && command -v gh >/dev/null 2>&1; then
  section "GitHub repository variables"
  if VARS="$(gh variable list --repo "$REPO" --json name -q '.[].name' 2>/dev/null)"; then
    for required in AZURE_SUBSCRIPTION_ID AZURE_TENANT_ID AZURE_CLIENT_ID \
                    ENTRA_APPLICATION_CLIENT_ID OPERATOR_FQDN TRACKING_FQDN \
                    ALLOWED_RECIPIENT_DOMAINS TF_STATE_RESOURCE_GROUP \
                    TF_STATE_STORAGE_ACCOUNT TF_STATE_CONTAINER ; do
      if printf '%s\n' "$VARS" | grep -qx "$required"; then
        record pass "$required" "set"
      elif [ "$required" = "ALLOWED_RECIPIENT_DOMAINS" ]; then
        # Fails closed under OIDC: with this empty nothing can be imported or sent.
        record fail "$required" "REQUIRED — recipient import and delivery are refused without it"
      else
        record fail "$required" "not set — run scripts/azure_bootstrap.sh, or set it manually"
      fi
    done
    if gh api "repos/$REPO/environments/$ENVIRONMENT" >/dev/null 2>&1; then
      record pass "environment '$ENVIRONMENT'" "exists"
    else
      record fail "environment '$ENVIRONMENT'" "not created — the deploy job runs as this environment"
    fi
  else
    record warn "repository variables" "could not read $REPO (not logged in, or no access)"
  fi
fi

# --- verdict -----------------------------------------------------------------
if [ "$JSON" -eq 1 ]; then
  python3 - "$PASS" "$WARN" "$FAIL" "${RESULTS[@]}" <<'PYJSON'
import json, sys
passed, warned, failed = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
checks = []
for row in sys.argv[4:]:
    kind, name, detail = row.split("|", 2)
    checks.append({"result": kind, "check": name, "detail": detail})
print(json.dumps({
    "ready": failed == 0,
    "passed": passed, "warnings": warned, "failed": failed,
    "checks": checks,
}, indent=2))
PYJSON
else
  printf '\n%s passed, %s warnings, %s blocking\n' "$PASS" "$WARN" "$FAIL"
  if [ "$FAIL" -eq 0 ]; then
    printf '\nThis tenant looks ready. Deploy with:\n'
    printf '  gh workflow run "Azure deployment" --repo %s \\\n' "${REPO:-<owner>/<repo>}"
    printf '    -f environment=%s -f network_mode=starter\n\n' "$ENVIRONMENT"
  else
    printf '\nResolve the blocking items above before deploying.\n\n'
  fi
fi

[ "$FAIL" -eq 0 ] || exit 1
