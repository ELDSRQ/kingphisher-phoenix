#!/usr/bin/env bash
#
# AZ-030 operator runbook — validated readiness + exact reviewed staging plan guide.
#
# Run on the controller Mac (the operator workstation with az + gh signed in).
# This script is READ-ONLY: it never mutates Azure, GitHub, or the repository.
# It (1) verifies the external prerequisites the reviewed deployment needs,
# (2) prints the exact `foundation_bootstrap` staging values to enter in the
# console Deployment GUI, with subscription/tenant prefilled from live `az`,
# and (3) tells you the script to run after the GUI returns the reviewed
# values file. A fabricated values file is never production/RSA evidence, so
# the file itself must come from the GUI (see STEP B), not from this script.
#
# Exit codes: 0 readiness OK (proceed to STEP B), 1 blocker found, 2 could not check.

set -euo pipefail

# --- auto-discover repo root -------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_here_is_repo_root() { [ -f "$1/RESUME-HERE.md" ] && [ -d "$1/scripts" ]; }
if _here_is_repo_root "$SCRIPT_DIR/../../.."; then
  REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
elif _here_is_repo_root "$SCRIPT_DIR/../../../../.."; then
  REPO_ROOT="$(cd "$SCRIPT_DIR/../../../../.." && pwd)"
else
  echo "error: could not resolve repo root from $SCRIPT_DIR" >&2
  exit 2
fi
PREFLIGHT="$REPO_ROOT/scripts/azure_preflight.sh"
PREFLIGHT_EXISTS=0; [ -x "$PREFLIGHT" ] && PREFLIGHT_EXISTS=1

PASS=0; WARN=0; FAIL=0
note()  { printf '  \033[32m✓\033[0m %-34s %s\n' "$1" "$2"; PASS=$((PASS+1)); }
warn()  { printf '  \033[33m!\033[0m %-34s %s\n' "$1" "$2"; WARN=$((WARN+1)); }
fail()  { printf '  \033[31m✗\033[0m %-34s %s\n' "$1" "$2"; FAIL=$((FAIL+1)); }

UUID_RE='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

SUBSCRIPTION="${AZURE_SUBSCRIPTION_ID:-}"
if [ $# -ge 1 ] && [ -n "$1" ]; then SUBSCRIPTION="$1"; fi
REPO="${2:-ELDSRQ/kingphisher-phoenix}"
ENVIRONMENT="${3:-staging}"
LOCATION="${4:-eastus2}"
OPERATOR_FQDN="${5:-}"
TRACKING_FQDN="${6:-}"

printf '%s\n' ""
printf 'AZ-030 operator runbook — %s / %s\n' "$REPO" "$ENVIRONMENT"
printf 'repo root  : %s\n' "$REPO_ROOT"
printf 'preflight  : %s\n' "$PREFLIGHT"
printf '%s\n' "--------------------------------------------"

command -v az >/dev/null 2>&1 || { fail "az CLI" "does not exist in PATH"; }
command -v gh  >/dev/null 2>&1 || { warn "gh CLI" "does not exist in PATH; not every check can run"; }
if ! command -v az >/dev/null 2>&1; then
  echo "^ reach a blocker: install Azure CLI (brew install azure-cli) and sign in" >&2
  exit 1
fi

# --- subscription ------------------------------------------------------------
if [ -z "$SUBSCRIPTION" ]; then SUBSCRIPTION="$(az account show --query id -o tsv 2>/dev/null || true)"; fi
if [ -z "$SUBSCRIPTION" ]; then
  fail "active subscription" "none selected; run: az login then az account set --subscription <id>"
else
  if [[ "$SUBSCRIPTION" =~ $UUID_RE ]]; then
    ACCOUNT="$(az account show --subscription "$SUBSCRIPTION" -o json 2>/dev/null || true)"
    if [ -n "$ACCOUNT" ]; then
      state="$(printf '%s' "$ACCOUNT" | sed -n 's/.*"state"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
      if [ "$state" = "Enabled" ]; then
        note "subscription $SUBSCRIPTION" "state $state"
      else
        warn "subscription $SUBSCRIPTION" "state '$state' (must be Enabled)"
      fi
    else
      warn "subscription $SUBSCRIPTION" "az account show failed (is it the right id? signed in?)"
    fi
  else
    fail "subscription" "'$SUBSCRIPTION' is not a UUID"
  fi
fi

# --- Microsoft Entra tenant --------------------------------------------------
TENANT="$(az account show --query tenantId -o tsv 2>/dev/null || true)"
if [ -n "$TENANT" ]; then
  note "Entra tenant id" "live-fetched for the GUI plan ($TENANT)"
else
  warn "Entra tenant id" "could not derive tenantId from az account show"
fi

# --- two hostnames -----------------------------------------------------------
_resolve_host() {
  # Cross-platform DNS resolution: macOS lacks getent, Linux lacks dscacheutil.
  # Prints one bare address, or nothing. It must never fail: an unresolvable
  # hostname is the normal pre-GUI state and has to warn, not abort the runbook
  # under `set -euo pipefail`.
  local host="$1"
  if command -v getent >/dev/null 2>&1; then
    getent hosts "$host" 2>/dev/null | awk 'NR == 1 { print $1 }' || true
  elif command -v dscacheutil >/dev/null 2>&1; then
    dscacheutil -q host -a name "$host" 2>/dev/null | awk '/ip_address:/ { print $2; exit }' || true
  elif command -v python3 >/dev/null 2>&1; then
    # Pass host as argv to avoid shell injection; do not interpolate into -c string.
    python3 -c 'import socket,sys; print(socket.getaddrinfo(sys.argv[1], 443)[0][4][0])' "$host" 2>/dev/null || true
  fi
  return 0
}
for pair in "operator:$OPERATOR_FQDN" "tracking:$TRACKING_FQDN"; do
  role="${pair%%:*}"; host="${pair#*:}"
  if [ -z "$host" ]; then
    warn "$role hostname" "not supplied as arg; you must choose a dedicated hostname in a zone you control"
  else
    addr="$(_resolve_host "$host" || true)"
    if [ -n "$addr" ]; then
      note "$role hostname $host" "resolves ($addr)"
    else
      warn "$role hostname $host" "does not resolve in DNS (normal pre-gui if the zone alias is created later)"
    fi
  fi
done

# --- GitHub repo connectivity (read-only) -------------------------------------
if command -v gh >/dev/null 2>&1; then
  if gh auth status >/dev/null 2>&1; then
    note "gh auth" "authenticated"
    REPO_INFO="$(gh repo view "$REPO" --json defaultBranchRef 2>/dev/null || true)"
    WORKFLOW="$(gh workflow list -R "$REPO" 2>/dev/null | grep -i 'Azure deployment' || true)"
    if [ -n "$REPO_INFO" ] && printf '%s' "$WORKFLOW" | grep -qi 'active'; then
      note "repo $REPO" "readable and the Azure deployment workflow is active"
    else
      warn "repo $REPO" "repo or Azure deployment workflow not visible via gh (scope/visibility?)"
    fi
  else
    warn "gh auth" "not authenticated; run: gh auth login"
  fi
fi

# --- ready-to-run preflight (after GUI values export) --------------------------
if [ "$PREFLIGHT_EXISTS" = 1 ]; then
  note "preflight script" "$PREFLIGHT (run after the GUI exports reviewed values)"
else
  warn "preflight script" "$PREFLIGHT missing"
fi

# --- summary -------------------------------------------------------------------
printf '\n'
printf '  passed: %d   warnings: %d   blockers: %d\n' "$PASS" "$WARN" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
  printf '\nA blocker was found above; resolve it before the GUI plan. Exit 1.\n' >&2
  exit 1
fi

printf '%s\n' ""
printf '%s\n' "STEP A complete (readiness OK in this environment at $(date -u +%Y-%m-%dT%H:%M:%SZ))."
printf '%s\n' ""
printf '%s\n' "STEP B — fill the reviewed staging plan in the console Deployment GUI:"
printf '%s\n' "  (the values file MUST come from the GUI; this table is your checklist)"
printf '%-30s %-46s %s\n' "field" "value to enter" "notes"
printf '%s\n' "---------------------------------------------------------------"
cat <<TABLE
subscription_id                 $SUBSCRIPTION                  live-verified above
environment                     $ENVIRONMENT                   staging (production is blocked by the GUI)
deployment_stage               foundation_bootstrap           must be the first stage
location                        $LOCATION                      region code e.g. eastus2
name_prefix                     kp                             short lowercase prefix
entra_tenant_id                 $TENANT                        from az, above
entra_client_id                 <console-app-client-id>        Entra > App registrations > your console app
operator_fqdn                   $OPERATOR_FQDN (or blank)      dedicated operator HTTPS hostname
tracking_fqdn                   $TRACKING_FQDN (or blank)      separate tracking HTTPS hostname
acs_resource_mode               provision                      provision (or select existing)
acs_sending_domain              mail.<your-domain>             a DNS domain you control for sending
acs_sender_local_part           awareness                      sender local part
acs_sender_display_name         Security Awareness            display name shown to recipients
acs_daily_message_limit         <reviewed quota>               0..supported quota for the ACS resource
acs_messages_per_minute         <reviewed pacing>              e.g. 20
acs_ramp_batch_size             <reviewed ramp>                e.g. 10
acs_ramp_interval_seconds       <reviewed ramp>               e.g. 60
communication_data_location     United States                  data location (or your approved one)
ai_endpoint                     <your approved AI gateway>     non-local HTTPS (internal-model path)
enable_directory_sync           false                          enable later after a tenant admin reviews grants
enable_reported_mailbox         false                          later, with a reviewed mailbox
allowed_recipient_domains       <your target domain(s)>        EXACT domains recipients may sit in
network_mode                    private                        private is required by the GUI stage sequence
TABLE
printf '%s\n' "---------------------------------------------------------------"
printf '%s\n' ""
printf 'STEP C — after the GUI returns the opaque request id / canonical config /\n'
printf 'reviewed-commit binding, run the read-only control-plane preflight:\n'
printf '\n    %s --subscription %s --repo %s --environment %s --values-file <downloaded .auto.tfvars>\n' \
  "$PREFLIGHT" "$SUBSCRIPTION" "$REPO" "$ENVIRONMENT"
printf '\nA passing preflight is structural/control-plane evidence only. The live\n(mutating) bootstrap/release still requires separate operator confirmation.\n'
exit 0