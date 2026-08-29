#!/usr/bin/env bash
#
# Read-only, exact-resource ACS email readiness diagnostic.
#
# Usage:
#   scripts/azure_mail_check.sh --resource-group <rg> \
#       --communication-service <name> --email-service <name> \
#       --sending-domain <customer-domain> --sender-local-part <local-part> \
#       [--subscription <id>] [--to <authorized-gui-canary-mailbox>] [--dry-run]
#
# This helper never reads an ACS access key or connection string and never
# sends mail. It inspects the exact configured resources and directs the
# operator to the normal GUI campaign/canary lifecycle for end-to-end proof.

set -euo pipefail

export AZURE_LOGGING_ENABLE_LOG_FILE=false

SUBSCRIPTION=""
RESOURCE_GROUP=""
ACS_NAME=""
EMAIL_SERVICE=""
SENDING_DOMAIN=""
SENDER_LOCAL_PART=""
TO=""
DRY_RUN=0
COMMAND_TIMEOUT_SECONDS="${KP_AZURE_COMMAND_TIMEOUT_SECONDS:-60}"
MAX_CONTROL_PLANE_BYTES=1048576

die() { printf '\nerror: %s\n' "$*" >&2; exit 2; }
log() { printf '  %s\n' "$*"; }
step() { printf '\n== %s\n' "$1"; }
require_argument() {
  [ "$#" -ge 2 ] && [ -n "$2" ] && [ "${2#--}" = "$2" ] || die "$1 requires a value"
}
require_bounded_output() {
  [ "${#2}" -le "$MAX_CONTROL_PLANE_BYTES" ] || \
    die "$1 returned unexpectedly large control-plane metadata"
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
    --resource-group) require_argument "$@"; RESOURCE_GROUP="$2"; shift 2 ;;
    --communication-service) require_argument "$@"; ACS_NAME="$2"; shift 2 ;;
    --email-service) require_argument "$@"; EMAIL_SERVICE="$2"; shift 2 ;;
    --sending-domain) require_argument "$@"; SENDING_DOMAIN="$2"; shift 2 ;;
    --sender-local-part) require_argument "$@"; SENDER_LOCAL_PART="$2"; shift 2 ;;
    --to) require_argument "$@"; TO="$2"; shift 2 ;;
    --dry-run)               DRY_RUN=1; shift ;;
    -h|--help)               sed -n '2,17p' "$0"; exit 0 ;;
    *)                       die "unknown argument; use --help" ;;
  esac
done

if [ -n "$TO" ]; then
  [[ "$TO" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$ ]] || \
    die "--to does not look like an email address"
fi
[ -n "$RESOURCE_GROUP" ] || die "--resource-group is required"
[ -n "$ACS_NAME" ] || die "--communication-service is required; resource guessing is prohibited"
[ -n "$EMAIL_SERVICE" ] || die "--email-service is required; resource guessing is prohibited"
[ -n "$SENDING_DOMAIN" ] || die "--sending-domain is required"
[ -n "$SENDER_LOCAL_PART" ] || die "--sender-local-part is required"
UUID_PATTERN='^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$'
[ -z "$SUBSCRIPTION" ] || [[ "$SUBSCRIPTION" =~ $UUID_PATTERN ]] || die "--subscription must be a UUID"
[[ "$RESOURCE_GROUP" =~ ^[A-Za-z0-9._()-]{1,90}$ ]] || die "--resource-group is invalid"
[[ "$ACS_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9-]{0,62}$ ]] || die "--communication-service is invalid"
[[ "$EMAIL_SERVICE" =~ ^[A-Za-z0-9][A-Za-z0-9-]{0,62}$ ]] || die "--email-service is invalid"
SENDING_DOMAIN="$(printf '%s' "$SENDING_DOMAIN" | tr '[:upper:]' '[:lower:]')"
case "$SENDING_DOMAIN" in
  azurecomm.net|*.azurecomm.net) die "--sending-domain must be customer-managed, not an Azure-managed test domain" ;;
esac
[[ "$SENDING_DOMAIN" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] || \
  die "--sending-domain must be a complete public DNS name"
[[ "$SENDER_LOCAL_PART" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$ ]] || \
  die "--sender-local-part contains unsupported characters"
case "$COMMAND_TIMEOUT_SECONDS" in
  ''|*[!0-9]*) die "KP_AZURE_COMMAND_TIMEOUT_SECONDS must be an integer" ;;
esac
[ "$COMMAND_TIMEOUT_SECONDS" -ge 5 ] && [ "$COMMAND_TIMEOUT_SECONDS" -le 300 ] || \
  die "KP_AZURE_COMMAND_TIMEOUT_SECONDS must be between 5 and 300"

command -v az >/dev/null 2>&1 || die "the Azure CLI (az) is not installed"
AZ_BIN="$(command -v az)"
az() { bounded "$AZ_BIN" "$@"; }
CURRENT_SUBSCRIPTION="$(az account show --query id -o tsv 2>/dev/null)" || \
  die "Azure authentication failed; run: az login"
require_bounded_output "Azure account inspection" "$CURRENT_SUBSCRIPTION"
if [ -z "$SUBSCRIPTION" ]; then
  SUBSCRIPTION="$CURRENT_SUBSCRIPTION"
else
  az account show --subscription "$SUBSCRIPTION" >/dev/null 2>&1 || \
    die "the selected subscription is not visible to this Azure login"
fi
log "subscription: $SUBSCRIPTION"

if [ "$DRY_RUN" -eq 1 ]; then
  log "--dry-run is retained for compatibility; this diagnostic is always read-only"
fi

step "Exact Communication Services resource"
if ! ACS_ROWS="$(az communication list --resource-group "$RESOURCE_GROUP" \
    --subscription "$SUBSCRIPTION" -o json 2>/dev/null)"; then
  die "could not inspect Communication Services in the exact resource group"
fi
require_bounded_output "Communication Services inventory" "$ACS_ROWS"
if ! ACS_JSON="$(ACS_ROWS="$ACS_ROWS" EXACT_NAME="$ACS_NAME" python3 <<'PYACS'
import json
import os

try:
    rows = json.loads(os.environ["ACS_ROWS"])
except json.JSONDecodeError:
    raise SystemExit(2) from None
if not isinstance(rows, list):
    raise SystemExit(2)
matches = [row for row in rows if isinstance(row, dict) and row.get("name") == os.environ["EXACT_NAME"]]
print(json.dumps(matches[0], separators=(",", ":")) if len(matches) == 1 else "")
PYACS
)"; then
  die "Azure returned malformed Communication Services metadata"
fi
[ -n "$ACS_JSON" ] || die "the exact Communication Service '$ACS_NAME' was not found in '$RESOURCE_GROUP'"
ACS_STATE="$(ACS_JSON="$ACS_JSON" python3 -c 'import json,os; row=json.loads(os.environ["ACS_JSON"]); print(row.get("provisioningState", row.get("properties", {}).get("provisioningState", "Unknown")))')"
[ "$ACS_STATE" = "Succeeded" ] || die "the exact Communication Service is not provisioned successfully"
log "communication service: $ACS_NAME"
log "provisioning:         $ACS_STATE"

step "Exact Email Communication Service"
if ! EMAIL_ROWS="$(az communication email list --resource-group "$RESOURCE_GROUP" \
    --subscription "$SUBSCRIPTION" -o json 2>/dev/null)"; then
  die "could not inspect Email Communication Services in the exact resource group"
fi
require_bounded_output "Email Communication Services inventory" "$EMAIL_ROWS"
if ! EMAIL_JSON="$(EMAIL_ROWS="$EMAIL_ROWS" EXACT_NAME="$EMAIL_SERVICE" python3 <<'PYEMAIL'
import json
import os

try:
    rows = json.loads(os.environ["EMAIL_ROWS"])
except json.JSONDecodeError:
    raise SystemExit(2) from None
if not isinstance(rows, list):
    raise SystemExit(2)
matches = [row for row in rows if isinstance(row, dict) and row.get("name") == os.environ["EXACT_NAME"]]
print(json.dumps(matches[0], separators=(",", ":")) if len(matches) == 1 else "")
PYEMAIL
)"; then
  die "Azure returned malformed Email Communication Services metadata"
fi
[ -n "$EMAIL_JSON" ] || die "the exact Email Communication Service '$EMAIL_SERVICE' was not found in '$RESOURCE_GROUP'"
EMAIL_STATE="$(EMAIL_JSON="$EMAIL_JSON" python3 -c 'import json,os; row=json.loads(os.environ["EMAIL_JSON"]); print(row.get("provisioningState", row.get("properties", {}).get("provisioningState", "Unknown")))')"
log "email service: $EMAIL_SERVICE"
log "provisioning:  $EMAIL_STATE"
[ "$EMAIL_STATE" = "Succeeded" ] || die "the exact Email Communication Service is not provisioned successfully"

step "Customer-managed domain verification"
if ! DOMAIN_ROWS="$(az communication email domain list \
    --resource-group "$RESOURCE_GROUP" --email-service-name "$EMAIL_SERVICE" \
    --subscription "$SUBSCRIPTION" -o json 2>/dev/null)"; then
  die "could not inspect domains on the exact Email Communication Service"
fi
require_bounded_output "email-domain inventory" "$DOMAIN_ROWS"
if ! DOMAIN_JSON="$(DOMAIN_ROWS="$DOMAIN_ROWS" EXACT_DOMAIN="$SENDING_DOMAIN" python3 <<'PYDOMAIN'
import json
import os

try:
    rows = json.loads(os.environ["DOMAIN_ROWS"])
except json.JSONDecodeError:
    raise SystemExit(2) from None
if not isinstance(rows, list):
    raise SystemExit(2)
expected = os.environ["EXACT_DOMAIN"]
matches = [
    row for row in rows
    if isinstance(row, dict)
    and str(row.get("name", "")).lower() == expected
    and str(row.get("fromSenderDomain", row.get("properties", {}).get("fromSenderDomain", ""))).lower() == expected
]
print(json.dumps(matches[0], separators=(",", ":")) if len(matches) == 1 else "")
PYDOMAIN
)"; then
  die "Azure returned malformed email-domain metadata"
fi
[ -n "$DOMAIN_JSON" ] || die "the exact customer domain '$SENDING_DOMAIN' was not found with a matching sender domain"

while IFS=$'\t' read -r name status; do
  log "$name: $status"
  [ "$(printf '%s' "$status" | tr '[:upper:]' '[:lower:]')" = "verified" ] || die "$name is not Verified"
done < <(DOMAIN_JSON="$DOMAIN_JSON" python3 <<'PYSTATUS'
import json
import os

row = json.loads(os.environ["DOMAIN_JSON"])
states = row.get("verificationStates", row.get("properties", {}).get("verificationStates", {}))
if not isinstance(states, dict):
    states = {}
for expected in ("Domain", "SPF", "DKIM", "DKIM2"):
    match = next((value for key, value in states.items() if str(key).lower() == expected.lower()), {})
    status = match.get("status", "Unknown") if isinstance(match, dict) else "Unknown"
    print(expected, status, sep="\t")
PYSTATUS
)

DOMAIN_MANAGEMENT="$(DOMAIN_JSON="$DOMAIN_JSON" python3 -c 'import json,os; row=json.loads(os.environ["DOMAIN_JSON"]); print(row.get("domainManagement", row.get("properties", {}).get("domainManagement", "Unknown")))')"
case "$(printf '%s' "$DOMAIN_MANAGEMENT" | tr '[:upper:]' '[:lower:]')" in
  customermanaged|customer-managed) log "domain management: customer-managed" ;;
  *) die "the exact domain is not reported as customer-managed" ;;
esac
DOMAIN_ID="$(DOMAIN_JSON="$DOMAIN_JSON" python3 -c 'import json,os; print(json.loads(os.environ["DOMAIN_JSON"]).get("id", ""))')"
[ -n "$DOMAIN_ID" ] || die "the exact domain has no Azure resource ID"

LINKED="$(ACS_JSON="$ACS_JSON" DOMAIN_ID="$DOMAIN_ID" python3 <<'PYLINK'
import json
import os

row = json.loads(os.environ["ACS_JSON"])
properties = row.get("properties", {}) if isinstance(row.get("properties"), dict) else {}
linked = row.get("linkedDomains", properties.get("linkedDomains", []))
expected = os.environ["DOMAIN_ID"].lower().rstrip("/")
print("yes" if isinstance(linked, list) and any(str(item).lower().rstrip("/") == expected for item in linked) else "no")
PYLINK
)"
[ "$LINKED" = "yes" ] || die "the exact customer domain is not linked to '$ACS_NAME'"
log "domain association: linked to $ACS_NAME"

step "Exact sender username"
SENDER_ID="${DOMAIN_ID%/}/senderUsernames/${SENDER_LOCAL_PART}"
if ! SENDER_JSON="$(az resource show --ids "$SENDER_ID" --api-version 2023-03-31 \
    --subscription "$SUBSCRIPTION" -o json 2>/dev/null)"; then
  die "could not inspect the exact sender username"
fi
require_bounded_output "sender username inspection" "$SENDER_JSON"
[ -n "$SENDER_JSON" ] || die "the exact sender username '$SENDER_LOCAL_PART' was not found"
SENDER_STATE="$(SENDER_JSON="$SENDER_JSON" python3 -c 'import json,os; row=json.loads(os.environ["SENDER_JSON"]); print(row.get("properties", {}).get("provisioningState", row.get("provisioningState", "Unknown")))')"
[ "$SENDER_STATE" = "Succeeded" ] || die "the exact sender username is not provisioned successfully"
log "configured sender: ${SENDER_LOCAL_PART}@${SENDING_DOMAIN}"
log "provisioning:     $SENDER_STATE"

cat <<SUMMARY

Read-only ACS control-plane checks passed for the exact configured resources.
No credential, access key, connection string, or bearer token was read, and no
message was sent.

This does not prove the delivery worker's managed identity, current ACS quota,
campaign safety gates, provider acceptance, Event Grid receipt processing,
destination-MTA handoff, inbox placement, or production/RSA readiness.

Next, use the operator GUI to create an authorized one-recipient canary campaign,
freeze the exact audience, obtain separate approvals, schedule it, and verify
the assignment progresses through provider acceptance to the authenticated ACS
delivery receipt. Record Azure quota and pacing evidence alongside that run.
SUMMARY

if [ -n "$TO" ]; then
  printf '\n  A GUI canary recipient was supplied but was not contacted.\n'
fi
printf '\n'
