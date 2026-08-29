#!/usr/bin/env bash
#
# Read-only control-plane preflight for a reviewed Azure deployment.
#
# Usage:
#   scripts/azure_preflight.sh --subscription <id> --repo <owner/name> \
#       --values-file <gui-exported.auto.tfvars> \
#       [--environment staging] [--location eastus2] [--json]
#
# The values file is the non-secret Terraform export downloaded from the Azure
# deployment GUI. This script never asks for a token, password, connection
# string, or Terraform state. A passing result is structural/control-plane
# evidence only, never live delivery or production/RSA readiness evidence.
#
# Exit codes: 0 no detected preflight blockers, 1 blocked, 2 could not check.

set -euo pipefail

export AZURE_LOGGING_ENABLE_LOG_FILE=false

SUBSCRIPTION=""
REPO=""
VALUES_FILE=""
ENVIRONMENT="staging"
LOCATION="eastus2"
JSON=0
COMMAND_TIMEOUT_SECONDS="${KP_AZURE_COMMAND_TIMEOUT_SECONDS:-60}"
MAX_CONTROL_PLANE_BYTES=8388608

PASS=0
WARN=0
FAIL=0
RESULTS=()
VALUES_JSON=""

die() {
  if [ "$JSON" -eq 1 ]; then
    python3 - "$*" <<'PYFATAL'
import json
import sys

print(json.dumps({
    "ready": False,
    "evidence_level": "control_plane_preflight_only",
    "production_ready": False,
    "passed": 0,
    "warnings": 0,
    "failed": 1,
    "checks": [{"result": "fail", "check": "preflight execution", "detail": sys.argv[1]}],
}, indent=2))
PYFATAL
  else
    printf '\nerror: %s\n' "$*" >&2
  fi
  exit 2
}

require_argument() {
  [ "$#" -ge 2 ] && [ -n "$2" ] && [ "${2#--}" = "$2" ] || die "$1 requires a value"
}
require_bounded_output() {
  [ "${#2}" -le "$MAX_CONTROL_PLANE_BYTES" ] || \
    die "$1 returned unexpectedly large control-plane metadata"
}

record() { # kind name detail
  RESULTS+=("$1|$2|$3")
  case "$1" in
    pass) PASS=$((PASS + 1)); [ "$JSON" -eq 1 ] || printf '  \033[32m✓\033[0m %-34s %s\n' "$2" "$3" ;;
    warn) WARN=$((WARN + 1)); [ "$JSON" -eq 1 ] || printf '  \033[33m!\033[0m %-34s %s\n' "$2" "$3" ;;
    fail) FAIL=$((FAIL + 1)); [ "$JSON" -eq 1 ] || printf '  \033[31m✗\033[0m %-34s %s\n' "$2" "$3" ;;
  esac
}

section() { [ "$JSON" -eq 1 ] || printf '\n== %s\n' "$1"; }

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
    --values-file) require_argument "$@"; VALUES_FILE="$2"; shift 2 ;;
    --environment) require_argument "$@"; ENVIRONMENT="$2"; shift 2 ;;
    --location) require_argument "$@"; LOCATION="$2"; shift 2 ;;
    --json)         JSON=1; shift ;;
    -h|--help)      sed -n '2,18p' "$0"; exit 0 ;;
    *)              die "unknown argument; use --help" ;;
  esac
done

[ -n "$SUBSCRIPTION" ] || die "--subscription is required"
UUID_PATTERN='^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$'
[[ "$SUBSCRIPTION" =~ $UUID_PATTERN ]] || die "--subscription must be a UUID"
case "$ENVIRONMENT" in
  staging|production) ;;
  *) die "--environment must be 'staging' or 'production'" ;;
esac
REPOSITORY_PATTERN='^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$'
[ -z "$REPO" ] || [[ "$REPO" =~ $REPOSITORY_PATTERN ]] || \
  die "--repo must use a valid owner/name format"
[[ "$LOCATION" =~ ^[a-z0-9]+$ ]] || die "--location must be an Azure region code such as eastus2"
case "$COMMAND_TIMEOUT_SECONDS" in
  ''|*[!0-9]*) die "KP_AZURE_COMMAND_TIMEOUT_SECONDS must be an integer" ;;
esac
[ "$COMMAND_TIMEOUT_SECONDS" -ge 5 ] && [ "$COMMAND_TIMEOUT_SECONDS" -le 300 ] || \
  die "KP_AZURE_COMMAND_TIMEOUT_SECONDS must be between 5 and 300"

# --- tooling -----------------------------------------------------------------
section "Tooling"
command -v az >/dev/null 2>&1 || die "the Azure CLI (az) is not installed"
AZ_BIN="$(command -v az)"
az() { bounded "$AZ_BIN" "$@"; }
record pass "azure cli" "$(az version --query '"azure-cli"' -o tsv 2>/dev/null || echo present)"

GH_AVAILABLE=0
GH_AUTHENTICATED=0
if command -v gh >/dev/null 2>&1; then
  GH_BIN="$(command -v gh)"
  gh() { bounded "$GH_BIN" "$@"; }
  GH_AVAILABLE=1
  record pass "github cli" "installed"
  if gh auth status >/dev/null 2>&1; then
    GH_AUTHENTICATED=1
    record pass "github authentication" "active token accepted"
  else
    record fail "github authentication" "token is missing or invalid; run gh auth login"
  fi
else
  record fail "github cli" "required to inspect the protected deployment environment"
fi

ACCOUNT_JSON="$(az account show --subscription "$SUBSCRIPTION" -o json 2>/dev/null)" || \
  die "Azure authentication failed or the selected subscription is not visible; run: az login"
require_bounded_output "Azure account inspection" "$ACCOUNT_JSON"

# --- GUI-exported non-secret configuration -----------------------------------
section "Reviewed GUI values"
if [ -z "$VALUES_FILE" ]; then
  record fail "GUI values export" "--values-file is required; download Terraform values from the Azure deployment GUI"
elif [ ! -f "$VALUES_FILE" ]; then
  record fail "GUI values export" "the selected file does not exist"
elif [ ! -r "$VALUES_FILE" ]; then
  record fail "GUI values export" "the selected file is not readable"
else
  if VALUES_JSON="$(python3 - "$VALUES_FILE" 2>/dev/null <<'PYVALUES'
import json
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
if path.stat().st_size > 65_536:
    raise SystemExit("GUI values export exceeds 64 KiB")
values = {}
for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    match = re.fullmatch(r"([a-z][a-z0-9_]*)\s*=\s*(.+)", line)
    if match is None:
        raise SystemExit(f"GUI values export has an unsupported line at {number}")
    key, encoded = match.groups()
    if key in values:
        raise SystemExit(f"GUI values export repeats {key}")
    try:
        value = json.loads(encoded)
    except json.JSONDecodeError:
        raise SystemExit(f"GUI values export has an invalid value at line {number}") from None
    if not isinstance(value, (str, int, bool)):
        raise SystemExit(f"GUI values export has an unsupported value at line {number}")
    if isinstance(value, str) and (len(value) > 2_048 or "\n" in value or "\r" in value):
        raise SystemExit(f"GUI values export has an unbounded or multiline value at line {number}")
    values[key] = value
print(json.dumps(values, separators=(",", ":"), sort_keys=True))
PYVALUES
  )"; then
    record pass "GUI values export" "parsed as bounded non-secret configuration"
    while IFS=$'\t' read -r kind name detail; do
      [ -n "$kind" ] && record "$kind" "$name" "$detail"
    done < <(VALUES_JSON="$VALUES_JSON" EXPECTED_ENVIRONMENT="$ENVIRONMENT" EXPECTED_LOCATION="$LOCATION" python3 <<'PYVALIDATE'
import json
import os
import re
from urllib.parse import urlparse

values = json.loads(os.environ["VALUES_JSON"])

def text(key: str) -> str:
    value = values.get(key, "")
    return value.strip() if isinstance(value, str) else str(value)

def emit(kind: str, name: str, detail: str) -> None:
    print(kind, name, detail, sep="\t")

required = (
    "subscription_id", "entra_tenant_id", "entra_client_id", "acs_resource_mode",
    "acs_sending_domain", "acs_sender_local_part", "acs_sender_display_name",
    "acs_daily_message_limit", "acs_messages_per_minute", "acs_ramp_batch_size",
    "acs_ramp_interval_seconds", "graph_endpoint", "directory_group_ids",
    "reported_mailbox_endpoint", "reported_mailbox_address", "reported_mailbox_folder",
    "allowed_recipient_domains",
)
missing = [key for key in required if key not in values]
if missing:
    emit("fail", "GUI value contract", "missing required keys from the current GUI export")
else:
    emit("pass", "GUI value contract", "current ACS, pacing, directory, mailbox, and safety keys are present")

expected = {
    "subscription_id", "environment", "location", "name_prefix", "operator_fqdn",
    "tracking_fqdn", "entra_tenant_id", "entra_client_id", "communication_data_location",
    "acs_resource_mode", "acs_existing_communication_service_id", "acs_existing_email_endpoint",
    "acs_existing_email_domain_id", "acs_sending_domain", "acs_sender_local_part",
    "acs_sender_display_name", "acs_dns_zone_id", "acs_daily_message_limit",
    "acs_messages_per_minute", "acs_ramp_batch_size", "acs_ramp_interval_seconds",
    "ai_endpoint", "graph_endpoint", "directory_group_ids", "reported_mailbox_endpoint",
    "reported_mailbox_address", "reported_mailbox_folder", "alert_webhook_domains",
    "allowed_recipient_domains", "ciphertext_active_key_id", "ciphertext_prior_key_ids",
    "ciphertext_prior_keys_secret_id",
}
if set(values) == expected:
    emit("pass", "GUI export exactness", "key set matches the current GUI Terraform export")
else:
    emit("fail", "GUI export exactness", "key set is incomplete or contains unrecognized drift")

credential_pattern = re.compile(
    r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|"
    r"(?:password|secret|token|api[_-]?key|authorization|accountkey)\s*[:=]\s*\S+|"
    r"bearer\s+[A-Za-z0-9._~+/=-]{8,})",
    re.IGNORECASE,
)
if any(isinstance(value, str) and credential_pattern.search(value) for value in values.values()):
    emit("fail", "non-secret GUI export", "a credential-like value was rejected")
else:
    emit("pass", "non-secret GUI export", "no credential-like value was detected")

environment = text("environment")
location = text("location")
emit("pass" if environment == os.environ.get("EXPECTED_ENVIRONMENT") else "fail", "reviewed environment binding", "GUI export matches the selected environment" if environment == os.environ.get("EXPECTED_ENVIRONMENT") else "GUI export does not match the selected environment")
emit("pass" if location == os.environ.get("EXPECTED_LOCATION") else "fail", "reviewed location binding", "GUI export matches the selected Azure region" if location == os.environ.get("EXPECTED_LOCATION") else "GUI export does not match the selected Azure region")

domain = text("acs_sending_domain").lower()
domain_ok = bool(re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain))
domain_ok = domain_ok and domain != "azurecomm.net" and not domain.endswith(".azurecomm.net")
emit("pass" if domain_ok else "fail", "customer ACS domain", "customer-managed domain is configured" if domain_ok else "a customer-managed public domain is required; Azure-managed test domains are rejected")

local_part = text("acs_sender_local_part").lower()
sender_ok = bool(re.fullmatch(r"[a-z0-9][a-z0-9._+-]{0,63}", local_part))
display = text("acs_sender_display_name")
display_ok = 1 <= len(display) <= 64 and "\n" not in display and "\r" not in display
emit("pass" if sender_ok and display_ok else "fail", "exact ACS sender", "local part and display name are structurally valid" if sender_ok and display_ok else "sender local part/display name is missing or invalid")

mode = text("acs_resource_mode")
existing_required = (
    text("acs_existing_communication_service_id"),
    text("acs_existing_email_endpoint"),
    text("acs_existing_email_domain_id"),
)
communication_id = re.fullmatch(
    r"/subscriptions/([^/]+)/resourceGroups/[^/]+/providers/Microsoft\.Communication/CommunicationServices/[^/]+",
    existing_required[0],
    flags=re.IGNORECASE,
)
domain_id = re.fullmatch(
    r"/subscriptions/([^/]+)/resourceGroups/[^/]+/providers/Microsoft\.Communication/emailServices/[^/]+/domains/[^/]+",
    existing_required[2],
    flags=re.IGNORECASE,
)
if mode == "provision" and not any(existing_required):
    emit("pass", "ACS resource mode", "provision a dedicated customer-domain service")
elif mode == "existing" and all(existing_required):
    endpoint_ok = bool(
        re.fullmatch(
            r"https://[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
            r"\.communication\.azure\.com(?::443)?/?",
            existing_required[1],
        )
    )
    resource_ids_ok = (
        communication_id is not None
        and domain_id is not None
        and communication_id.group(1).lower() == text("subscription_id").lower()
        and domain_id.group(1).lower() == text("subscription_id").lower()
    )
    emit("pass" if endpoint_ok and resource_ids_ok else "fail", "ACS resource mode", "exact same-subscription resource IDs and non-secret endpoint are present" if endpoint_ok and resource_ids_ok else "existing ACS mode requires complete same-subscription resource IDs and a non-secret HTTPS endpoint")
else:
    emit("fail", "ACS resource mode", "choose clean provision mode, or provide all exact existing-resource identifiers")

hostname_pattern = re.compile(r"(?=.{4,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
operator_fqdn = text("operator_fqdn").lower()
tracking_fqdn = text("tracking_fqdn").lower()
hostnames_ok = (
    hostname_pattern.fullmatch(operator_fqdn) is not None
    and hostname_pattern.fullmatch(tracking_fqdn) is not None
    and operator_fqdn != tracking_fqdn
)
emit("pass" if hostnames_ok else "fail", "operator/tracking hostnames", "distinct public hostnames are configured" if hostnames_ok else "complete, distinct public operator and tracking hostnames are required")

dns_zone_id = text("acs_dns_zone_id")
if dns_zone_id:
    zone = re.fullmatch(
        r"/subscriptions/([^/]+)/resourceGroups/[^/]+/providers/Microsoft\.Network/dnszones/([^/]+)",
        dns_zone_id,
        flags=re.IGNORECASE,
    )
    dns_ok = (
        zone is not None
        and zone.group(1).lower() == text("subscription_id").lower()
        and (domain == zone.group(2).lower() or domain.endswith(f".{zone.group(2).lower()}"))
    )
    emit("pass" if dns_ok else "fail", "ACS DNS zone", "same-subscription public zone contains the sending domain" if dns_ok else "DNS zone ID must be same-subscription and contain the sending domain")
else:
    emit("warn", "ACS DNS zone", "external DNS requires separate live record verification")

limits = {}
limit_specs = {
    "acs_daily_message_limit": (1, 1_000_000),
    "acs_messages_per_minute": (1, 10_000),
    "acs_ramp_batch_size": (1, 2_000),
    "acs_ramp_interval_seconds": (1, 3_600),
}
all_limits_valid = True
for key, bounds in limit_specs.items():
    value = values.get(key)
    try:
        parsed = int(value)
        valid = not isinstance(value, bool) and str(value).strip() == str(parsed) and bounds[0] <= parsed <= bounds[1]
    except (TypeError, ValueError):
        parsed, valid = 0, False
    limits[key] = parsed
    all_limits_valid = all_limits_valid and valid
if not all_limits_valid:
    emit("fail", "ACS quota and pacing", "quota or pacing value is outside the supported range")
else:
    emit("pass", "ACS quota and pacing", "all four reviewed values are within supported ranges")
if all_limits_valid:
    relationships_ok = (
        limits["acs_messages_per_minute"] <= limits["acs_daily_message_limit"]
        and limits["acs_ramp_batch_size"] <= limits["acs_messages_per_minute"]
    )
    emit("pass" if relationships_ok else "fail", "ACS pacing relationships", "ramp batch <= per-minute <= daily limit" if relationships_ok else "require ramp batch <= per-minute <= daily limit")

graph = text("graph_endpoint").rstrip("/").lower()
groups = [part.strip() for part in text("directory_group_ids").split(",") if part.strip()]
uuid_pattern = re.compile(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}")
if graph:
    valid = graph == "https://graph.microsoft.com/v1.0" and bool(groups) and all(uuid_pattern.fullmatch(group) for group in groups)
    emit("pass" if valid else "fail", "directory worker role", "selected groups use the native Graph endpoint" if valid else "enabled directory sync requires the native Graph endpoint and exact group UUIDs")
elif groups:
    emit("fail", "directory worker role", "group IDs are present while directory sync is disabled")
else:
    emit("pass", "directory worker role", "disabled; no directory group scope supplied")

mailbox_endpoint = text("reported_mailbox_endpoint").rstrip("/").lower()
mailbox = text("reported_mailbox_address")
folder = text("reported_mailbox_folder")
mailbox_ok = bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", mailbox))
if mailbox_endpoint:
    valid = mailbox_endpoint == "https://graph.microsoft.com/v1.0" and mailbox_ok and 1 <= len(folder) <= 256
    emit("pass" if valid else "fail", "reported-mailbox worker role", "dedicated mailbox and bounded folder use the native Graph endpoint" if valid else "enabled mailbox ingestion requires the native Graph endpoint, mailbox address, and folder")
elif mailbox:
    emit("fail", "reported-mailbox worker role", "a mailbox is present while mailbox ingestion is disabled")
else:
    emit("pass", "reported-mailbox worker role", "disabled; no mailbox supplied")

allowlist = [part.strip().lower() for part in text("allowed_recipient_domains").split(",") if part.strip()]
allowlist_ok = bool(allowlist) and len(allowlist) <= 100 and all(hostname_pattern.fullmatch(part) for part in allowlist)
emit("pass" if allowlist_ok else "fail", "recipient allowlist", "bounded target domains are configured" if allowlist_ok else "one to 100 complete recipient domains are required")

alert_domains = [part.strip().lower() for part in text("alert_webhook_domains").split(",") if part.strip()]
alerts_ok = len(alert_domains) <= 100 and all(hostname_pattern.fullmatch(part) for part in alert_domains)
emit("pass" if alerts_ok else "fail", "alert webhook allowlist", "bounded hostnames are configured or alerts are disabled" if alerts_ok else "alert webhook entries must be complete hostnames")

ai_endpoint = text("ai_endpoint")
if ai_endpoint:
    parsed_ai = urlparse(ai_endpoint)
    ai_ok = (
        parsed_ai.scheme == "https"
        and parsed_ai.hostname is not None
        and parsed_ai.username is None
        and parsed_ai.password is None
        and not parsed_ai.query
        and not parsed_ai.fragment
    )
    emit("pass" if ai_ok else "fail", "AI gateway endpoint", "non-secret HTTPS endpoint is configured" if ai_ok else "AI endpoint must be HTTPS without credentials, query, or fragment")
else:
    emit("pass", "AI gateway endpoint", "optional AI assistance is disabled")

key_id_pattern = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}\Z")
active_key_id = text("ciphertext_active_key_id")
prior_key_ids = [part.strip() for part in text("ciphertext_prior_key_ids").split(",") if part.strip()]
prior_secret_id = text("ciphertext_prior_keys_secret_id")
prior_secret_match = re.fullmatch(
    r"/subscriptions/([^/]+)/resourceGroups/[^/]+/providers/Microsoft\.KeyVault/vaults/[A-Za-z0-9-]{3,24}/secrets/[A-Za-z0-9-]{1,127}",
    prior_secret_id,
    flags=re.IGNORECASE,
) if prior_secret_id else None
ciphertext_ok = (
    key_id_pattern.fullmatch(active_key_id) is not None
    and len(prior_key_ids) <= 4
    and len(set(prior_key_ids)) == len(prior_key_ids)
    and active_key_id not in prior_key_ids
    and all(key_id_pattern.fullmatch(item) for item in prior_key_ids)
    and bool(prior_key_ids) == bool(prior_secret_id)
    and (
        not prior_secret_id
        or prior_secret_match is not None
        and prior_secret_match.group(1).lower() == text("subscription_id").lower()
    )
)
emit("pass" if ciphertext_ok else "fail", "ciphertext key lifecycle", "active/prior key identifiers and versionless reference are structurally safe" if ciphertext_ok else "ciphertext key identifiers or versionless Key Vault reference are invalid")
emit("warn", "ACS evidence", "GUI status fields are operator-supplied; this preflight does not call them live delivery evidence")
PYVALIDATE
    )
  else
    record fail "GUI values export" "file is not the bounded one-value-per-line export produced by the GUI"
    VALUES_JSON=""
  fi
fi

# --- subscription and identity ----------------------------------------------
section "Subscription"
TENANT_ID="$(ACCOUNT_JSON="$ACCOUNT_JSON" python3 -c 'import json,os; print(json.loads(os.environ["ACCOUNT_JSON"])["tenantId"])')"
STATE="$(ACCOUNT_JSON="$ACCOUNT_JSON" python3 -c 'import json,os; print(json.loads(os.environ["ACCOUNT_JSON"]).get("state", ""))')"
record pass "subscription" "$SUBSCRIPTION"
record pass "tenant" "$TENANT_ID"
if [ "$STATE" = "Enabled" ]; then
  record pass "subscription state" "$STATE"
else
  record fail "subscription state" "must be Enabled"
fi
if [ -n "$VALUES_JSON" ]; then
  CONFIG_SUBSCRIPTION="$(VALUES_JSON="$VALUES_JSON" python3 -c 'import json,os; print(str(json.loads(os.environ["VALUES_JSON"]).get("subscription_id", "")))')"
  CONFIG_TENANT="$(VALUES_JSON="$VALUES_JSON" python3 -c 'import json,os; print(str(json.loads(os.environ["VALUES_JSON"]).get("entra_tenant_id", "")))')"
  if [ "$(printf '%s' "$CONFIG_SUBSCRIPTION" | tr '[:upper:]' '[:lower:]')" = "$(printf '%s' "$SUBSCRIPTION" | tr '[:upper:]' '[:lower:]')" ]; then
    record pass "reviewed subscription binding" "GUI export matches the selected subscription"
  else
    record fail "reviewed subscription binding" "GUI export does not match the selected subscription"
  fi
  if [ "$(printf '%s' "$CONFIG_TENANT" | tr '[:upper:]' '[:lower:]')" = "$(printf '%s' "$TENANT_ID" | tr '[:upper:]' '[:lower:]')" ]; then
    record pass "reviewed tenant binding" "GUI export matches the live tenant"
  else
    record fail "reviewed tenant binding" "GUI export does not match the live tenant"
  fi
  CONFIG_CLIENT_ID="$(VALUES_JSON="$VALUES_JSON" python3 -c 'import json,os; print(str(json.loads(os.environ["VALUES_JSON"]).get("entra_client_id", "")))')"
  LIVE_CLIENT_ID="$(az ad app show --id "$CONFIG_CLIENT_ID" --query appId -o tsv 2>/dev/null || true)"
  if [[ "$CONFIG_CLIENT_ID" =~ $UUID_PATTERN ]] && \
      [ "$(printf '%s' "$LIVE_CLIENT_ID" | tr '[:upper:]' '[:lower:]')" = \
        "$(printf '%s' "$CONFIG_CLIENT_ID" | tr '[:upper:]' '[:lower:]')" ]; then
    record pass "operator Entra application" "reviewed client ID exists in the live tenant"
  else
    record fail "operator Entra application" "reviewed client ID is missing or not readable in the live tenant"
  fi
fi

# Terraform assigns roles to managed identities, so Contributor alone is not
# enough. This is a control-plane observation of the current CLI principal.
section "Permissions"
SIGNED_IN="$(az ad signed-in-user show --query id -o tsv 2>/dev/null || echo "")"
if [ -z "$SIGNED_IN" ]; then
  record fail "role assignments" "cannot inspect the signed-in principal; verify the deployment identity separately"
else
  ROLES="$(az role assignment list --assignee "$SIGNED_IN" --scope "/subscriptions/$SUBSCRIPTION" \
    --include-inherited --query '[].roleDefinitionName' -o tsv 2>/dev/null || echo "")"
  if printf '%s' "$ROLES" | grep -qx "Owner"; then
    record pass "role assignments" "Owner"
  elif printf '%s' "$ROLES" | grep -qx "User Access Administrator" && printf '%s' "$ROLES" | grep -qx "Contributor"; then
    record pass "role assignments" "Contributor + User Access Administrator"
  else
    record fail "role assignments" "need Owner, or Contributor + User Access Administrator"
  fi
fi

# --- resource providers ------------------------------------------------------
section "Resource providers"
if PROVIDERS_JSON="$(az provider list --subscription "$SUBSCRIPTION" -o json 2>/dev/null)"; then
  require_bounded_output "Azure provider inventory" "$PROVIDERS_JSON"
  while IFS=$'\t' read -r provider state; do
    case "$state" in
      Registered)  record pass "$provider" "registered" ;;
      Registering) record warn "$provider" "still registering" ;;
      *)           record fail "$provider" "not registered" ;;
    esac
  done < <(PROVIDERS_JSON="$PROVIDERS_JSON" python3 <<'PYPROVIDERS'
import json
import os

expected = (
    "Microsoft.App", "Microsoft.Authorization", "Microsoft.Communication",
    "Microsoft.ContainerRegistry", "Microsoft.DBforPostgreSQL", "Microsoft.EventGrid",
    "Microsoft.Insights", "Microsoft.KeyVault", "Microsoft.ManagedIdentity",
    "Microsoft.Network", "Microsoft.OperationalInsights", "Microsoft.Storage",
)
try:
    rows = json.loads(os.environ["PROVIDERS_JSON"])
except json.JSONDecodeError:
    rows = []
states = {
    str(row.get("namespace", "")): str(row.get("registrationState", "Unknown"))
    for row in rows
    if isinstance(row, dict)
}
for name in expected:
    print(name, states.get(name, "Unknown"), sep="\t")
PYPROVIDERS
  )
else
  record fail "resource provider inspection" "Azure control-plane query failed; registration state was not inferred"
fi

section "Region and ACS boundary"
if LOCATION_ROWS="$(az account list-locations --subscription "$SUBSCRIPTION" \
    --query "[?name=='$LOCATION'].name" -o tsv 2>/dev/null)"; then
  require_bounded_output "Azure location inventory" "$LOCATION_ROWS"
  if printf '%s\n' "$LOCATION_ROWS" | grep -Fqx "$LOCATION"; then
    record pass "location" "$LOCATION"
  else
    record fail "location" "$LOCATION is not available to this subscription"
  fi
else
  record fail "location inspection" "Azure control-plane query failed; regional availability was not inferred"
fi
if CONTAINER_APP_LOCATIONS="$(az provider show --namespace Microsoft.App --subscription "$SUBSCRIPTION" \
    --query "resourceTypes[?resourceType=='managedEnvironments'].locations[]" -o tsv 2>/dev/null)"; then
  require_bounded_output "Container Apps location inventory" "$CONTAINER_APP_LOCATIONS"
  if printf '%s\n' "$CONTAINER_APP_LOCATIONS" | tr '[:upper:]' '[:lower:]' | tr -d ' ' \
      | grep -Fqx "$(printf '%s' "$LOCATION" | tr -d ' ')"; then
    record pass "container apps in region" "$LOCATION"
  else
    record warn "container apps in region" "provider metadata did not list the selected region"
  fi
else
  record warn "container apps in region" "provider metadata query failed; regional support was not inferred"
fi
record warn "ACS live readiness" "provider registration does not prove domain verification, sender provisioning, quota, managed-identity send, receipt processing, or inbox placement"

# --- protected GitHub environment -------------------------------------------
section "Protected GitHub environment"
if [ -z "$REPO" ]; then
  record fail "GitHub environment" "--repo is required to inspect protected deployment controls"
elif [ "$GH_AVAILABLE" -ne 1 ]; then
  record fail "GitHub environment" "GitHub CLI is unavailable"
elif [ "$GH_AUTHENTICATED" -ne 1 ]; then
  record fail "GitHub environment" "GitHub authentication is required before protected controls can be inspected"
else
  ENVIRONMENT_JSON="$(gh api "repos/$REPO/environments/$ENVIRONMENT" 2>/dev/null || true)"
  require_bounded_output "GitHub environment inspection" "$ENVIRONMENT_JSON"
  if [ -z "$ENVIRONMENT_JSON" ]; then
    record fail "environment '$ENVIRONMENT'" "missing or not visible"
  else
    while IFS=$'\t' read -r kind name detail; do
      [ -n "$kind" ] && record "$kind" "$name" "$detail"
    done < <(ENVIRONMENT_JSON="$ENVIRONMENT_JSON" EXPECTED_ENVIRONMENT="$ENVIRONMENT" python3 <<'PYENV'
import json
import os

try:
    payload = json.loads(os.environ["ENVIRONMENT_JSON"])
except json.JSONDecodeError:
    print("fail\tGitHub environment\tmetadata is malformed")
    raise SystemExit
if payload.get("name") != os.environ["EXPECTED_ENVIRONMENT"]:
    print("fail\tGitHub environment\tname does not match the selected environment")
rules = payload.get("protection_rules")
reviewer_count = 0
if isinstance(rules, list):
    for rule in rules:
        if isinstance(rule, dict) and rule.get("type") == "required_reviewers":
            reviewers = rule.get("reviewers")
            if isinstance(reviewers, list):
                reviewer_count += len(reviewers)
print("pass\trequired reviewers\tat least one reviewer is configured" if reviewer_count > 0 else "fail\trequired reviewers\tno required reviewer is configured")
bypass = payload.get("can_admins_bypass")
if bypass is False:
    print("pass\tadministrator bypass\tdisabled")
elif bypass is True:
    print("fail\tadministrator bypass\tenabled")
else:
    print("warn\tadministrator bypass\tnot returned by GitHub; verify it is disabled in the environment settings")
policy = payload.get("deployment_branch_policy")
print("pass\tdeployment branch policy\tpresent; GitHub enforces the configured ref admission" if isinstance(policy, dict) else "warn\tdeployment branch policy\tnot returned; verify the reviewed connector ref is allowed")
PYENV
    )
  fi

  VARIABLES_JSON="$(gh variable list --repo "$REPO" --env "$ENVIRONMENT" --json name,value 2>/dev/null || true)"
  require_bounded_output "GitHub variable inspection" "$VARIABLES_JSON"
  if [ -z "$VARIABLES_JSON" ]; then
    record fail "environment variables" "could not inspect the protected environment variables"
  else
    while IFS=$'\t' read -r kind name detail; do
      [ -n "$kind" ] && record "$kind" "$name" "$detail"
    done < <(VARIABLES_JSON="$VARIABLES_JSON" SUBSCRIPTION="$SUBSCRIPTION" TENANT_ID="${TENANT_ID:-}" REPO="$REPO" python3 <<'PYVARS'
import json
import os
import re

try:
    rows = json.loads(os.environ["VARIABLES_JSON"])
except json.JSONDecodeError:
    print("fail\tenvironment variables\tmetadata is malformed")
    raise SystemExit
if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
    print("fail\tenvironment variables\tmetadata is malformed")
    raise SystemExit
values = {str(row.get("name", "")): str(row.get("value", "")) for row in rows}
required = (
    "AZURE_SUBSCRIPTION_ID", "AZURE_TENANT_ID", "AZURE_CLIENT_ID",
    "TF_STATE_RESOURCE_GROUP", "TF_STATE_STORAGE_ACCOUNT", "TF_STATE_CONTAINER",
)
for key in required:
    value = values.get(key, "").strip()
    if not value:
        print("fail", key, "missing from the protected environment", sep="\t")
    elif key == "AZURE_SUBSCRIPTION_ID" and value.lower() != os.environ["SUBSCRIPTION"].lower():
        print("fail", key, "does not match the selected subscription", sep="\t")
    elif key == "AZURE_TENANT_ID" and value.lower() != os.environ["TENANT_ID"].lower():
        print("fail", key, "does not match the live tenant", sep="\t")
    else:
        print("pass", key, "configured in the protected environment", sep="\t")

mode = values.get("DEPLOYMENT_ORCHESTRATION_MODE", "disabled").strip() or "disabled"
if mode == "disabled":
    print("pass\tGUI deployment connector\tdisabled by default; no server-side dispatch credential is expected")
elif mode != "github_actions":
    print("fail\tGUI deployment connector\tDEPLOYMENT_ORCHESTRATION_MODE is invalid")
else:
    repository = values.get("DEPLOYMENT_GITHUB_REPOSITORY", "").strip()
    ref = values.get("DEPLOYMENT_GITHUB_REF", "main").strip() or "main"
    secret_id = values.get("DEPLOYMENT_GITHUB_TOKEN_SECRET_ID", "").strip()
    versionless_secret = re.fullmatch(
        r"/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.KeyVault/vaults/[^/]+/secrets/[A-Za-z0-9-]+",
        secret_id,
        re.IGNORECASE,
    )
    valid_ref = (
        bool(re.fullmatch(r"[A-Za-z0-9._/-]{1,255}", ref))
        and not ref.startswith("/")
        and not ref.endswith(("/", ".", ".lock"))
        and ".." not in ref
        and "//" not in ref
        and not any(part.startswith(".") for part in ref.split("/"))
    )
    if repository != os.environ["REPO"] or not valid_ref or versionless_secret is None:
        print("fail\tGUI deployment connector\tenabled mode requires the fixed repository/ref and a versionless deployment-Key-Vault secret ID")
    else:
        print("pass\tGUI deployment connector\tfixed repository/ref and versionless secret ID are configured")
        print("warn\tGUI deployment credential\tvariable inspection cannot prove the Key Vault secret value, permissions, or token validity")
PYVARS
    )

    DEPLOYMENT_APP_ID="$(VARIABLES_JSON="$VARIABLES_JSON" python3 -c 'import json,os; rows=json.loads(os.environ["VARIABLES_JSON"]); values={str(row.get("name", "")): str(row.get("value", "")) for row in rows if isinstance(row, dict)}; print(values.get("AZURE_CLIENT_ID", "").strip())' 2>/dev/null || true)"
    STATE_RG="$(VARIABLES_JSON="$VARIABLES_JSON" python3 -c 'import json,os; rows=json.loads(os.environ["VARIABLES_JSON"]); values={str(row.get("name", "")): str(row.get("value", "")) for row in rows if isinstance(row, dict)}; print(values.get("TF_STATE_RESOURCE_GROUP", "").strip())' 2>/dev/null || true)"
    STATE_SA="$(VARIABLES_JSON="$VARIABLES_JSON" python3 -c 'import json,os; rows=json.loads(os.environ["VARIABLES_JSON"]); values={str(row.get("name", "")): str(row.get("value", "")) for row in rows if isinstance(row, dict)}; print(values.get("TF_STATE_STORAGE_ACCOUNT", "").strip())' 2>/dev/null || true)"
    STATE_CONTAINER="$(VARIABLES_JSON="$VARIABLES_JSON" python3 -c 'import json,os; rows=json.loads(os.environ["VARIABLES_JSON"]); values={str(row.get("name", "")): str(row.get("value", "")) for row in rows if isinstance(row, dict)}; print(values.get("TF_STATE_CONTAINER", "").strip())' 2>/dev/null || true)"

    if [[ "$DEPLOYMENT_APP_ID" =~ $UUID_PATTERN ]] && \
        DEPLOYMENT_SP_ID="$(az ad sp show --id "$DEPLOYMENT_APP_ID" --query id -o tsv 2>/dev/null)" && \
        [ -n "$DEPLOYMENT_SP_ID" ]; then
      record pass "deployment Entra application" "protected client ID resolves to a service principal"
    else
      DEPLOYMENT_SP_ID=""
      record fail "deployment Entra application" "protected client ID is missing or not readable in the live tenant"
    fi

    if [[ "$STATE_RG" =~ ^[A-Za-z0-9._()-]{1,90}$ ]] && \
        [[ "$STATE_SA" =~ ^[a-z0-9]{3,24}$ ]] && \
        [[ "$STATE_CONTAINER" =~ ^[a-z0-9]([a-z0-9-]{1,61}[a-z0-9])?$ ]]; then
      if STATE_ACCOUNT_JSON="$(az storage account show --name "$STATE_SA" --resource-group "$STATE_RG" \
          --subscription "$SUBSCRIPTION" -o json 2>/dev/null)" && [ -n "$STATE_ACCOUNT_JSON" ]; then
        require_bounded_output "Terraform state account inspection" "$STATE_ACCOUNT_JSON"
        STATE_ACCOUNT_ID="$(STATE_ACCOUNT_JSON="$STATE_ACCOUNT_JSON" python3 -c 'import json,os; print(json.loads(os.environ["STATE_ACCOUNT_JSON"]).get("id", ""))')"
        if STATE_ACCOUNT_JSON="$STATE_ACCOUNT_JSON" python3 <<'PYSTATE'
import json
import os

row = json.loads(os.environ["STATE_ACCOUNT_JSON"])
secure = (
    row.get("allowBlobPublicAccess") is False
    and row.get("allowSharedKeyAccess") is False
    and row.get("enableHttpsTrafficOnly", row.get("supportsHttpsTrafficOnly")) is True
    and row.get("minimumTlsVersion") == "TLS1_2"
)
raise SystemExit(0 if secure else 1)
PYSTATE
        then
          record pass "Terraform state account" "exact account disables public blobs/shared keys and requires HTTPS/TLS 1.2"
        else
          record fail "Terraform state account" "exact account is missing one or more required transport/access controls"
        fi
        if BLOB_PROPERTIES="$(az storage account blob-service-properties show --account-name "$STATE_SA" \
            --resource-group "$STATE_RG" --subscription "$SUBSCRIPTION" -o json 2>/dev/null)"; then
          require_bounded_output "Terraform state retention inspection" "$BLOB_PROPERTIES"
          if BLOB_PROPERTIES="$BLOB_PROPERTIES" python3 <<'PYRETENTION'
import json
import os

row = json.loads(os.environ["BLOB_PROPERTIES"])
secure = (
    row.get("isVersioningEnabled") is True
    and row.get("deleteRetentionPolicy", {}).get("enabled") is True
    and int(row.get("deleteRetentionPolicy", {}).get("days", 0)) >= 7
    and row.get("containerDeleteRetentionPolicy", {}).get("enabled") is True
    and int(row.get("containerDeleteRetentionPolicy", {}).get("days", 0)) >= 7
)
raise SystemExit(0 if secure else 1)
PYRETENTION
          then
            record pass "Terraform state recovery" "versioning plus blob/container delete retention are enabled"
          else
            record fail "Terraform state recovery" "versioning or delete retention is missing"
          fi
        else
          record fail "Terraform state recovery" "retention properties could not be inspected"
        fi
        if az storage container-rm show --name "$STATE_CONTAINER" --storage-account "$STATE_SA" \
            --resource-group "$STATE_RG" --subscription "$SUBSCRIPTION" --query name -o tsv 2>/dev/null \
            | grep -Fqx "$STATE_CONTAINER"; then
          record pass "Terraform state container" "exact ARM-managed container exists"
        else
          record fail "Terraform state container" "exact container is missing or not readable"
        fi
        if [ -n "$DEPLOYMENT_SP_ID" ] && [ -n "$STATE_ACCOUNT_ID" ] && \
            az role assignment list --assignee "$DEPLOYMENT_SP_ID" --scope "$STATE_ACCOUNT_ID" \
              --include-inherited --query '[].roleDefinitionName' -o tsv 2>/dev/null \
              | grep -Fqx "Storage Blob Data Contributor"; then
          record pass "Terraform state data role" "deployment identity can use the Azure AD backend"
        else
          record fail "Terraform state data role" "deployment identity lacks Storage Blob Data Contributor on the exact account"
        fi
      else
        record fail "Terraform state account" "exact account is missing or not readable"
      fi
    else
      record fail "Terraform state identifiers" "protected resource group/account/container names are missing or invalid"
    fi
  fi
fi

# --- verdict -----------------------------------------------------------------
if [ "$JSON" -eq 1 ]; then
  python3 - "$PASS" "$WARN" "$FAIL" "${RESULTS[@]}" <<'PYJSON'
import json
import sys

passed, warned, failed = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
checks = []
for row in sys.argv[4:]:
    kind, name, detail = row.split("|", 2)
    checks.append({"result": kind, "check": name, "detail": detail})
print(json.dumps({
    "ready": failed == 0,
    "evidence_level": "control_plane_preflight_only",
    "production_ready": False,
    "passed": passed,
    "warnings": warned,
    "failed": failed,
    "checks": checks,
}, indent=2))
PYJSON
else
  printf '\n%s passed, %s warnings, %s blocking\n' "$PASS" "$WARN" "$FAIL"
  if [ "$FAIL" -eq 0 ]; then
    printf '\nNo structural/control-plane blockers were detected. This is not live\n'
    printf 'delivery, production, or RSA readiness evidence. Continue in the Azure\n'
    printf 'deployment GUI; after foundation, complete DNS/ACS verification and use\n'
    printf 'the exact-resource mail diagnostic before a GUI canary lifecycle.\n\n'
  else
    printf '\nResolve the blocking items above in the Azure deployment GUI or the\n'
    printf 'named external control plane. Nothing was changed by this script.\n\n'
  fi
fi

[ "$FAIL" -eq 0 ] || exit 1
