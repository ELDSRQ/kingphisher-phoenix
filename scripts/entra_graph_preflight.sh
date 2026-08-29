#!/usr/bin/env bash
#
# Read-only Microsoft 365 permission preflight for the directory and mailbox
# managed identities. This script never grants a permission. Use
# --print-commands to render commands for a tenant administrator to review and
# run separately.

set -euo pipefail

export AZURE_LOGGING_ENABLE_LOG_FILE=false

GRAPH_APP_ID="00000003-0000-0000-c000-000000000000"
GROUP_MEMBER_READ_ALL_ID="98830695-27a2-44f7-8c18-0c3ebc9698f6"
USER_READ_BASIC_ALL_ID="97235f07-e226-4f63-ace3-39588e11d3a1"

DIRECTORY_CLIENT_ID=""
DIRECTORY_PRINCIPAL_ID=""
MAILBOX_CLIENT_ID=""
MAILBOX_PRINCIPAL_ID=""
REPORT_MAILBOX=""
TENANT_ID=""
MODE="preflight"
GROUP_IDS=()
COMMAND_TIMEOUT_SECONDS="${KP_AZURE_COMMAND_TIMEOUT_SECONDS:-60}"

usage() {
  cat <<'EOF'
Usage: scripts/entra_graph_preflight.sh \
  --directory-client-id <application-client-id> \
  --directory-principal-id <service-principal-object-id> \
  --mailbox-client-id <application-client-id> \
  --mailbox-principal-id <service-principal-object-id> \
  --tenant-id <entra-tenant-id> \
  --mailbox <report-mailbox> \
  --group-id <entra-group-object-id> [--group-id <id> ...] \
  [--print-commands]

The default mode performs read-only Entra checks with the Azure CLI. It checks
the two service-principal identities, the two Microsoft Graph application role
assignments, and the selected group object IDs. It cannot prove Exchange Online
Application RBAC; follow the printed read-only Exchange verification command.

--print-commands performs no cloud calls. It prints deterministic Graph and
Exchange Online commands for a tenant administrator to review and run. The
script itself never executes a grant and never requests or prints tokens.

Exit codes: 0 requested checks passed, 1 a checked item is missing, 2 bad input
or the read-only checks could not be performed. Exit 0 is not a live-readiness
claim for directory synchronization or mailbox ingestion.
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 2
}

require_argument() {
  [ "$#" -ge 2 ] && [ -n "$2" ] && [ "${2#--}" = "$2" ] || die "$1 requires a value"
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

while [ "$#" -gt 0 ]; do
  case "$1" in
    --directory-client-id)
      require_argument "$@"
      DIRECTORY_CLIENT_ID="$2"
      shift 2
      ;;
    --directory-principal-id)
      require_argument "$@"
      DIRECTORY_PRINCIPAL_ID="$2"
      shift 2
      ;;
    --mailbox-client-id)
      require_argument "$@"
      MAILBOX_CLIENT_ID="$2"
      shift 2
      ;;
    --mailbox-principal-id)
      require_argument "$@"
      MAILBOX_PRINCIPAL_ID="$2"
      shift 2
      ;;
    --mailbox)
      require_argument "$@"
      REPORT_MAILBOX="$2"
      shift 2
      ;;
    --tenant-id)
      require_argument "$@"
      TENANT_ID="$2"
      shift 2
      ;;
    --group-id)
      require_argument "$@"
      GROUP_IDS+=("$2")
      shift 2
      ;;
    --print-commands)
      MODE="print"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

UUID_PATTERN='^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$'

validate_uuid() {
  local flag="$1"
  local value="$2"
  [[ "$value" =~ $UUID_PATTERN ]] || die "$flag must be a UUID"
}

[ -n "$DIRECTORY_CLIENT_ID" ] || die "--directory-client-id is required"
[ -n "$DIRECTORY_PRINCIPAL_ID" ] || die "--directory-principal-id is required"
[ -n "$MAILBOX_CLIENT_ID" ] || die "--mailbox-client-id is required"
[ -n "$MAILBOX_PRINCIPAL_ID" ] || die "--mailbox-principal-id is required"
[ -n "$REPORT_MAILBOX" ] || die "--mailbox is required"
[ "${#GROUP_IDS[@]}" -gt 0 ] || die "at least one --group-id is required"

validate_uuid "--directory-client-id" "$DIRECTORY_CLIENT_ID"
validate_uuid "--directory-principal-id" "$DIRECTORY_PRINCIPAL_ID"
validate_uuid "--mailbox-client-id" "$MAILBOX_CLIENT_ID"
validate_uuid "--mailbox-principal-id" "$MAILBOX_PRINCIPAL_ID"
[ -z "$TENANT_ID" ] || validate_uuid "--tenant-id" "$TENANT_ID"
for group_id in "${GROUP_IDS[@]}"; do
  validate_uuid "--group-id" "$group_id"
done

[[ "$REPORT_MAILBOX" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$ ]] \
  || die "--mailbox must be an email address"

[ "$DIRECTORY_CLIENT_ID" != "$MAILBOX_CLIENT_ID" ] \
  || die "directory and mailbox client IDs must identify distinct managed identities"
[ "$DIRECTORY_PRINCIPAL_ID" != "$MAILBOX_PRINCIPAL_ID" ] \
  || die "directory and mailbox principal IDs must identify distinct managed identities"

GROUP_LIST=""
for group_id in "${GROUP_IDS[@]}"; do
  if [ -n "$GROUP_LIST" ]; then
    GROUP_LIST="$GROUP_LIST,$group_id"
  else
    GROUP_LIST="$group_id"
  fi
done

print_matrix() {
  printf '%s\n' \
    "Reviewed permission matrix" \
    "  directory | Microsoft Graph | application | GroupMember.Read.All | $GROUP_MEMBER_READ_ALL_ID" \
    "  directory | Microsoft Graph | application | User.ReadBasic.All  | $USER_READ_BASIC_ALL_ID" \
    "  directory | configured group object IDs | $GROUP_LIST" \
    "  mailbox   | Exchange Online | Application Mail.Read | custom scope: $REPORT_MAILBOX" \
    "" \
    "Graph application permissions are tenant-wide capabilities, not resource-scoped enforcement." \
    "The application must still constrain every directory query to the configured group IDs." \
    "Do NOT also grant Entra/Microsoft Graph Mail.Read: permissions are additive and that" \
    "would bypass the Exchange custom mailbox scope."
}

print_grant_commands() {
  local scope_name
  scope_name="kp-report-mailbox-$(printf '%s' "$REPORT_MAILBOX" | tr '[:upper:]@.' '[:lower:]--')"

  print_matrix
  printf '\n%s\n' \
    "# Microsoft Graph application-role assignments (run in a reviewed admin shell)" \
    "DIRECTORY_PRINCIPAL_ID='$DIRECTORY_PRINCIPAL_ID'" \
    "GRAPH_RESOURCE_ID=\$(az ad sp show --id '$GRAPH_APP_ID' --query id -o tsv)" \
    "az rest --method POST --uri \"https://graph.microsoft.com/v1.0/servicePrincipals/\$DIRECTORY_PRINCIPAL_ID/appRoleAssignments\" --body \"{\\\"principalId\\\":\\\"\$DIRECTORY_PRINCIPAL_ID\\\",\\\"resourceId\\\":\\\"\$GRAPH_RESOURCE_ID\\\",\\\"appRoleId\\\":\\\"$GROUP_MEMBER_READ_ALL_ID\\\"}\"" \
    "az rest --method POST --uri \"https://graph.microsoft.com/v1.0/servicePrincipals/\$DIRECTORY_PRINCIPAL_ID/appRoleAssignments\" --body \"{\\\"principalId\\\":\\\"\$DIRECTORY_PRINCIPAL_ID\\\",\\\"resourceId\\\":\\\"\$GRAPH_RESOURCE_ID\\\",\\\"appRoleId\\\":\\\"$USER_READ_BASIC_ALL_ID\\\"}\"" \
    "" \
    "# Exchange Online Application RBAC (run in reviewed Exchange Online PowerShell)" \
    "\$MailboxAppId = '$MAILBOX_CLIENT_ID'" \
    "\$MailboxObjectId = '$MAILBOX_PRINCIPAL_ID'" \
    "\$Mailbox = '$REPORT_MAILBOX'" \
    "\$ScopeName = '$scope_name'" \
    "Connect-ExchangeOnline" \
    "New-ServicePrincipal -AppId \$MailboxAppId -ObjectId \$MailboxObjectId -DisplayName 'KP report mailbox reader'" \
    "New-ManagementScope -Name \$ScopeName -RecipientRestrictionFilter \"PrimarySmtpAddress -eq '\$Mailbox'\"" \
    "New-ManagementRoleAssignment -Name 'KP report mailbox Mail.Read' -Role 'Application Mail.Read' -App \$MailboxObjectId -CustomResourceScope \$ScopeName" \
    "Test-ServicePrincipalAuthorization -Identity \$MailboxObjectId -Resource \$Mailbox | Format-Table"
}

if [ "$MODE" = "print" ]; then
  print_grant_commands
  printf '\nCommands printed only; no cloud command was executed. Review current state before running them.\n'
  exit 0
fi

[ -n "$TENANT_ID" ] || die "--tenant-id is required for read-only preflight tenant binding"
case "$COMMAND_TIMEOUT_SECONDS" in
  ''|*[!0-9]*) die "KP_AZURE_COMMAND_TIMEOUT_SECONDS must be an integer" ;;
esac
[ "$COMMAND_TIMEOUT_SECONDS" -ge 5 ] && [ "$COMMAND_TIMEOUT_SECONDS" -le 300 ] || \
  die "KP_AZURE_COMMAND_TIMEOUT_SECONDS must be between 5 and 300"
command -v az >/dev/null 2>&1 || die "the Azure CLI (az) is required for read-only preflight"
AZ_BIN="$(command -v az)"
az() { bounded "$AZ_BIN" "$@"; }
CURRENT_TENANT_ID="$(az account show --query tenantId -o tsv 2>/dev/null)" || \
  die "Azure authentication failed; run az login in the target tenant"
[ "$(printf '%s' "$CURRENT_TENANT_ID" | tr '[:upper:]' '[:lower:]')" = \
  "$(printf '%s' "$TENANT_ID" | tr '[:upper:]' '[:lower:]')" ] || \
  die "the active Azure login is bound to a different Entra tenant"
printf 'PASS tenant binding: active Azure login matches %s\n' "$TENANT_ID"

FAILURES=0

check_identity() {
  local label="$1"
  local client_id="$2"
  local expected_principal_id="$3"
  local actual_principal_id

  if ! actual_principal_id="$(az ad sp show --id "$client_id" --query id -o tsv 2>/dev/null)"; then
    printf 'FAIL %s identity: service principal is not readable\n' "$label"
    FAILURES=$((FAILURES + 1))
  elif [ "$(printf '%s' "$actual_principal_id" | tr '[:upper:]' '[:lower:]')" != \
      "$(printf '%s' "$expected_principal_id" | tr '[:upper:]' '[:lower:]')" ]; then
    printf 'FAIL %s identity: client ID does not resolve to the supplied principal ID\n' "$label"
    FAILURES=$((FAILURES + 1))
  else
    printf 'PASS %s identity: client/principal IDs match\n' "$label"
  fi
}

check_identity "directory" "$DIRECTORY_CLIENT_ID" "$DIRECTORY_PRINCIPAL_ID"
check_identity "mailbox" "$MAILBOX_CLIENT_ID" "$MAILBOX_PRINCIPAL_ID"

if ! GRAPH_RESOURCE_ID="$(az ad sp show --id "$GRAPH_APP_ID" --query id -o tsv 2>/dev/null)" || \
    [ -z "$GRAPH_RESOURCE_ID" ]; then
  die "could not resolve the Microsoft Graph service principal in the selected tenant"
fi

if ! ASSIGNED_ROLE_IDS="$(
  az rest --method GET \
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$DIRECTORY_PRINCIPAL_ID/appRoleAssignments" \
    --query "value[?resourceId=='$GRAPH_RESOURCE_ID'].appRoleId" -o tsv 2>/dev/null
)"; then
  die "could not read directory application-role assignments"
fi

check_role() {
  local name="$1"
  local role_id="$2"
  if printf '%s\n' "$ASSIGNED_ROLE_IDS" | grep -Fqx "$role_id"; then
    printf 'PASS directory permission: %s (application)\n' "$name"
  else
    printf 'FAIL directory permission: %s (application) is missing\n' "$name"
    FAILURES=$((FAILURES + 1))
  fi
}

check_role "GroupMember.Read.All" "$GROUP_MEMBER_READ_ALL_ID"
check_role "User.ReadBasic.All" "$USER_READ_BASIC_ALL_ID"

while IFS= read -r assigned_role_id; do
  [ -z "$assigned_role_id" ] && continue
  case "$(printf '%s' "$assigned_role_id" | tr '[:upper:]' '[:lower:]')" in
    "$GROUP_MEMBER_READ_ALL_ID"|"$USER_READ_BASIC_ALL_ID") ;;
    *)
      printf 'FAIL directory permission: an unreviewed Microsoft Graph application role is assigned\n'
      FAILURES=$((FAILURES + 1))
      ;;
  esac
done <<<"$ASSIGNED_ROLE_IDS"

if ! MAILBOX_GRAPH_ROLE_IDS="$(
  az rest --method GET \
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$MAILBOX_PRINCIPAL_ID/appRoleAssignments" \
    --query "value[?resourceId=='$GRAPH_RESOURCE_ID'].appRoleId" -o tsv 2>/dev/null
)"; then
  die "could not read mailbox application-role assignments"
elif [ -n "$MAILBOX_GRAPH_ROLE_IDS" ]; then
  printf 'FAIL mailbox permission: Microsoft Graph application roles would bypass the Exchange custom scope\n'
  FAILURES=$((FAILURES + 1))
else
  printf 'PASS mailbox permission: no Microsoft Graph application role bypass is present\n'
fi

for group_id in "${GROUP_IDS[@]}"; do
  LIVE_GROUP_ID="$(az rest --method GET \
      --uri "https://graph.microsoft.com/v1.0/groups/$group_id?\$select=id" \
      --query id -o tsv 2>/dev/null || true)"
  if [ "$(printf '%s' "$LIVE_GROUP_ID" | tr '[:upper:]' '[:lower:]')" = \
      "$(printf '%s' "$group_id" | tr '[:upper:]' '[:lower:]')" ]; then
    printf 'PASS selected group: %s is readable by the signed-in administrator\n' "$group_id"
  else
    printf 'FAIL selected group: %s was not readable by the signed-in administrator\n' "$group_id"
    FAILURES=$((FAILURES + 1))
  fi
done

printf '\n'
print_matrix
printf '\n%s\n' \
  "Exchange Online authorization was not inferred from Entra consent." \
  "An Exchange administrator must run this read-only verification after connecting:" \
  "  Test-ServicePrincipalAuthorization -Identity '$MAILBOX_PRINCIPAL_ID' -Resource '$REPORT_MAILBOX' | Format-Table" \
  "This preflight does not claim live directory-sync or mailbox-ingestion readiness."

[ "$FAILURES" -eq 0 ] || exit 1
