#!/usr/bin/env bash
#
# azure-nightly-shutdown.sh — the CHEAP, FAST-REVERSIBLE nightly power-down.
#
# Usage:
#   scripts/operator/azure-nightly-shutdown.sh [--dry-run] [--json]
#       [--resource-group <rg>] [--environment <staging|production>]
#       [--subscription <uuid>]
#
# WHAT THIS IS
#   A nightly safety net so Azure cost cannot silently resume when someone
#   starts the stack for a test and forgets to stop it. It performs ONLY the
#   three reversible power-down actions the operator already performs by hand
#   (see docs/NEXT_SESSION_HANDOFF.md, "Azure IDLED"):
#
#     1. stop the PostgreSQL flexible server   (retains data; ~7-day auto-restart)
#     2. set every project Container App to --min-replicas 0
#     3. deallocate the CI runner VM
#
# WHAT THIS IS NOT
#   It is NOT `scripts/operator/azure-idle.sh stop`. That one additionally runs
#   a terraform apply with deploy_workloads=false deploy_data_plane=false, which
#   DESTROYS the container registry and Redis. Destroying ACR nightly would force
#   re-pushing every image the next morning, and an unattended terraform apply is
#   exactly the kind of thing that must never run on a timer. `azure-idle.sh
#   stop` stays the deliberate, operator-driven, deeper idle.
#
#   This script therefore leaves INTACT, on purpose:
#     - ACR and Redis                     (deleting them breaks "push code / test
#                                          tomorrow"; they are re-created only by
#                                          a reviewed terraform apply)
#     - ACS + email domain + public DNS + Event Grid + Entra   (Tier 1, ~$0, and
#                                          painful to rebuild: SPF/DKIM re-verify)
#     - Key Vault, audit-anchor Storage, networking, Container Apps environment
#     - every Container App *job* (e.g. migration): manually triggered, $0 idle
#
# SAFETY PROPERTIES
#   - Read-only discovery first; every mutation is checked against a three-entry
#     allowlist (`az_write`) before it can run.
#   - Idempotent: an already-stopped/already-zeroed/already-deallocated resource
#     is a logged no-op success, never an error.
#   - Only resources tagged application=kingphisher-phoenix AND
#     environment=<environment> are touched. Anything else is skipped and logged.
#   - No terraform, no delete, no destroy, no purge, no `az group` mutation, and
#     it NEVER starts anything. Restart is manual and on-demand, by design.
#   - --dry-run performs the same read-only discovery and prints the exact
#     commands it would run, without running them.
#
# Requires: az (logged in), python3.

set -euo pipefail

export AZURE_LOGGING_ENABLE_LOG_FILE=false

RESOURCE_GROUP="${KP_RG:-rg-kp-staging}"
ENVIRONMENT="${KP_ENV:-staging}"
SUBSCRIPTION=""
DRY_RUN=0
EMIT_JSON=0
APPLICATION_TAG="kingphisher-phoenix"
COMMAND_TIMEOUT_SECONDS="${KP_AZURE_COMMAND_TIMEOUT_SECONDS:-300}"
MAX_CONTROL_PLANE_BYTES=1048576
STOPPED_COUNT=0
SKIPPED_COUNT=0
FAILED_COUNT=0

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
    --resource-group) require_argument "$@"; RESOURCE_GROUP="$2"; shift 2 ;;
    --environment)    require_argument "$@"; ENVIRONMENT="$2"; shift 2 ;;
    --subscription)   require_argument "$@"; SUBSCRIPTION="$2"; shift 2 ;;
    --dry-run)        DRY_RUN=1; shift ;;
    --json)           EMIT_JSON=1; shift ;;
    -h|--help)        sed -n '3,9p' "$0"; exit 0 ;;
    *)                die "unknown argument; use --help" ;;
  esac
done

[[ "$RESOURCE_GROUP" =~ ^[A-Za-z0-9._()-]{1,90}$ ]] || die "--resource-group is invalid"
case "$ENVIRONMENT" in
  staging|production) ;;
  *) die "--environment must be staging or production" ;;
esac
UUID_PATTERN='^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$'
[ -z "$SUBSCRIPTION" ] || [[ "$SUBSCRIPTION" =~ $UUID_PATTERN ]] || die "--subscription must be a UUID"
case "$COMMAND_TIMEOUT_SECONDS" in
  ''|*[!0-9]*) die "KP_AZURE_COMMAND_TIMEOUT_SECONDS must be an integer" ;;
esac
[ "$COMMAND_TIMEOUT_SECONDS" -ge 30 ] && [ "$COMMAND_TIMEOUT_SECONDS" -le 900 ] || \
  die "KP_AZURE_COMMAND_TIMEOUT_SECONDS must be between 30 and 900"

command -v python3 >/dev/null 2>&1 || die "python3 is not installed"
command -v az >/dev/null 2>&1 || die "the Azure CLI (az) is not installed"
AZ_BIN="$(command -v az)"
az() { bounded "$AZ_BIN" "$@"; }

ACTION_LOG="$(mktemp -t kp-nightly-shutdown.XXXXXX)"
SELECT_HELPER=""
cleanup() { rm -f "$ACTION_LOG" "$SELECT_HELPER"; }
trap cleanup EXIT

# Append one structured action record. Values arrive as argv, never as shell
# interpolation into a JSON string, so a hostile resource name cannot forge a
# record.
record() {
  python3 - "$ACTION_LOG" "$1" "$2" "$3" "$4" "$5" <<'PYRECORD'
import json
import sys

path, kind, name, action, result, reason = sys.argv[1:7]
with open(path, "a", encoding="utf-8") as target:
    target.write(
        json.dumps(
            {"kind": kind, "name": name, "action": action, "result": result, "reason": reason},
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )
PYRECORD
}

# Defense in depth. This script is permitted exactly four mutating Azure
# operations. Anything else is a bug and is refused before it can reach Azure.
# (backup create is a WRITE, but it only ever adds a restore point.)
az_write() {
  case "$*" in
    "postgres flexible-server backup create "*) ;;
    "postgres flexible-server stop "*) ;;
    "containerapp update "*" --min-replicas 0") ;;
    "vm deallocate "*) ;;
    *) die "refusing an Azure write outside the nightly power-down allowlist: az $*" ;;
  esac
  if [ "$DRY_RUN" -eq 1 ]; then
    log "would run: az $*"
    return 0
  fi
  az "$@" >/dev/null
}

# The selector reads the listing from a file, not from stdin: a `python3 -`
# heredoc already owns stdin, so a piped payload would silently read as empty
# and every resource would look "already off".
SELECT_HELPER="$(mktemp -t kp-nightly-select.XXXXXX)"
cat >"$SELECT_HELPER" <<'PYSELECT'
# Emit "name<TAB>state" for rows whose project tags match, and
# "name<TAB>__foreign__" for rows that do not, so skips stay auditable.
import json
import sys
from pathlib import Path

application, environment, state_field, listing_path = sys.argv[1:5]
payload = json.loads(Path(listing_path).read_text(encoding="utf-8") or "[]")
if not isinstance(payload, list) or len(payload) > 512:
    raise SystemExit("control-plane listing is malformed or exceeds the fixed limit")
for row in payload:
    if not isinstance(row, dict):
        raise SystemExit("control-plane listing is malformed")
    name = row.get("name")
    if not isinstance(name, str) or not name or "\t" in name or "\n" in name or len(name) > 128:
        raise SystemExit("control-plane listing contains an unusable resource name")
    if row.get("application") != application or row.get("environment") != environment:
        print(f"{name}\t__foreign__")
        continue
    state = row.get(state_field)
    print(f"{name}\t{'' if state is None else state}")
PYSELECT

# Discovery must fail loudly. A malformed listing that silently produced zero
# rows would look identical to "everything is already off".
selected_rows() {
  local label="$1" payload="$2" field="$3" listing selected status
  listing="$(mktemp -t kp-nightly-listing.XXXXXX)"
  printf '%s' "$payload" >"$listing"
  selected="$(python3 "$SELECT_HELPER" "$APPLICATION_TAG" "$ENVIRONMENT" "$field" "$listing")" && status=0 || status=$?
  rm -f "$listing"
  [ "$status" -eq 0 ] || die "could not interpret the $label listing from the Azure control plane"
  printf '%s\n' "$selected"
}

step "Nightly Azure power-down"
log "resource group: $RESOURCE_GROUP"
log "environment tag: $ENVIRONMENT"
log "mode: $([ "$DRY_RUN" -eq 1 ] && echo 'DRY RUN (nothing will be changed)' || echo 'APPLY')"

if [ -n "$SUBSCRIPTION" ]; then
  az account set --subscription "$SUBSCRIPTION" >/dev/null 2>&1 || \
    die "the selected subscription is not visible to this Azure login"
fi
CURRENT_SUBSCRIPTION="$(az account show --query id -o tsv 2>/dev/null)" || \
  die "Azure authentication failed; run: az login"
require_bounded_output "Azure account inspection" "$CURRENT_SUBSCRIPTION"
log "subscription: $CURRENT_SUBSCRIPTION"

az group show --name "$RESOURCE_GROUP" --query name -o tsv >/dev/null 2>&1 || \
  die "resource group '$RESOURCE_GROUP' is not visible to this Azure login"

# ---------------------------------------------------------------------------
# 1. PostgreSQL flexible server — the single biggest lever. Stopping retains all
#    data and Azure auto-restarts the server after ~7 days, so this is a cost
#    action, never a data action.
# ---------------------------------------------------------------------------
step "PostgreSQL flexible servers"
if ! PG_ROWS="$(az postgres flexible-server list --resource-group "$RESOURCE_GROUP" -o json \
    --query "[].{name:name,state:state,application:tags.application,environment:tags.environment}" 2>/dev/null)"; then
  die "could not list PostgreSQL flexible servers in $RESOURCE_GROUP"
fi
require_bounded_output "PostgreSQL listing" "$PG_ROWS"
if [ -z "$(printf '%s' "$PG_ROWS" | tr -d '[] \n')" ]; then
  log "none present — nothing to stop"
fi
while IFS=$'\t' read -r name state; do
  [ -n "$name" ] || continue
  case "$state" in
    __foreign__)
      log "SKIP $name — not tagged for this project/environment"
      record postgres "$name" none skipped "resource is not tagged $APPLICATION_TAG/$ENVIRONMENT"
      SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
      ;;
    Ready)
      # A STOPPED Azure PostgreSQL flexible server takes NO automated backups.
      # Observed directly on this server: dailies ran 2026-09-01..09-05, then
      # ceased the moment it was stopped. With 7-day retention, stopping it every
      # night would quietly age the restore window out to nothing. So take an
      # on-demand backup FIRST, and if that does not succeed leave the server
      # RUNNING — an unstopped server costs money, an unbacked one costs data.
      backup_name="nightly-$(date -u +%Y%m%dT%H%M%SZ)"
      log "BACKUP $name -> $backup_name (before stopping)"
      if ! az_write postgres flexible-server backup create --resource-group "$RESOURCE_GROUP" \
          --server-name "$name" --name "$backup_name"; then
        log "REFUSING to stop $name — pre-stop backup failed; leaving it running"
        record postgres "$name" backup failed \
          "pre-stop on-demand backup failed; server deliberately left running"
        FAILED_COUNT=$((FAILED_COUNT + 1))
        continue
      fi
      record postgres "$name" backup \
        "$([ "$DRY_RUN" -eq 1 ] && echo would_backup || echo backed_up)" \
        "on-demand restore point $backup_name taken before stop"
      log "STOP $name (state=$state)"
      if az_write postgres flexible-server stop --resource-group "$RESOURCE_GROUP" --name "$name"; then
        record postgres "$name" stop "$([ "$DRY_RUN" -eq 1 ] && echo would_stop || echo stopped)" "was $state"
        STOPPED_COUNT=$((STOPPED_COUNT + 1))
      else
        log "FAILED to stop $name"
        record postgres "$name" stop failed "az postgres flexible-server stop returned non-zero"
        FAILED_COUNT=$((FAILED_COUNT + 1))
      fi
      ;;
    *)
      log "SKIP $name — already not running (state=${state:-unknown})"
      record postgres "$name" none skipped "state is ${state:-unknown}, not Ready"
      SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
      ;;
  esac
done <<< "$(selected_rows "PostgreSQL" "$PG_ROWS" state)"

# ---------------------------------------------------------------------------
# 2. Container Apps — operator, tracking, ai-gateway and every worker. Setting
#    min-replicas to 0 removes the always-on replica charge and is reverted by
#    the next reviewed terraform apply (which is the manual restart path).
# ---------------------------------------------------------------------------
step "Container Apps"
if ! CA_ROWS="$(az containerapp list --resource-group "$RESOURCE_GROUP" -o json \
    --query "[].{name:name,minReplicas:properties.template.scale.minReplicas,application:tags.application,environment:tags.environment}" 2>/dev/null)"; then
  die "could not list Container Apps in $RESOURCE_GROUP"
fi
require_bounded_output "Container Apps listing" "$CA_ROWS"
if [ -z "$(printf '%s' "$CA_ROWS" | tr -d '[] \n')" ]; then
  log "none present — nothing to scale down"
fi
while IFS=$'\t' read -r name minimum; do
  [ -n "$name" ] || continue
  case "$minimum" in
    __foreign__)
      log "SKIP $name — not tagged for this project/environment"
      record containerapp "$name" none skipped "resource is not tagged $APPLICATION_TAG/$ENVIRONMENT"
      SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
      ;;
    0)
      # "min-replicas 0" at the APP level does NOT mean nothing is billing. Under
      # revision_mode=Multiple every past deploy leaves its revision ACTIVE, each
      # pinned at the min_replicas it was born with, and scaling the app does not
      # touch them. On 2026-09-07 operator+tracking were reporting 0 here while 75
      # orphaned replicas billed continuously (~$889/mo). Report it loudly — this
      # script deliberately does not deactivate revisions (that is a destructive,
      # deploy-history-mutating action an unattended timer should not take), but it
      # must never again say "already scaled down" while replicas are running.
      # Count replicas held by active revisions OTHER than the current one. The
      # live revision legitimately scaling up (a queue rule waking a worker) is not
      # this bug and must not cry wolf every night; replicas pinned on SUPERSEDED
      # revisions always are.
      current_rev="$(az containerapp show --resource-group "$RESOURCE_GROUP" --name "$name" \
        --query "properties.latestRevisionName" -o tsv 2>/dev/null)"
      orphan_replicas="$(az containerapp revision list --resource-group "$RESOURCE_GROUP" \
        --name "$name" --query \
        "[?properties.active && name!='${current_rev}'].properties.replicas" -o tsv 2>/dev/null \
        | awk '{s+=$1} END {print s+0}')"
      if [ "${orphan_replicas:-0}" -gt 0 ]; then
        log "WARNING $name — ${orphan_replicas} replica(s) BILLING on superseded revisions"
        log "         orphaned active revisions are holding them; see docs/design/AZURE-RESIDENCY-AUDIT-2026-09.md"
        record containerapp "$name" none billing_replicas_remain \
          "${orphan_replicas} replicas pinned on superseded revisions despite app min-replicas 0"
        SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
        continue
      fi
      log "SKIP $name — already at min-replicas 0"
      record containerapp "$name" none skipped "min-replicas is already 0"
      SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
      ;;
    *)
      log "SCALE $name to min-replicas 0 (was ${minimum:-unknown})"
      if az_write containerapp update --name "$name" --resource-group "$RESOURCE_GROUP" --min-replicas 0; then
        record containerapp "$name" scale_to_zero \
          "$([ "$DRY_RUN" -eq 1 ] && echo would_scale_to_zero || echo scaled_to_zero)" \
          "min-replicas was ${minimum:-unknown}"
        STOPPED_COUNT=$((STOPPED_COUNT + 1))
      else
        log "FAILED to scale $name"
        record containerapp "$name" scale_to_zero failed "az containerapp update returned non-zero"
        FAILED_COUNT=$((FAILED_COUNT + 1))
      fi
      ;;
  esac
done <<< "$(selected_rows "Container Apps" "$CA_ROWS" minReplicas)"

# ---------------------------------------------------------------------------
# 3. CI runner VM — deallocate (not delete). Deallocated compute bills nothing;
#    the OS disk survives, so `az vm start` brings the same runner back.
# ---------------------------------------------------------------------------
# Deliberately NOT `az vm list --show-details`. That convenience flag shells out to
# network commands to report IP addresses, so it needs
# Microsoft.Network/networkInterfaces/read and Microsoft.Network/publicIPAddresses/read —
# permissions the least-privilege nightly role does not hold, and does not need in order
# to power a VM down. (Verified against real Azure: --show-details fails for this role
# with "could not list virtual machines".) Power state comes from the instance view,
# which Microsoft.Compute/virtualMachines/instanceView/read does grant.
vm_rows_with_power_state() {
  python3 - "$RESOURCE_GROUP" <<'PYVM'
import json
import subprocess
import sys

resource_group = sys.argv[1]


def _az(args: list[str]) -> tuple[int, str]:
    try:
        done = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["az", *args], capture_output=True, text=True, timeout=120
        )
    except Exception:
        return 1, ""
    return done.returncode, done.stdout or ""


code, listed = _az(
    [
        "vm", "list", "--resource-group", resource_group, "-o", "json",
        "--query", "[].{name:name,application:tags.application,environment:tags.environment}",
    ]
)
if code != 0:
    sys.exit(1)
try:
    rows = json.loads(listed or "[]")
except ValueError:
    sys.exit(1)
for row in rows:
    name = row.get("name") or ""
    power = ""
    if name:
        got_code, got = _az(
            [
                "vm", "get-instance-view", "--resource-group", resource_group, "--name", name,
                "--query",
                "instanceView.statuses[?starts_with(code, 'PowerState/')].displayStatus | [0]",
                "-o", "tsv",
            ]
        )
        if got_code == 0:
            power = got.strip()
    row["powerState"] = power
print(json.dumps(rows))
PYVM
}

step "CI runner virtual machines"
if ! VM_ROWS="$(vm_rows_with_power_state)"; then
  die "could not list virtual machines in $RESOURCE_GROUP"
fi
require_bounded_output "Virtual machine listing" "$VM_ROWS"
if [ -z "$(printf '%s' "$VM_ROWS" | tr -d '[] \n')" ]; then
  log "none present — nothing to deallocate"
fi
while IFS=$'\t' read -r name power; do
  [ -n "$name" ] || continue
  case "$power" in
    __foreign__)
      log "SKIP $name — not tagged for this project/environment"
      record vm "$name" none skipped "resource is not tagged $APPLICATION_TAG/$ENVIRONMENT"
      SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
      ;;
    *deallocat*)
      log "SKIP $name — already ${power}"
      record vm "$name" none skipped "power state is ${power:-unknown}"
      SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
      ;;
    *)
      log "DEALLOCATE $name (power state=${power:-unknown})"
      if az_write vm deallocate --resource-group "$RESOURCE_GROUP" --name "$name"; then
        record vm "$name" deallocate \
          "$([ "$DRY_RUN" -eq 1 ] && echo would_deallocate || echo deallocated)" \
          "power state was ${power:-unknown}"
        STOPPED_COUNT=$((STOPPED_COUNT + 1))
      else
        log "FAILED to deallocate $name"
        record vm "$name" deallocate failed "az vm deallocate returned non-zero"
        FAILED_COUNT=$((FAILED_COUNT + 1))
      fi
      ;;
  esac
done <<< "$(selected_rows "virtual machine" "$VM_ROWS" powerState)"

# ---------------------------------------------------------------------------
# Deliberately untouched. Printed every run so the cost reasoning stays visible
# in the log rather than only in the docs.
# ---------------------------------------------------------------------------
step "Left running on purpose"
log "ACR + Redis           — destroying them nightly would force re-pushing every"
log "                        image before tomorrow's test; only azure-idle.sh stop"
log "                        removes them, behind a reviewed terraform plan."
log "ACS + email domain    — Tier 1, ~\$0. Rebuilding means SPF/DKIM re-verification"
log "  + public DNS + Entra  and a Namecheap purge risk. Never torn down."
log "Event Grid receipts   — Tier 1, per-event, ~\$0."
log "Key Vault / audit     — audit anchor storage is locked WORM by design."
log "  anchor storage"
log "Container App jobs    — migration job is manually triggered; \$0 while idle."
log "Networking            — starter-mode public endpoints; the private-mode"
log "                        endpoints are removed by terraform, not by a timer."

step "Summary"
log "changed: $STOPPED_COUNT   skipped: $SKIPPED_COUNT   failed: $FAILED_COUNT"
if [ "$DRY_RUN" -eq 1 ]; then
  log "DRY RUN — no Azure resource was modified."
fi
log "Restart is MANUAL and on demand: docs/NIGHTLY-AZURE-SHUTDOWN.md"

if [ "$EMIT_JSON" -eq 1 ]; then
  step "Machine-readable action log"
  cat "$ACTION_LOG"
fi

[ "$FAILED_COUNT" -eq 0 ] || die "$FAILED_COUNT resource(s) could not be powered down; inspect them in Azure"
exit 0
