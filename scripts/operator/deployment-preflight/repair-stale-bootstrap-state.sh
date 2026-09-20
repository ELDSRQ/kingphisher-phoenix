#!/usr/bin/env bash
# repair-stale-bootstrap-state.sh — clear the three stale Terraform state entries
# that make the staging foundation_bootstrap plan non-create/update-only, which
# the workflow's plan allowlist (.github/workflows/azure-deploy.yml, step
# "Enforce ACS foundation bootstrap plan allowlist") rejects outright.
#
# WHY each entry is stale (verified 2026-09-20 against live Azure):
#   random_password.ai_gateway_auth[0]
#       count = var.deploy_workloads && var.deploy_ai_gateway (main.tf:759).
#       foundation_bootstrap hardcodes deploy_workloads=false, so the count
#       collapses to 0. No Azure resource backs it; it is pure state.
#   azurerm_key_vault_secret.runtime["ai-gateway-auth-key"]
#       Reads random_password.ai_gateway_auth[0].result (main.tf:1119); falls
#       with it. The vault secret itself is left in place and the workloads
#       phase writes a fresh version.
#   azurerm_role_assignment.audit_anchor_writer
#       Binds azurerm_user_assigned_identity.workload["worker"].principal_id
#       (main.tf:941). When that identity has been deleted outside Terraform the
#       principal_id becomes known-after-apply and Terraform forces a
#       replacement, leaving the live assignment orphaned to a dead principal.
#       This is drift, NOT a phase artifact: after a successful apply the
#       assignment is healthy again and must be left alone. The script therefore
#       reads principal_id out of state and removes the entry only when that
#       principal no longer resolves in Entra.
#
# This is state-only surgery plus one optional orphan cleanup. It creates NO
# Azure resources and deletes no data. A full state snapshot is written to disk
# before anything is modified.
#
# Every candidate must PROVE it is stale before removal. Nothing is removed on
# the strength of a guessed resource name: an earlier version guarded on a
# hardcoded identity name that never existed (the suffix is "kp-staging", not
# "kp-staging-6117w"), so the guard passed vacuously and would have removed a
# healthy entry once the environment recovered.
#
# Overrides:
#   REPO_ROOT=/abs/path   repo root (default: git toplevel from this script)
#   SNAPSHOT_DIR=/abs/dir where the pre-surgery state snapshot is written
#                         (default: $REPO_ROOT/.tf-state-snapshots)
#   DELETE_ORPHAN_ROLE=no skip deleting the orphaned audit-anchor role
#                         assignment (default: yes)
#   CONFIRM=yes           required to modify anything; without it the script
#                         runs read-only and shows exactly what it would do.
#
# Run read-only first:   bash scripts/operator/deployment-preflight/repair-stale-bootstrap-state.sh
# Then, to apply:  CONFIRM=yes bash scripts/operator/deployment-preflight/repair-stale-bootstrap-state.sh
set -euo pipefail

say(){  printf "\033[1;34m==>\033[0m %s\n" "$*"; }
ok(){   printf "\033[1;32m  ok\033[0m %s\n" "$*"; }
warn(){ printf "\033[1;33m  !!\033[0m %s\n" "$*"; }
die(){  printf "\033[1;31m  xx\033[0m %s\n" "$*"; exit 1; }

CONFIRM="${CONFIRM:-no}"
DELETE_ORPHAN_ROLE="${DELETE_ORPHAN_ROLE:-yes}"

# Backend + identity constants, read from the staging GitHub environment
# variables on 2026-09-20 so this script needs no lookups.
TF_STATE_RESOURCE_GROUP="rg-kp-tfstate-staging"
TF_STATE_STORAGE_ACCOUNT="kptfstatestg1165"
TF_STATE_CONTAINER="tfstate"
TF_STATE_KEY="staging/kingphisher.tfstate"
SUBSCRIPTION_ID="169644fd-c81d-4935-af55-5770f8271022"
ORPHAN_ROLE_SCOPE="/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/rg-kp-staging/providers/Microsoft.Storage/storageAccounts/stkpstagingaudit6117w/blobServices/default/containers/audit-head-anchors"

# Addresses whose staleness is proved by inspecting their principal: the state
# entry is removed ONLY when the principal it binds no longer resolves in Entra.
# A healthy assignment is left alone.
PRINCIPAL_BOUND_ADDRESSES=(
  'azurerm_role_assignment.audit_anchor_writer'
)

# Addresses that go stale purely because foundation_bootstrap plans with
# deploy_workloads=false. These are only candidates while the manifest still
# gates them on that flag; once the gate is fixed they can never collapse and
# must never be removed.
PHASE_COLLAPSE_ADDRESSES=(
  'random_password.ai_gateway_auth[0]'
  'azurerm_key_vault_secret.runtime["ai-gateway-auth-key"]'
)

# ---------------------------------------------------------------- 1. discover
say "Resolving paths"
if [ -n "${REPO_ROOT:-}" ]; then
  REPO_ROOT="$(cd "$REPO_ROOT" && pwd)"
else
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
fi
TF_DIR="$REPO_ROOT/infrastructure/terraform"
SNAPSHOT_DIR="${SNAPSHOT_DIR:-$REPO_ROOT/.tf-state-snapshots}"
[ -f "$TF_DIR/main.tf" ] || die "no main.tf under $TF_DIR; pass REPO_ROOT=/abs/path"
echo "     REPO_ROOT    = $REPO_ROOT"
echo "     TF_DIR       = $TF_DIR"
echo "     SNAPSHOT_DIR = $SNAPSHOT_DIR"
ok "paths resolved"

say "Checking prerequisites"
command -v terraform >/dev/null 2>&1 || die "terraform not on PATH"
command -v az >/dev/null 2>&1 || die "az not on PATH"
export AZURE_CONFIG_DIR="${AZURE_CONFIG_DIR:-$HOME/.azure}"
echo "     terraform        = $(terraform version | head -n1)"
echo "     AZURE_CONFIG_DIR = $AZURE_CONFIG_DIR"
ACCOUNT_NAME="$(az account show --query user.name -o tsv 2>/dev/null || true)"
[ -n "$ACCOUNT_NAME" ] || die "az is not logged in; run: az login"
echo "     az account       = $ACCOUNT_NAME"
ok "prerequisites present"

# ------------------------------------------------------------------- 2. init
say "Initializing Terraform against the staging backend"
cd "$TF_DIR"
terraform init -input=false -reconfigure \
  -backend-config="resource_group_name=$TF_STATE_RESOURCE_GROUP" \
  -backend-config="storage_account_name=$TF_STATE_STORAGE_ACCOUNT" \
  -backend-config="container_name=$TF_STATE_CONTAINER" \
  -backend-config="key=$TF_STATE_KEY" \
  -backend-config="use_azuread_auth=true" >/dev/null \
  || die "terraform init failed; confirm Storage Blob Data Contributor on $TF_STATE_STORAGE_ACCOUNT"
ok "backend initialized ($TF_STATE_STORAGE_ACCOUNT/$TF_STATE_CONTAINER/$TF_STATE_KEY)"

# -------------------------------------------------------------- 3. snapshot
say "Snapshotting state before any modification"
mkdir -p "$SNAPSHOT_DIR"
SNAPSHOT="$SNAPSHOT_DIR/staging-kingphisher-$(date -u +%Y%m%dT%H%M%SZ).tfstate"
terraform state pull > "$SNAPSHOT" || die "terraform state pull failed"
[ -s "$SNAPSHOT" ] || die "state snapshot is empty; refusing to continue"
SNAPSHOT_SERIAL="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("serial","?"))' "$SNAPSHOT")"
echo "     SNAPSHOT = $SNAPSHOT"
echo "     serial   = $SNAPSHOT_SERIAL"
ok "state snapshot written ($(wc -c < "$SNAPSHOT" | tr -d ' ') bytes)"

# -------------------------------------------------- 4. verify staleness live
# Every candidate must PROVE it is stale. An earlier version of this script
# trusted a hardcoded identity name (id-kp-staging-6117w-worker) that never
# existed — the suffix is "kp-staging", not "kp-staging-6117w" — so the guard
# passed vacuously and would have removed a perfectly healthy state entry.
# Nothing here is name-guessed any more.
STATE_LIST="$(terraform state list)"
PRESENT=()

say "Proving staleness of principal-bound addresses"
for addr in "${PRINCIPAL_BOUND_ADDRESSES[@]}"; do
  if ! printf '%s\n' "$STATE_LIST" | grep -Fxq "$addr"; then
    echo "     absent   $addr (not in state)"
    continue
  fi
  principal="$(terraform state show -no-color "$addr" 2>/dev/null \
    | awk -F'"' '/^[[:space:]]*principal_id[[:space:]]*=/ {print $2; exit}')"
  if [ -z "$principal" ]; then
    warn "SKIP     $addr (cannot read principal_id from state; refusing to guess)"
    continue
  fi
  if az ad sp show --id "$principal" >/dev/null 2>&1; then
    echo "     healthy  $addr (principal $principal still exists) — leaving alone"
  else
    echo "     STALE    $addr (principal $principal no longer exists)"
    PRESENT+=("$addr")
  fi
done

say "Checking whether the phase-collapse addresses still apply"
# These only go stale while the manifest gates them on deploy_workloads. Once
# that gate is removed they can never collapse under foundation_bootstrap, so
# removing them would destroy live configuration rather than repair it.
MANIFEST="$TF_DIR/main.tf"
if grep -q 'count   = var.deploy_workloads && var.deploy_ai_gateway ? 1 : 0' "$MANIFEST"; then
  echo "     manifest still gates ai_gateway_auth on deploy_workloads — addresses apply"
  for addr in "${PHASE_COLLAPSE_ADDRESSES[@]}"; do
    if printf '%s\n' "$STATE_LIST" | grep -Fxq "$addr"; then
      echo "     STALE    $addr (collapses under deploy_workloads=false)"
      PRESENT+=("$addr")
    else
      echo "     absent   $addr (already cleared)"
    fi
  done
else
  ok "manifest no longer gates ai_gateway_auth on deploy_workloads — these can no longer collapse, skipping"
fi

if [ "${#PRESENT[@]}" -eq 0 ]; then
  ok "nothing to remove; state is already clean"
else
  ok "${#PRESENT[@]} address(es) proved stale"
fi

# ----------------------------------------------------------- 5. orphan role
ORPHAN_NAMES=()
if [ "$DELETE_ORPHAN_ROLE" = "yes" ]; then
  say "Checking for role assignments on the audit-anchor container bound to deleted principals"
  while IFS=$'\t' read -r ra_name ra_principal; do
    [ -n "$ra_name" ] || continue
    if az ad sp show --id "$ra_principal" >/dev/null 2>&1; then
      echo "     live     $ra_name (principal $ra_principal still exists)"
    else
      echo "     orphan   $ra_name (principal $ra_principal no longer exists)"
      ORPHAN_NAMES+=("$ra_name")
    fi
  done < <(az role assignment list --scope "$ORPHAN_ROLE_SCOPE" --query "[].[name,principalId]" -o tsv 2>/dev/null || true)
  if [ "${#ORPHAN_NAMES[@]}" -eq 0 ]; then
    ok "no orphaned assignments found"
  else
    ok "${#ORPHAN_NAMES[@]} orphaned assignment(s) to delete"
  fi
else
  warn "DELETE_ORPHAN_ROLE=no — leaving any orphaned role assignment in place"
fi

# ---------------------------------------------------------------- 6. apply
if [ "$CONFIRM" != "yes" ]; then
  echo
  warn "DRY RUN — nothing was modified."
  warn "State snapshot was still written to: $SNAPSHOT"
  echo
  echo "     To apply the repair, re-run with CONFIRM=yes:"
  echo "       CONFIRM=yes bash $REPO_ROOT/scripts/operator/deployment-preflight/repair-stale-bootstrap-state.sh"
  exit 0
fi

if [ "${#PRESENT[@]}" -gt 0 ]; then
  say "Removing stale addresses from state"
  for addr in "${PRESENT[@]}"; do
    terraform state rm "$addr" >/dev/null || die "terraform state rm failed for: $addr"
    ok "removed $addr"
  done
fi

if [ "${#ORPHAN_NAMES[@]}" -gt 0 ]; then
  say "Deleting orphaned role assignments"
  for ra_name in "${ORPHAN_NAMES[@]}"; do
    az role assignment delete --ids "$ORPHAN_ROLE_SCOPE/providers/Microsoft.Authorization/roleAssignments/$ra_name" >/dev/null \
      || die "failed to delete orphaned role assignment $ra_name"
    ok "deleted orphaned assignment $ra_name"
  done
fi

# ---------------------------------------------------------------- 7. verify
say "Verifying"
STATE_LIST_AFTER="$(terraform state list)"
FAILED=0
# Only the addresses proved stale should be gone. Anything left healthy was
# deliberately not touched and must NOT be reported as a failure.
if [ "${#PRESENT[@]}" -gt 0 ]; then
  for addr in "${PRESENT[@]}"; do
    if printf '%s\n' "$STATE_LIST_AFTER" | grep -Fxq "$addr"; then
      warn "STILL PRESENT: $addr"
      FAILED=1
    else
      ok "cleared $addr"
    fi
  done
else
  ok "no addresses needed removal"
fi
[ "$FAILED" -eq 0 ] || die "state still contains stale addresses; do not re-dispatch yet"
echo "     resources remaining in state: $(printf '%s\n' "$STATE_LIST_AFTER" | wc -l | tr -d ' ')"
ok "state repair complete; rollback snapshot at $SNAPSHOT"

echo
say "Next step — re-dispatch the staging bootstrap:"
echo "  bash $REPO_ROOT/scripts/operator/deployment-preflight/dispatch-staging-bootstrap.sh"
echo
say "Then approve the run's staging environment; list pending deployments with:"
echo "  gh api /repos/ELDSRQ/kingphisher-phoenix/actions/runs/RUN_ID/pending_deployments"
