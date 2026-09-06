#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# azure-idle.sh — idle/resume the expensive Azure tier to cut cost between real
# sends, per docs/HYBRID-AZURE-LOCAL-PLAN.md (Path B).
#
#   status  read-only: Postgres power state, Container App revisions, ACR/Redis presence
#   stop    idle: stop Postgres (retains data) + plan/confirm/apply deploy_data_plane=false
#   start   resume: start Postgres + plan/confirm/apply the workloads/data plane + OIDC re-patch
#
# SAFE BY DESIGN:
#   - Postgres is STOPPED, never destroyed (it carries prevent_destroy; stop retains
#     data and auto-restarts within ~7 days).
#   - The Terraform step ALWAYS shows a plan and requires you to type 'yes' after
#     reviewing it — the idle path has not been plan-verified, so you must confirm it
#     destroys ONLY ACR + Redis + Container Apps and nothing else.
#
# Requires: az (logged in), terraform (init'd with the real backend). Assumes the
# staging resource group + operator app names below; override via env.
# ---------------------------------------------------------------------------
set -euo pipefail

RG="${KP_RG:-rg-kp-staging}"
ENVNAME="${KP_ENV:-staging}"
OPERATOR_APP="${KP_OPERATOR_APP:-ca-kp-staging-operator}"
OIDC_CLIENT_ID="${KP_OIDC_CLIENT_ID:-97466174-d0ac-460c-94e8-7b6ff3c83da5}"
TF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../infrastructure/terraform" && pwd)"
VARFILE="environments/${ENVNAME}.tfvars"

die() { echo "!! $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || die "$1 not on PATH"; }
need az; need terraform
az account show >/dev/null 2>&1 || die "not logged in — run 'az login' first"

pg_server() {
  az postgres flexible-server list -g "$RG" --query "[0].name" -o tsv 2>/dev/null
}

confirm_apply() {
  # $1 = human label, remaining args = -var flags
  local label="$1"; shift
  echo "==> terraform plan ($label) in $TF_DIR"
  ( cd "$TF_DIR" && terraform plan -input=false -var-file="$VARFILE" "$@" -out=".idle.tfplan" ) || die "plan failed"
  echo
  echo "  REVIEW THE PLAN ABOVE. For 'stop' it must destroy ONLY the registry, Redis,"
  echo "  their private endpoints/role/secret, and (if idling) the Container Apps —"
  echo "  and must show NO destroy/replace of Postgres or the audit storage."
  read -r -p "  Type 'yes' to apply this plan: " ans
  [ "$ans" = "yes" ] || { rm -f "$TF_DIR/.idle.tfplan"; die "aborted — nothing applied"; }
  ( cd "$TF_DIR" && terraform apply -input=false ".idle.tfplan" )
  rm -f "$TF_DIR/.idle.tfplan"
}

repatch_oidc() {
  echo "==> re-patching operator OIDC env (reverts on every deploy)"
  az containerapp update --name "$OPERATOR_APP" -g "$RG" --set-env-vars \
    "OPERATOR_API_OIDC_SCOPES=openid profile api://${OIDC_CLIENT_ID}/console" \
    "OPERATOR_API_OIDC_AUDIENCE=${OIDC_CLIENT_ID}" >/dev/null \
    && echo "   OIDC env re-patched." || echo "   (operator app not up yet — re-patch after it is)"
}

cmd_status() {
  local pg; pg="$(pg_server || true)"
  echo "=== resource group: $RG ==="
  if [ -n "$pg" ]; then
    echo "Postgres '$pg' state: $(az postgres flexible-server show -g "$RG" -n "$pg" --query state -o tsv 2>/dev/null || echo '?')"
  else
    echo "Postgres: none found"
  fi
  echo "--- Container Apps (name : running revision) ---"
  az containerapp list -g "$RG" --query "[].{n:name,rev:properties.latestReadyRevisionName}" -o tsv 2>/dev/null || echo "  (none)"
  echo "--- ACR present: $(az acr list -g "$RG" --query "length(@)" -o tsv 2>/dev/null || echo '?') | Redis present: $(az redisenterprise list -g "$RG" --query "length(@)" -o tsv 2>/dev/null || echo '?') ---"
}

cmd_stop() {
  local pg; pg="$(pg_server)" || die "no Postgres server found in $RG"
  echo "==> stopping Postgres '$pg' (retains data; ~7-day auto-restart)"
  az postgres flexible-server stop -g "$RG" -n "$pg" 2>&1 | tail -2 || true
  confirm_apply "idle: ACR+Redis+workloads OFF" \
    -var "deploy_workloads=false" -var "deploy_data_plane=false"
  echo "==> IDLED. Tier-1 (ACS/domain/DNS) stays up at ~\$0. Resume with: $0 start"
}

cmd_start() {
  local pg; pg="$(pg_server)" || die "no Postgres server found in $RG"
  echo "==> starting Postgres '$pg'"
  az postgres flexible-server start -g "$RG" -n "$pg" 2>&1 | tail -2 || true
  confirm_apply "resume: ACR+Redis+workloads ON" \
    -var "deploy_workloads=true" -var "deploy_data_plane=true"
  repatch_oidc
  echo "==> RESUMED. Log in at the operator console and verify before a real send."
}

case "${1:-status}" in
  status) cmd_status ;;
  stop)   cmd_stop ;;
  start)  cmd_start ;;
  *) echo "usage: $0 {status|stop|start}"; exit 2 ;;
esac
