#!/usr/bin/env bash
# recreate-foundry-and-finish.sh — recreate the out-of-band AI Foundry account
# and its model deployments, then re-run the private workloads deploy.
#
# WHY: the Foundry account and its model deployments are NOT Terraform-managed
# (AI_HANDOFF_2026-09-12.md §"Foundry account + model deployments are NOT
# Terraform-managed"). rg-kp-staging was deleted on 2026-09-14, taking the
# account with it, so azurerm_role_assignment.ai_gateway_foundry_user now fails
# the workloads apply with ResourceNotFound on
# Microsoft.CognitiveServices/accounts/ais-kp-staging-6117w.
#
# THIS CREATES BILLABLE AZURE RESOURCES: one AIServices S0 account plus three
# GlobalStandard model deployments. Pay-per-token; the deployments themselves
# are not charged hourly, but the account is a real resource.
#
# Idempotent: every create is skipped when the object already exists.
#
# Overrides:
#   SKIP_DEPLOY=1   recreate Foundry only, do not re-run the workloads deploy
#   AUTO_APPROVE=1  approve the protected staging environment without prompting
#
# Run: bash /Users/edierks/projects/codex-test/phishing-awareness-platform/scripts/operator/deployment-preflight/recreate-foundry-and-finish.sh
set -euo pipefail

REPO="ELDSRQ/kingphisher-phoenix"
ENV_ID=20961255392
ROOT="/Users/edierks/projects/codex-test/phishing-awareness-platform"
RG="rg-kp-staging"
FOUNDRY="ais-kp-staging-6117w"
LOCATION="eastus2"

say(){  printf "\033[1;34m==>\033[0m %s\n" "$*"; }
ok(){   printf "\033[1;32m  ok\033[0m %s\n" "$*"; }
warn(){ printf "\033[1;33m  !!\033[0m %s\n" "$*"; }
die(){  printf "\033[1;31m  xx\033[0m %s\n" "$*"; exit 1; }

export AZURE_CONFIG_DIR="${AZURE_CONFIG_DIR:-$HOME/.azure}"
cd "$ROOT"
command -v az >/dev/null || die "az not on PATH"
az account show >/dev/null 2>&1 || die "az is not logged in; run: az login"
echo "     REPO_ROOT = $ROOT"
echo "     account   = $(az account show --query user.name -o tsv)"

# ------------------------------------------------------- 1. Foundry account
say "Ensuring Foundry account $FOUNDRY"
if az cognitiveservices account show -g "$RG" -n "$FOUNDRY" >/dev/null 2>&1; then
  ok "account already exists"
else
  az cognitiveservices account create \
    --name "$FOUNDRY" --resource-group "$RG" --location "$LOCATION" \
    --kind AIServices --sku S0 --custom-domain "$FOUNDRY" \
    --yes >/dev/null || die "failed to create the Foundry account"
  ok "created $FOUNDRY (AIServices/S0/$LOCATION)"
fi

# --------------------------------------------------- 2. Microsoft.Bing
say "Ensuring the Microsoft.Bing provider is registered (Responses web_search)"
state="$(az provider show -n Microsoft.Bing --query registrationState -o tsv 2>/dev/null || echo NotRegistered)"
if [ "$state" = "Registered" ]; then
  ok "Microsoft.Bing already Registered"
else
  az provider register -n Microsoft.Bing >/dev/null || warn "could not register Microsoft.Bing"
  ok "registration requested (async; /discover web_search needs it)"
fi

# -------------------------------------------------- 3. model deployments
# name|model|version|capacity  — versions per AI_HANDOFF_2026-09-12/13.
# The model FORMAT differs by publisher: the GA OpenAI models are "OpenAI",
# while the open-weight gpt-oss family is "OpenAI-OSS". Passing the wrong one
# fails with DeploymentModelNotSupported. Confirm with:
#   az cognitiveservices model list -l eastus2 \
#     --query "[?model.name=='<name>'].{v:model.version,f:model.format}" -o table
deploy_model() {
  local name="$1" model="$2" version="$3" capacity="$4" format="${5:-OpenAI}" required="${6:-yes}"
  if az cognitiveservices account deployment show \
       -g "$RG" -n "$FOUNDRY" --deployment-name "$name" >/dev/null 2>&1; then
    ok "deployment $name already exists"
    return
  fi
  say "Creating deployment $name ($model v$version, $format, GlobalStandard, capacity $capacity)"
  if az cognitiveservices account deployment create \
       -g "$RG" -n "$FOUNDRY" \
       --deployment-name "$name" \
       --model-name "$model" --model-version "$version" --model-format "$format" \
       --sku-name GlobalStandard --sku-capacity "$capacity" >/dev/null 2>&1; then
    ok "created $name"
  elif [ "$required" = "yes" ]; then
    die "failed to create deployment $name"
  else
    warn "could not create optional deployment $name — continuing"
    warn "staging does not use it; it is kept only for rollback / A-B and is production's default"
  fi
}

# staging.tfvars pins terra for generation and luna for extract + discover;
# gpt-oss-120b is kept for rollback / A-B and is production's default.
deploy_model "gpt-5.6-terra"  "gpt-5.6-terra"  "2026-07-09" 100 "OpenAI"
deploy_model "gpt-5.6-luna"   "gpt-5.6-luna"   "2026-07-09" 200 "OpenAI"
# Open-weight family: format is OpenAI-OSS. Not required by staging (staging.tfvars
# pins terra + luna), so a failure here must not block the deploy.
deploy_model "gpt-oss-120b"   "gpt-oss-120b"   "1"          100 "OpenAI-OSS" "no"

say "Foundry state"
az cognitiveservices account deployment list -g "$RG" -n "$FOUNDRY" \
  --query "[].{name:name,model:properties.model.name,version:properties.model.version,sku:sku.name}" -o table

[ "${SKIP_DEPLOY:-0}" = "1" ] && { ok "SKIP_DEPLOY=1 — stopping before the deploy"; exit 0; }

# ------------------------------------------------------ 4. re-run workloads
say "Syncing main"
git checkout main -q && git pull -q origin main
ok "main = $(git rev-parse --short HEAD)"
grep -q NETWORK_MODE scripts/operator/deployment-preflight/dispatch-staging-finalize.sh \
  || die "dispatcher lacks NETWORK_MODE; merge PR #48 first"

say "Dispatching staging / private / workloads"
out="$(NETWORK_MODE=private PHASE=workloads bash scripts/operator/deployment-preflight/dispatch-staging-finalize.sh)"
echo "$out"
RUN_ID="$(printf '%s' "$out" | grep -oE 'actions/runs/[0-9]+' | head -n1 | grep -oE '[0-9]+')"
[ -n "$RUN_ID" ] || die "could not determine the dispatched run id"
ok "run $RUN_ID -> https://github.com/$REPO/actions/runs/$RUN_ID"

say "Waiting for the approval gate"
for _ in $(seq 1 60); do
  st="$(gh run view "$RUN_ID" --repo "$REPO" --json status --jq .status 2>/dev/null || echo unknown)"
  case "$st" in
    waiting)   ok "at the staging approval gate"; break;;
    completed) die "run finished before the gate; see https://github.com/$REPO/actions/runs/$RUN_ID";;
  esac
  sleep 20
done

if [ "${AUTO_APPROVE:-0}" != "1" ]; then
  printf "\n     Approve the protected staging environment for run %s? [y/N] " "$RUN_ID"
  read -r answer
  case "$answer" in
    [yY]*) ;;
    *) warn "not approved; approve later with:"
       echo "  gh api --method POST /repos/$REPO/actions/runs/$RUN_ID/pending_deployments -F 'environment_ids[]=$ENV_ID' -f state=approved -f comment='workloads private'"
       exit 0;;
  esac
fi
gh api --method POST "/repos/$REPO/actions/runs/$RUN_ID/pending_deployments" \
  -F "environment_ids[]=$ENV_ID" -f state=approved -f comment='workloads private' >/dev/null \
  || die "approval failed"
ok "approved"

say "Following the run (~20-40 min on the VNet runner)"
prev=""
while :; do
  j="$(gh run view "$RUN_ID" --repo "$REPO" --json status,conclusion,jobs 2>/dev/null)" || { sleep 20; continue; }
  cur="$(printf '%s' "$j" | jq -r '.jobs[] | select(.name|test("Deploy reviewed Azure phase")) | .steps[] | select(.conclusion != null and .conclusion != "" and .conclusion != "skipped") | "\(.conclusion|ascii_upcase)\t\(.name)"')"
  comm -13 <(printf '%s\n' "$prev") <(printf '%s\n' "$cur") | grep -v '^$' || true
  prev="$cur"
  [ "$(printf '%s' "$j" | jq -r .status)" = "completed" ] || { sleep 20; continue; }
  concl="$(printf '%s' "$j" | jq -r .conclusion)"
  echo
  if [ "$concl" = "success" ]; then
    ok "workloads COMPLETED"
  else
    warn "workloads finished: $concl"
    echo "     gh run view $RUN_ID --repo $REPO --log-failed | tail -40"
  fi
  break
done

echo
say "Verify what landed:"
echo "  az containerapp list -g $RG --query \"[].{name:name,running:properties.runningStatus}\" -o table"
