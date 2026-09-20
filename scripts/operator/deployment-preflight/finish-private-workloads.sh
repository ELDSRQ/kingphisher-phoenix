#!/usr/bin/env bash
# finish-private-workloads.sh — merge the two open fixes, dispatch the private
# workloads deploy, approve it, and follow it to completion. One command.
#
# Safe to re-run: each step checks whether it is already done.
#
# Overrides:
#   SKIP_MERGE=1   don't merge PRs #48/#49 (use if already merged)
#   AUTO_APPROVE=1 approve the protected staging environment without prompting
#
# Run: bash /Users/edierks/projects/codex-test/phishing-awareness-platform/scripts/operator/deployment-preflight/finish-private-workloads.sh
set -euo pipefail

REPO="ELDSRQ/kingphisher-phoenix"
ENV_ID=20961255392
ROOT="/Users/edierks/projects/codex-test/phishing-awareness-platform"

say(){  printf "\033[1;34m==>\033[0m %s\n" "$*"; }
ok(){   printf "\033[1;32m  ok\033[0m %s\n" "$*"; }
warn(){ printf "\033[1;33m  !!\033[0m %s\n" "$*"; }
die(){  printf "\033[1;31m  xx\033[0m %s\n" "$*"; exit 1; }

export AZURE_CONFIG_DIR="${AZURE_CONFIG_DIR:-$HOME/.azure}"
cd "$ROOT"
echo "     REPO_ROOT = $ROOT"

# ----------------------------------------------------------- 1. merge fixes
if [ "${SKIP_MERGE:-0}" != "1" ]; then
  for n in 48 49; do
    state="$(gh pr view "$n" --repo "$REPO" --json state --jq .state)"
    if [ "$state" = "MERGED" ]; then
      ok "PR #$n already merged"
      continue
    fi
    say "Merging PR #$n"
    checks="$(gh pr checks "$n" --repo "$REPO" --json state \
      --jq 'if all(.state=="SUCCESS") then "green" else "notgreen" end' 2>/dev/null || echo notgreen)"
    [ "$checks" = "green" ] || die "PR #$n checks are not green; refusing to merge"
    gh pr merge "$n" --repo "$REPO" --merge || die "merge of #$n failed"
    ok "merged #$n"
  done
fi

# ------------------------------------------------------ 2. sync working tree
say "Syncing main"
git checkout main -q
git pull -q origin main
ok "main = $(git rev-parse --short HEAD)"

# The NETWORK_MODE override lives in #48; if it has not landed, recover it from
# the stash so the dispatcher below understands NETWORK_MODE.
if ! grep -q 'NETWORK_MODE' scripts/operator/deployment-preflight/dispatch-staging-finalize.sh; then
  warn "dispatcher lacks NETWORK_MODE; restoring from stash"
  git stash pop || die "could not restore the dispatcher change; check: git stash list"
fi
ok "dispatcher supports NETWORK_MODE"

# -------------------------------------------------------------- 3. dispatch
say "Dispatching staging / private / workloads"
out="$(NETWORK_MODE=private PHASE=workloads bash scripts/operator/deployment-preflight/dispatch-staging-finalize.sh)"
echo "$out"
RUN_ID="$(printf '%s' "$out" | grep -oE 'actions/runs/[0-9]+' | head -n1 | grep -oE '[0-9]+')"
[ -n "$RUN_ID" ] || die "could not determine the dispatched run id"
ok "run $RUN_ID -> https://github.com/$REPO/actions/runs/$RUN_ID"

# ---------------------------------------------------- 4. wait for the gate
say "Waiting for qualification to reach the approval gate"
for _ in $(seq 1 60); do
  st="$(gh run view "$RUN_ID" --repo "$REPO" --json status --jq .status 2>/dev/null || echo unknown)"
  case "$st" in
    waiting)   ok "run is at the staging approval gate"; break;;
    completed) die "run finished before the gate; see https://github.com/$REPO/actions/runs/$RUN_ID";;
  esac
  sleep 20
done
[ "$(gh run view "$RUN_ID" --repo "$REPO" --json status --jq .status)" = "waiting" ] \
  || die "run did not reach the approval gate in time"

# ------------------------------------------------------------- 5. approve
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
say "Approving"
gh api --method POST "/repos/$REPO/actions/runs/$RUN_ID/pending_deployments" \
  -F "environment_ids[]=$ENV_ID" -f state=approved -f comment='workloads private' >/dev/null \
  || die "approval failed"
ok "approved"

# -------------------------------------------------------------- 6. follow
say "Following the run (this phase takes ~20-40 min on the VNet runner)"
prev=""
while :; do
  j="$(gh run view "$RUN_ID" --repo "$REPO" --json status,conclusion,jobs 2>/dev/null)" || { sleep 20; continue; }
  cur="$(printf '%s' "$j" | jq -r '.jobs[] | select(.name|test("Deploy reviewed Azure phase")) | .steps[] | select(.conclusion != null and .conclusion != "" and .conclusion != "skipped") | "\(.conclusion|ascii_upcase)\t\(.name)"')"
  comm -13 <(printf '%s\n' "$prev") <(printf '%s\n' "$cur") | grep -v '^$' || true
  prev="$cur"
  st="$(printf '%s' "$j" | jq -r '.status')"
  if [ "$st" = "completed" ]; then
    concl="$(printf '%s' "$j" | jq -r '.conclusion')"
    echo
    if [ "$concl" = "success" ]; then
      ok "workloads COMPLETED: $concl"
    else
      warn "workloads finished: $concl"
      echo "     failed step log:"
      echo "       gh run view $RUN_ID --repo $REPO --log-failed | tail -40"
    fi
    break
  fi
  sleep 20
done

echo
say "Verify what landed:"
echo "  az containerapp list -g rg-kp-staging --query \"[].{name:name,running:properties.runningStatus}\" -o table"
echo "  az network private-endpoint list -g rg-kp-staging --query \"[].name\" -o tsv"
