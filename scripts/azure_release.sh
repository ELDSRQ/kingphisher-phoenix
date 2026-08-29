#!/usr/bin/env bash
# Start exactly one Azure migration execution, reconcile it, then qualify APIs.
# This script never deletes, resets, recreates, or prunes Azure/project state.
set -euo pipefail

export AZURE_LOGGING_ENABLE_LOG_FILE=false

COMMAND_TIMEOUT_SECONDS="${KP_AZURE_COMMAND_TIMEOUT_SECONDS:-60}"
RELEASE_TIMEOUT_SECONDS="${KP_AZURE_RELEASE_TIMEOUT_SECONDS:-900}"

fail() {
  printf 'error: %s\n' "$1" >&2
  printf 'safe next action: %s\n' "$2" >&2
  exit 1
}

for variable_name in AZURE_RESOURCE_GROUP AZURE_MIGRATION_JOB AZURE_OPERATOR_URL AZURE_TRACKING_URL; do
  if [ -z "${!variable_name:-}" ]; then
    fail "required release configuration is incomplete" "set $variable_name through the deployment GUI and rerun preflight"
  fi
done

case "$COMMAND_TIMEOUT_SECONDS" in
  ''|*[!0-9]*) fail "Azure command timeout is invalid" "set KP_AZURE_COMMAND_TIMEOUT_SECONDS to an integer from 5 through 300" ;;
esac
[ "$COMMAND_TIMEOUT_SECONDS" -ge 5 ] && [ "$COMMAND_TIMEOUT_SECONDS" -le 300 ] || \
  fail "Azure command timeout is outside its safe range" "set KP_AZURE_COMMAND_TIMEOUT_SECONDS to an integer from 5 through 300"
case "$RELEASE_TIMEOUT_SECONDS" in
  ''|*[!0-9]*) fail "release timeout is invalid" "set KP_AZURE_RELEASE_TIMEOUT_SECONDS to an integer from 60 through 1800" ;;
esac
[ "$RELEASE_TIMEOUT_SECONDS" -ge 60 ] && [ "$RELEASE_TIMEOUT_SECONDS" -le 1800 ] || \
  fail "release timeout is outside its safe range" "set KP_AZURE_RELEASE_TIMEOUT_SECONDS to an integer from 60 through 1800"

[[ "$AZURE_RESOURCE_GROUP" =~ ^[A-Za-z0-9._()-]{1,90}$ ]] || \
  fail "Azure resource-group identifier is invalid" "correct the reviewed deployment configuration"
[[ "$AZURE_MIGRATION_JOB" =~ ^[A-Za-z0-9][A-Za-z0-9-]{0,62}$ ]] || \
  fail "Azure migration-job identifier is invalid" "correct the reviewed deployment configuration"

for command_name in az curl python3; do
  command -v "$command_name" >/dev/null 2>&1 || \
    fail "required release tooling is unavailable" "install $command_name without removing project assets, then rerun preflight"
done

if ! AZURE_OPERATOR_URL="$AZURE_OPERATOR_URL" AZURE_TRACKING_URL="$AZURE_TRACKING_URL" python3 <<'PYURL'
import os
from urllib.parse import urlsplit

for name in ("AZURE_OPERATOR_URL", "AZURE_TRACKING_URL"):
    parsed = urlsplit(os.environ[name])
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise SystemExit(2)
PYURL
then
  fail "an API base URL is invalid" "provide a credential-free HTTPS origin through the deployment GUI"
fi

if [ -n "${DEPLOYMENT_REQUEST_ID:-}" ] \
  && ! [[ "$DEPLOYMENT_REQUEST_ID" =~ ^kp-[0-9a-f]{32}-[1-9][0-9]{0,2}$ ]]; then
  fail "deployment correlation identifier is invalid" "use the immutable deployment request identifier from the GUI"
fi

bounded() {
  python3 - "$COMMAND_TIMEOUT_SECONDS" "$@" <<'PYTIMEOUT'
import subprocess
import sys

try:
    result = subprocess.run(sys.argv[2:], timeout=int(sys.argv[1]), check=False)
except subprocess.TimeoutExpired:
    raise SystemExit(124) from None
raise SystemExit(result.returncode)
PYTIMEOUT
}

AZ_BIN="$(command -v az)"
az() { bounded "$AZ_BIN" "$@"; }

# A retry must first prove that no previous execution is still in an uncertain
# state. Starting another migration while one is active is not idempotent.
if ! active_executions="$(az containerapp job execution list \
    --resource-group "$AZURE_RESOURCE_GROUP" \
    --name "$AZURE_MIGRATION_JOB" \
    --query "[?properties.status!='Succeeded' && properties.status!='Failed' && properties.status!='Stopped' && properties.status!='Canceled'].name" \
    -o tsv 2>/dev/null)"; then
  fail "migration execution inventory could not be inspected" "inspect the exact job executions in Azure and reconcile their status before retrying"
fi
if (( ${#active_executions} > 4096 )); then
  fail "migration execution inventory was unexpectedly large" "inspect the exact job in Azure and reconcile it before retrying"
fi
if [ -n "$active_executions" ]; then
  fail "an earlier migration execution is still active or uncertain" "reconcile that execution in Azure; do not start a duplicate"
fi

if ! execution_name="$(az containerapp job start \
    --resource-group "$AZURE_RESOURCE_GROUP" \
    --name "$AZURE_MIGRATION_JOB" \
    --query name -o tsv 2>/dev/null)"; then
  fail "migration start did not return a confirmed execution" "inspect job executions in Azure before deciding whether a retry is safe"
fi
if ! [[ "$execution_name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]]; then
  fail "migration start returned an invalid execution identity" "inspect job executions in Azure before deciding whether a retry is safe"
fi
printf 'migration execution: %s\n' "$execution_name"
if [ -n "${DEPLOYMENT_REQUEST_ID:-}" ]; then
  printf 'deployment request: %s\n' "$DEPLOYMENT_REQUEST_ID"
fi

deadline=$((SECONDS + RELEASE_TIMEOUT_SECONDS))
status=""
while (( SECONDS < deadline )); do
  if ! status="$(az containerapp job execution show \
      --resource-group "$AZURE_RESOURCE_GROUP" \
      --name "$AZURE_MIGRATION_JOB" \
      --job-execution-name "$execution_name" \
      --query properties.status -o tsv 2>/dev/null)"; then
    fail "migration execution status became uncertain" "inspect the recorded execution in Azure before deciding whether a retry is safe"
  fi
  if (( ${#status} > 64 )); then
    fail "migration execution returned an invalid status" "inspect the recorded execution in Azure before deciding whether a retry is safe"
  fi
  case "$status" in
    Succeeded) break ;;
    Failed|Stopped|Canceled) fail "migration execution ended without success" "inspect the recorded execution logs and correct the cause before a reviewed retry" ;;
    Running|Processing|Pending|Starting|"") sleep 5 ;;
    *) fail "migration execution returned an unrecognized status" "inspect the recorded execution in Azure before deciding whether a retry is safe" ;;
  esac
done

[ "$status" = "Succeeded" ] || \
  fail "migration execution did not finish within the bounded release window" "inspect the recorded execution in Azure before deciding whether a retry is safe"

qualify_api() {
  local label="$1" url="$2"
  if ! curl --fail --silent --show-error \
      --connect-timeout 10 --max-time 30 \
      --retry 12 --retry-delay 5 --retry-max-time 180 --retry-all-errors \
      "${url%/}/readyz" >/dev/null; then
    fail "$label readiness was not confirmed" "inspect that API revision and its migration binding; do not replace persistent state"
  fi
}

qualify_api "operator API" "$AZURE_OPERATOR_URL"
qualify_api "tracking API" "$AZURE_TRACKING_URL"

echo "Azure release qualification passed."
