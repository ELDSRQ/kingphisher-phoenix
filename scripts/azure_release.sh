#!/usr/bin/env bash
set -euo pipefail

: "${AZURE_RESOURCE_GROUP:?set AZURE_RESOURCE_GROUP}"
: "${AZURE_MIGRATION_JOB:?set AZURE_MIGRATION_JOB}"
: "${AZURE_OPERATOR_URL:?set AZURE_OPERATOR_URL}"
: "${AZURE_TRACKING_URL:?set AZURE_TRACKING_URL}"

execution_name="$(az containerapp job start \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --name "$AZURE_MIGRATION_JOB" \
  --query name -o tsv)"

for _ in $(seq 1 120); do
  status="$(az containerapp job execution show \
    --resource-group "$AZURE_RESOURCE_GROUP" \
    --name "$AZURE_MIGRATION_JOB" \
    --job-execution-name "$execution_name" \
    --query properties.status -o tsv)"
  case "$status" in
    Succeeded) break ;;
    Failed|Stopped) echo "Migration execution $execution_name ended with $status" >&2; exit 1 ;;
  esac
  sleep 5
done

test "${status:-}" = "Succeeded" || { echo "Migration timed out" >&2; exit 1; }
curl --fail --silent --show-error --retry 12 --retry-delay 5 "$AZURE_OPERATOR_URL/healthz"
curl --fail --silent --show-error --retry 12 --retry-delay 5 "$AZURE_TRACKING_URL/healthz"

echo "Azure release qualification passed."
