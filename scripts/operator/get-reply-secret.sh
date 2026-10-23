#!/usr/bin/env bash
# get-reply-secret.sh — pull the Graph client secret out of the provisioning
# output file, copy it to the clipboard, and (optionally) store it in Key Vault.
#
#   bash scripts/operator/get-reply-secret.sh         # extract + copy to clipboard
#   bash scripts/operator/get-reply-secret.sh --kv    # also push to Key Vault (needs VNet reach)
#   bash scripts/operator/get-reply-secret.sh --file /path/to/worker-config.txt
#
set -euo pipefail

FILE="${HOME}/.kp-reply-ingestion/worker-config.txt"
VAULT="kvkpstaging6117w"
SECRET_NAME="kp-worker-graph-client-secret"
DO_KV=0
while [ $# -gt 0 ]; do
  case "$1" in
    --kv) DO_KV=1; shift ;;
    --file) FILE="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[ -f "$FILE" ] || { echo "error: config file not found: $FILE" >&2; exit 1; }

SECRET="$(sed -n 's/^KP_WORKER_GRAPH_CLIENT_SECRET[[:space:]]*=[[:space:]]*//p' "$FILE" | head -n1)"
[ -n "$SECRET" ] || { echo "error: KP_WORKER_GRAPH_CLIENT_SECRET not found in $FILE" >&2; exit 1; }

# Copy to clipboard without echoing the secret to the terminal/scrollback.
if command -v pbcopy >/dev/null 2>&1; then
  printf '%s' "$SECRET" | pbcopy
  echo "Secret copied to clipboard (${#SECRET} chars; starts '${SECRET:0:3}', ends '${SECRET: -2}')."
else
  echo "pbcopy not available; secret NOT echoed. Read it from $FILE."
fi

if [ "$DO_KV" -eq 1 ]; then
  echo "Storing in Key Vault '$VAULT' as '$SECRET_NAME'..."
  if az keyvault secret set --vault-name "$VAULT" --name "$SECRET_NAME" --value "$SECRET" --only-show-errors >/dev/null 2>&1; then
    echo "Stored in Key Vault. You can now delete $FILE."
  else
    echo "Key Vault write failed (expected from the laptop: $VAULT is on a private endpoint)."
    echo "Run this from inside the VNet (the CI runner VM) when Azure is up:"
    echo "    az keyvault secret set --vault-name $VAULT --name $SECRET_NAME --value \"\$SECRET\""
  fi
else
  echo
  echo "Ready-to-run Key Vault command (works from inside the VNet):"
  echo "    az keyvault secret set --vault-name $VAULT --name $SECRET_NAME --value \"<clipboard>\""
  echo "Or re-run this script with --kv to attempt it now."
fi
