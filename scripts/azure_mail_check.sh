#!/usr/bin/env bash
#
# Post-deployment email verification.
#
# Deploying successfully does not mean mail works. The Azure Communication
# Services domain has to finish provisioning, the runtime identity has to hold
# the Email Sender role, and the sending address has to be one ACS will accept.
# Each of those fails silently at *send* time — the first campaign just reports
# failures — so this proves the path end to end before anyone schedules one.
#
# It sends exactly one message, to an address you supply, and tells you what
# actually left the building.
#
# Usage:
#   scripts/azure_mail_check.sh --resource-group <rg> --to <address> [--dry-run]
#
# Deliberately NOT wired into the deploy workflow: it sends real mail to a real
# person, which is a decision an operator makes, not something CI should do on
# every deploy.

set -euo pipefail

RESOURCE_GROUP=""
TO=""
DRY_RUN=0

die() { printf '\nerror: %s\n' "$*" >&2; exit 2; }
log() { printf '  %s\n' "$*"; }
step() { printf '\n== %s\n' "$1"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --resource-group) RESOURCE_GROUP="${2:-}"; shift 2 ;;
    --to)             TO="${2:-}"; shift 2 ;;
    --dry-run)        DRY_RUN=1; shift ;;
    -h|--help)        sed -n '2,20p' "$0"; exit 0 ;;
    *)                die "unknown argument: $1" ;;
  esac
done

[ -n "$RESOURCE_GROUP" ] || die "--resource-group is required"
[ -n "$TO" ] || die "--to is required (a mailbox you can read)"
# Deliberately strict: a glob like *@*.* also matches "@example.com", and this
# script sends real mail, so a malformed address must never reach the send.
case "$TO" in
  @*|*@|*" "*) die "--to does not look like an email address: $TO" ;;
  ?*@?*.?*) ;;
  *) die "--to does not look like an email address: $TO" ;;
esac

command -v az >/dev/null 2>&1 || die "the Azure CLI (az) is not installed"
az account show >/dev/null 2>&1 || die "not logged in to Azure; run: az login"

step "Locating the Communication Services resources"
ACS_NAME="$(az communication list --resource-group "$RESOURCE_GROUP" --query '[0].name' -o tsv 2>/dev/null || echo "")"
[ -n "$ACS_NAME" ] || die "no Communication Services resource found in $RESOURCE_GROUP"
log "communication service: $ACS_NAME"

EMAIL_SVC="$(az communication email list --resource-group "$RESOURCE_GROUP" --query '[0].name' -o tsv 2>/dev/null || echo "")"
[ -n "$EMAIL_SVC" ] || die "no Email Communication Service found in $RESOURCE_GROUP"
log "email service: $EMAIL_SVC"

step "Checking the sending domain"
DOMAIN_JSON="$(az communication email domain list \
  --resource-group "$RESOURCE_GROUP" --email-service-name "$EMAIL_SVC" -o json 2>/dev/null || echo '[]')"
FROM_DOMAIN="$(printf '%s' "$DOMAIN_JSON" | python3 -c '
import json, sys
rows = json.load(sys.stdin)
print(rows[0].get("fromSenderDomain", "") if rows else "")
')"
VERIFY_STATE="$(printf '%s' "$DOMAIN_JSON" | python3 -c '
import json, sys
rows = json.load(sys.stdin)
if not rows:
    print("")
else:
    states = rows[0].get("verificationStates") or {}
    print(states.get("domain", {}).get("status", "Unknown") if isinstance(states, dict) else "Unknown")
')"
[ -n "$FROM_DOMAIN" ] || die "the email domain has no sender domain yet; it may still be provisioning"
log "sender domain: $FROM_DOMAIN"
log "verification:  ${VERIFY_STATE:-Unknown}"

SENDER="DoNotReply@${FROM_DOMAIN}"
log "sending as:    $SENDER"

if [ "${VERIFY_STATE:-}" != "Verified" ] && [ -n "${VERIFY_STATE:-}" ] && [ "$VERIFY_STATE" != "Unknown" ]; then
  printf '\n  The domain is not Verified yet (%s). Azure-managed domains usually\n' "$VERIFY_STATE"
  printf '  verify within a few minutes of creation; a custom domain needs its DNS\n'
  printf '  records published first. Sending now will probably fail.\n'
fi

step "Sending one test message"
if [ "$DRY_RUN" -eq 1 ]; then
  log "[dry-run] would send from $SENDER to $TO via $ACS_NAME"
  printf '\nDry run complete. Nothing was sent.\n\n'
  exit 0
fi

CONNECTION_STRING="$(az communication list-key --name "$ACS_NAME" --resource-group "$RESOURCE_GROUP" \
  --query primaryConnectionString -o tsv 2>/dev/null || echo "")"
[ -n "$CONNECTION_STRING" ] || die "could not read the Communication Services connection string"

# Sent through the same SDK path the delivery worker uses, so a success here
# means the worker's transport works — not merely that some HTTP call did.
CONNECTION_STRING="$CONNECTION_STRING" SENDER="$SENDER" TO="$TO" python3 - <<'PYSEND'
import os
import sys

try:
    from azure.communication.email import EmailClient
except ImportError:
    sys.exit("azure-communication-email is not installed in this interpreter; run: uv sync --all-packages")

client = EmailClient.from_connection_string(os.environ["CONNECTION_STRING"])
message = {
    "senderAddress": os.environ["SENDER"],
    "recipients": {"to": [{"address": os.environ["TO"]}]},
    "content": {
        "subject": "KingPhisher-Phoenix delivery check",
        "plainText": (
            "This is an automated delivery check from your KingPhisher-Phoenix deployment.\n\n"
            "It confirms that Azure Communication Services email is provisioned, that the "
            "runtime can send, and which address simulations will arrive from.\n\n"
            "No campaign has been created or sent. Nothing is required of you."
        ),
    },
}
poller = client.begin_send(message)
result = poller.result()
status = getattr(result, "status", None) or (result.get("status") if isinstance(result, dict) else "unknown")
message_id = getattr(result, "id", None) or (result.get("id") if isinstance(result, dict) else "unknown")
print(f"  status:     {status}")
print(f"  message id: {message_id}")
if str(status).lower() not in {"succeeded", "success"}:
    sys.exit(f"send did not succeed: {status}")
PYSEND

cat <<SUMMARY

Mail path verified.

  from   $SENDER
  to     $TO

Check that mailbox, including its spam folder. Where the message lands tells you
what a simulation will do:

  Inbox        the path works end to end.
  Spam/Junk    expected for an Azure-managed domain — it has no reputation and
               you do not control its DNS. Fine for validating the pipeline,
               not for a real assessment. Move to a custom domain with SPF,
               DKIM and DMARC before running one.
  Nowhere      the send was accepted but not delivered. Check the recipient's
               gateway, and whether the destination blocks azurecomm.net.

SUMMARY
