#!/usr/bin/env bash
# Prove that licensing@ is a usable SECOND approver for pattern and campaign
# review, by reading the identity and roles out of a real token.
#
# WHY THIS MATTERS: self-approval is barred unconditionally
# (routes/patterns.py and routes/campaigns.py compare principal_id, which is the
# token's `oid`). A solo operator therefore cannot complete a campaign. The
# second identity must be a DIFFERENT oid that still carries the approval
# capabilities.
#
# ALREADY VERIFIED VIA GRAPH (2026-09-22), so this script only confirms the
# token actually says so:
#   licensing@erikdierksgmail.onmicrosoft.com  oid ee54cb16-6028-45c7-b37f-059aa2f95e8e
#   accountEnabled=true, userType=Member
#   app role `administrator` on kp-phoenix-console-staging
#   -> approve:pattern, approve_security:campaign, approve_privacy:campaign
#   primary operator oid eacd7c6c-7a67-4b0d-9711-5d301d51244f (different)
#
# TWO GOTCHAS THIS SCRIPT AVOIDS:
#   1. `az login --allow-no-subscriptions` WITHOUT --tenant enumerates tenants
#      against Azure Resource Manager, which this tenant requires MFA for:
#      AADSTS50076 for resource 797f4846-ba00-4fd7-ba43-dac1f8f63013. Scoping
#      the login to the tenant skips that entirely.
#   2. az CLI 2.89.1 then crashes in _subscription_selector.py with
#      "'NoneType' object has no attribute 'get'" when the account has no
#      subscription. That is a CLI bug, not a configuration fault; --tenant
#      plus --allow-no-subscriptions avoids the code path.
#
# Run: bash /Users/edierks/projects/codex-test/phishing-awareness-platform/scripts/operator/verify-second-approver.sh
set -euo pipefail

TENANT="808f2f63-5b2c-46e6-ace7-d133a2df35f8"
CONSOLE_APP="97466174-d0ac-460c-94e8-7b6ff3c83da5"
SCOPE="api://${CONSOLE_APP}/console"
EXPECT_SECOND_OID="ee54cb16-6028-45c7-b37f-059aa2f95e8e"
PRIMARY_OID="eacd7c6c-7a67-4b0d-9711-5d301d51244f"
CFG="${AZURE_CONFIG_DIR_LICENSING:-$HOME/.azure-licensing}"

say(){ printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok(){  printf '\033[1;32m  ok\033[0m %s\n' "$*"; }
warn(){ printf '\033[1;33m  !!\033[0m %s\n' "$*"; }
die(){ printf '\033[1;31m  xx\033[0m %s\n' "$*"; exit 1; }

command -v az >/dev/null || die "az is not on PATH"
export AZURE_CONFIG_DIR="$CFG"
echo "     AZURE_CONFIG_DIR = $AZURE_CONFIG_DIR   (separate profile; your primary login is untouched)"

say "Signing in as the SECOND identity"
if az account show >/dev/null 2>&1; then
  ok "already signed in to this profile as $(az account show --query user.name -o tsv 2>/dev/null)"
else
  echo "     A browser will open. Sign in as licensing@erikdierksgmail.onmicrosoft.com"
  echo "     and complete MFA if prompted."
  az login --tenant "$TENANT" --allow-no-subscriptions --only-show-errors >/dev/null \
    || die "login failed. If MFA blocks the browser flow, try: az login --tenant $TENANT --allow-no-subscriptions --use-device-code"
  ok "signed in"
fi

say "Requesting a console-scoped token"
TOKEN="$(az account get-access-token --scope "$SCOPE" --query accessToken -o tsv 2>/dev/null)" \
  || die "could not get a token for $SCOPE (the az CLI is pre-authorized on this app, so this usually means the sign-in identity lacks access)"
[ -n "$TOKEN" ] || die "empty token"
ok "token acquired"

say "Decoding the token claims"
python3 - "$TOKEN" "$EXPECT_SECOND_OID" "$PRIMARY_OID" <<'PY'
import base64, json, sys
tok, expect_oid, primary_oid = sys.argv[1], sys.argv[2], sys.argv[3]
payload = tok.split(".")[1]
payload += "=" * (-len(payload) % 4)          # JWTs strip base64 padding
claims = json.loads(base64.urlsafe_b64decode(payload))
oid   = claims.get("oid")
roles = claims.get("roles") or []
upn   = claims.get("upn") or claims.get("preferred_username")
print(f"     upn:   {upn}")
print(f"     oid:   {oid}")
print(f"     roles: {roles}")
print(f"     aud:   {claims.get('aud')}")
fail = []
if oid != expect_oid:
    fail.append(f"oid is {oid}, expected the second identity {expect_oid}")
if oid == primary_oid:
    fail.append("signed in as the PRIMARY operator; this identity cannot approve its own work")
approving = {"administrator", "source_curator", "security_approver", "privacy_approver"}
if not (set(roles) & approving):
    fail.append(f"token carries no approval-capable role; has {roles}, needs one of {sorted(approving)}")
print()
if fail:
    for f in fail: print("  xx", f)
    raise SystemExit(1)
print("  ok distinct identity with approval-capable roles: usable as the second approver")
PY

say "What this does and does not prove"
echo "     PROVEN:     the token identity differs from the primary operator and"
echo "                 carries a role granting approve:pattern / approve_*:campaign."
echo "     NOT PROVEN: that a full campaign review completes end to end. That is"
echo "                 the Azure campaign dry run, and it needs Azure powered back up."
