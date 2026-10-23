#!/usr/bin/env bash
# provision-recipients.sh
# Creates ONLY the two floridamanevolved.com recipient mailboxes that forward a
# simulated email out to your Gmail/Proton. Exchange-admin only: NO license and
# NO Security-Defaults change required (sending is handled separately via Gmail
# SMTP). One Exchange Online sign-in.
#
#   Run:  bash scripts/operator/provision-recipients.sh
#
# Creates (idempotent):
#   phish-test-gmail@floridamanevolved.com  (shared) -> erik.dierks@gmail.com
#   phish-test-proton@floridamanevolved.com (shared) -> eldsrq@proton.me
# and turns on admin auto-forwarding (external auto-forward is blocked by default).
set -euo pipefail

if ! command -v pwsh >/dev/null 2>&1; then
  echo "pwsh (PowerShell 7) not found. Install it with:" >&2
  echo "    brew install --cask powershell" >&2
  exit 1
fi

OUT_DIR="${HOME}/.kp-sending"
mkdir -p "$OUT_DIR"
PS1_FILE="${OUT_DIR}/provision-recipients.ps1"

cat > "$PS1_FILE" <<'PWSH'
#Requires -Version 7
$ErrorActionPreference = 'Stop'

$Domain         = 'floridamanevolved.com'
$RcptGmailAddr  = "phish-test-gmail@$Domain"
$RcptGmailFwd   = 'erik.dierks@gmail.com'
$RcptProtonAddr = "phish-test-proton@$Domain"
$RcptProtonFwd  = 'eldsrq@proton.me'

Write-Host "== Ensuring ExchangeOnlineManagement module ==" -ForegroundColor Cyan
if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
  Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber
}
Import-Module ExchangeOnlineManagement

Write-Host "`n== Connecting to Exchange Online - sign in as an Exchange admin ==" -ForegroundColor Cyan
Connect-ExchangeOnline -ShowBanner:$false

function Ensure-ForwardingMailbox($addr,$name,$fwd) {
  if (-not (Get-Mailbox -Identity $addr -ErrorAction SilentlyContinue)) {
    Write-Host "Creating shared mailbox $addr ..."
    New-Mailbox -Shared -Name $name -DisplayName $name -PrimarySmtpAddress $addr | Out-Null
    for ($i=0; $i -lt 20; $i++) { if (Get-Mailbox -Identity $addr -ErrorAction SilentlyContinue) { break }; Start-Sleep -Seconds 15 }
  } else { Write-Host "Shared mailbox $addr exists." }
  Write-Host "Setting $addr to forward to $fwd ..."
  Set-Mailbox -Identity $addr -ForwardingSmtpAddress $fwd -DeliverToMailboxAndForward $false
}
Ensure-ForwardingMailbox $RcptGmailAddr  'KP Phish Test (Gmail)'  $RcptGmailFwd
Ensure-ForwardingMailbox $RcptProtonAddr 'KP Phish Test (Proton)' $RcptProtonFwd

Write-Host "Enabling admin auto-forwarding on the Default outbound spam policy ..."
Set-HostedOutboundSpamFilterPolicy -Identity 'Default' -AutoForwardingMode On

Write-Host "`n================= CAMPAIGN RECIPIENTS =================" -ForegroundColor Green
Write-Host "RECIPIENT_GMAIL  = $RcptGmailAddr   (-> $RcptGmailFwd)"
Write-Host "RECIPIENT_PROTON = $RcptProtonAddr   (-> $RcptProtonFwd)"
Write-Host "======================================================" -ForegroundColor Green
Write-Host "Verifying forwarding is set:"
Get-Mailbox $RcptGmailAddr,$RcptProtonAddr | Format-Table PrimarySmtpAddress,ForwardingSmtpAddress,DeliverToMailboxAndForward -Auto

Disconnect-ExchangeOnline -Confirm:$false | Out-Null
PWSH

echo "Running recipient provisioning via pwsh (you'll sign in once, to Exchange Online)..."
pwsh -NoProfile -File "$PS1_FILE"
echo
echo "Done. Both floridamanevolved.com recipients now forward to your Gmail/Proton."
