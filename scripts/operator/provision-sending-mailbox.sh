#!/usr/bin/env bash
# provision-sending-mailbox.sh
# ONE command to provision a Kingphisher-Phoenix EXTERNAL SMTP SENDER + the two
# forwarding recipients that deliver a simulated email to your Gmail/Proton.
# It writes a PowerShell script and runs it with pwsh 7. You sign in twice
# (Microsoft Graph, then Exchange Online) as a Global/Exchange admin; everything
# else is automatic. Requires Azure/M365 online.
#
#   Run:  bash scripts/operator/provision-sending-mailbox.sh
#
# Graph work uses Invoke-MgGraphRequest (raw REST) so it needs ONLY the
# Microsoft.Graph.Authentication module — avoiding the "Authentication needed"
# version-mismatch between Microsoft.Graph sub-modules.
#
# What it does, in your tenant (erikdierksgmail.onmicrosoft.com):
#   0. Checks Entra "Security Defaults" (if ON, SMTP AUTH is blocked tenant-wide;
#      it warns but does NOT change this for you).
#   1. Creates the sending mailbox security@floridamanevolved.com (licensed user,
#      known password), enabling per-mailbox SMTP client auth.
#   2. Creates two shared (unlicensed) recipient mailboxes that forward externally:
#        phish-test-gmail@floridamanevolved.com  -> erik.dierks@gmail.com
#        phish-test-proton@floridamanevolved.com -> eldsrq@proton.me
#   3. Turns on admin auto-forwarding (Default outbound spam policy).
#   4. Prints + saves the exact .105 SMTP env and the recipient addresses.
set -euo pipefail

if ! command -v pwsh >/dev/null 2>&1; then
  echo "pwsh (PowerShell 7) not found. Install it with:" >&2
  echo "    brew install --cask powershell" >&2
  exit 1
fi

OUT_DIR="${HOME}/.kp-sending"
mkdir -p "$OUT_DIR"
PS1_FILE="${OUT_DIR}/provision-sending-mailbox.ps1"
CONFIG_OUT="${OUT_DIR}/sending-config.txt"

cat > "$PS1_FILE" <<'PWSH'
#Requires -Version 7
$ErrorActionPreference = 'Stop'

# --- Fixed, real values for THIS tenant (verified; nothing to look up) ------
$TenantId      = '808f2f63-5b2c-46e6-ace7-d133a2df35f8'   # erikdierksgmail.onmicrosoft.com
$Graph         = 'https://graph.microsoft.com/v1.0'
$Domain        = 'floridamanevolved.com'
$SenderAddr    = "security@$Domain"
$SenderName    = 'Security Awareness'
$SenderNick    = 'security'
$RcptGmailAddr = "phish-test-gmail@$Domain"
$RcptGmailFwd  = 'erik.dierks@gmail.com'
$RcptProtonAddr= "phish-test-proton@$Domain"
$RcptProtonFwd = 'eldsrq@proton.me'
$UsageLocation = 'US'
$ConfigOut     = $env:KP_SENDING_CONFIG_OUT

function New-StrongPassword {
  $upper='ABCDEFGHJKLMNPQRSTUVWXYZ'; $lower='abcdefghijkmnpqrstuvwxyz'
  $digit='23456789'; $sym='!@#$%^*-_=+'; $all="$upper$lower$digit$sym"
  $rng=[System.Security.Cryptography.RandomNumberGenerator]::Create()
  function pick($set){ $b=[byte[]]::new(1); $rng.GetBytes($b); $set[[int]($b[0]) % $set.Length] }
  $chars=@(pick $upper; pick $lower; pick $digit; pick $sym)
  for($i=0;$i -lt 16;$i++){ $chars+=pick $all }
  -join ($chars | Sort-Object { Get-Random })
}
function GraphGET($u){ Invoke-MgGraphRequest -Method GET -Uri $u -OutputType PSObject }
function GraphReq($method,$u,$obj){
  Invoke-MgGraphRequest -Method $method -Uri $u -Body ($obj | ConvertTo-Json -Depth 8) -ContentType 'application/json' -OutputType PSObject
}

Write-Host "== Ensuring PowerShell modules ==" -ForegroundColor Cyan
foreach ($m in 'Microsoft.Graph.Authentication','ExchangeOnlineManagement') {
  if (-not (Get-Module -ListAvailable -Name $m)) {
    Write-Host "Installing $m (CurrentUser)..."
    Install-Module $m -Scope CurrentUser -Force -AllowClobber
  }
  Import-Module $m
}

Write-Host "`n== Connecting to Microsoft Graph - sign in as a Global admin ==" -ForegroundColor Cyan
Connect-MgGraph -TenantId $TenantId -NoWelcome `
  -Scopes 'User.ReadWrite.All','Organization.Read.All','Policy.Read.All','Directory.Read.All'

# --- 0. Preflight: Security Defaults (blocks SMTP AUTH if ON) ---------------
$SmtpBlocked = $false
try {
  $sd = GraphGET "$Graph/policies/identitySecurityDefaultsEnforcementPolicy"
  if ($sd.isEnabled) { $SmtpBlocked = $true }
} catch { Write-Host "(could not read Security Defaults policy: $_)" -ForegroundColor Yellow }
if ($SmtpBlocked) {
  Write-Host "`n*** WARNING: Entra Security Defaults are ENABLED -> SMTP AUTH is blocked tenant-wide. ***" -ForegroundColor Yellow
  Write-Host "    The sender will NOT authenticate until you disable them (Entra admin center >" -ForegroundColor Yellow
  Write-Host "    Properties > Manage security defaults > Disabled) or switch to Azure Communication Services." -ForegroundColor Yellow
  Write-Host "    This script still provisions everything so a later toggle is enough." -ForegroundColor Yellow
} else {
  Write-Host "Security Defaults: OFF (SMTP AUTH is not blocked at the tenant level)." -ForegroundColor Green
}

# --- 1. Sending user mailbox (create or reuse) + license -------------------
$SenderPassword = New-StrongPassword
$userId = $null
try { $u = GraphGET "$Graph/users/$SenderAddr"; $userId = $u.id } catch { $userId = $null }
if (-not $userId) {
  Write-Host "`nCreating user $SenderAddr ..."
  $body = @{
    accountEnabled=$true; displayName=$SenderName; mailNickname=$SenderNick;
    userPrincipalName=$SenderAddr; usageLocation=$UsageLocation;
    passwordProfile=@{ password=$SenderPassword; forceChangePasswordNextSignIn=$false }
  }
  $u = GraphReq POST "$Graph/users" $body
  $userId = $u.id
  Write-Host "Created user object id: $userId"
} else {
  Write-Host "`nUser $SenderAddr exists (id $userId). Resetting password for a known SMTP credential..." -ForegroundColor Yellow
  GraphReq PATCH "$Graph/users/$userId" @{ usageLocation=$UsageLocation; passwordProfile=@{ password=$SenderPassword; forceChangePasswordNextSignIn=$false } } | Out-Null
}

# Assign the first subscribed SKU that has free units AND includes ANY Exchange
# Online plan (service plan name starts with EXCHANGE_S_).
function Has-ExoPlan($plans){ @($plans | Where-Object { $_.servicePlanName -like 'EXCHANGE_S_*' }).Count -gt 0 }
$hasExo = $false
try {
  $det = GraphGET "$Graph/users/$userId/licenseDetails"
  foreach ($l in $det.value) { if (Has-ExoPlan $l.servicePlans) { $hasExo = $true } }
} catch {}
if (-not $hasExo) {
  $skus = (GraphGET "$Graph/subscribedSkus").value
  $sku = $skus | Where-Object { (($_.prepaidUnits.enabled - $_.consumedUnits) -gt 0) -and (Has-ExoPlan $_.servicePlans) } | Select-Object -First 1
  if (-not $sku) {
    Write-Host "*** No available license with Exchange Online found. Free/allocate one for $SenderAddr" -ForegroundColor Red
    Write-Host "    in the M365 admin center, then re-run (idempotent)." -ForegroundColor Red
    throw "no_available_exchange_license"
  }
  Write-Host "Assigning license $($sku.skuPartNumber) ..."
  GraphReq POST "$Graph/users/$userId/assignLicense" @{ addLicenses=@(@{ skuId=$sku.skuId }); removeLicenses=@() } | Out-Null
} else { Write-Host "User already has an Exchange Online license." }

# --- 2. Exchange Online -----------------------------------------------------
Write-Host "`n== Connecting to Exchange Online - sign in as an Exchange admin ==" -ForegroundColor Cyan
Connect-ExchangeOnline -ShowBanner:$false

Write-Host "Waiting for the sender mailbox to provision (can take a few minutes)..."
$mbx = $null
for ($i=0; $i -lt 30; $i++) {
  $mbx = Get-Mailbox -Identity $SenderAddr -ErrorAction SilentlyContinue
  if ($mbx) { break }
  Start-Sleep -Seconds 20
}
if (-not $mbx) {
  Write-Host "*** Sender mailbox not provisioned yet (can take ~15 min after licensing). Re-run later." -ForegroundColor Red
  throw "sender_mailbox_not_ready"
}
Write-Host "Enabling per-mailbox SMTP client authentication on $SenderAddr ..."
Set-CASMailbox -Identity $SenderAddr -SmtpClientAuthenticationDisabled $false

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

# --- 3. Print + save the exact .105 SMTP env + recipient addresses ----------
$lines = @(
  "# ---- paste into .105 .env (then restart kp-supervisor) ----"
  "KP_WORKER_EMAIL_PROVIDER=smtp"
  "KP_WORKER_SMTP_ADDRESS=smtp.office365.com:587"
  "KP_WORKER_SMTP_USERNAME=$SenderAddr"
  "KP_WORKER_SMTP_PASSWORD=$SenderPassword"
  "KP_WORKER_SMTP_STARTTLS=true"
  "KP_WORKER_SMTP_SSL=false"
  "KP_WORKER_SMTP_SENDER=$SenderAddr"
  "# ---- campaign recipients (RoE domain = $Domain; these forward out) ----"
  "RECIPIENT_GMAIL=$RcptGmailAddr   (-> $RcptGmailFwd)"
  "RECIPIENT_PROTON=$RcptProtonAddr   (-> $RcptProtonFwd)"
  "SECURITY_DEFAULTS_BLOCK_SMTP=$SmtpBlocked"
)
Write-Host "`n================= SENDING-MAILBOX CONFIG =================" -ForegroundColor Green
$lines | ForEach-Object { Write-Host $_ }
Write-Host "==========================================================" -ForegroundColor Green
if ($ConfigOut) {
  $lines | Set-Content -Path $ConfigOut
  Write-Host "Saved to $ConfigOut (contains the PASSWORD - treat as a secret)."
}
if ($SmtpBlocked) {
  Write-Host "`nREMINDER: Security Defaults are ON -> SMTP AUTH will fail until you disable them (or use ACS)." -ForegroundColor Yellow
}
Write-Host "`nSend me the USERNAME + recipient addresses (NOT the password); I'll wire .105 and run the send."

Disconnect-ExchangeOnline -Confirm:$false | Out-Null
Disconnect-MgGraph | Out-Null
PWSH

echo "Running provisioning via pwsh (you'll be prompted to sign in twice)..."
KP_SENDING_CONFIG_OUT="$CONFIG_OUT" pwsh -NoProfile -File "$PS1_FILE"
echo
echo "Done. Sending config written to: $CONFIG_OUT"
echo "That file contains the sender PASSWORD - keep it safe; delete it once .105 is wired."
