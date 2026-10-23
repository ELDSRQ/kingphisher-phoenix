#!/usr/bin/env bash
# provision-reply-mailbox.sh
# ONE command to provision Kingphisher-Phoenix reply ingestion end to end.
# It writes the PowerShell provisioning script and runs it with pwsh 7. You only
# sign in twice (Graph, then Exchange Online) as an Application + Exchange admin;
# everything else is automatic. Requires Azure/M365 online.
#
#   Run:  bash scripts/operator/provision-reply-mailbox.sh
#
set -euo pipefail

if ! command -v pwsh >/dev/null 2>&1; then
  echo "pwsh (PowerShell 7) not found. Install it with:" >&2
  echo "    brew install --cask powershell" >&2
  exit 1
fi

OUT_DIR="${HOME}/.kp-reply-ingestion"
mkdir -p "$OUT_DIR"
PS1_FILE="${OUT_DIR}/provision-reply-mailbox.ps1"
CONFIG_OUT="${OUT_DIR}/worker-config.txt"

cat > "$PS1_FILE" <<'PWSH'
#Requires -Version 7
$ErrorActionPreference = 'Stop'

# --- Fixed, real values for THIS tenant (verified; nothing to look up) ------
$TenantId       = '808f2f63-5b2c-46e6-ace7-d133a2df35f8'   # erikdierksgmail.onmicrosoft.com
$AppName        = 'kp-phoenix-graph-mail-staging'
$MailboxAddr    = 'sim-replies@floridamanevolved.com'
$MailboxName    = 'KP Simulation Replies'
$ScopeGroup     = 'kp-sim-reply-scope@floridamanevolved.com'
$ScopeGroupName = 'KP Sim Reply Scope'
$GraphAppId     = '00000003-0000-0000-c000-000000000000'   # Microsoft Graph (well-known)
$ConfigOut      = $env:KP_REPLY_CONFIG_OUT

Write-Host "== Ensuring PowerShell modules ==" -ForegroundColor Cyan
foreach ($m in 'Microsoft.Graph.Authentication','Microsoft.Graph.Applications','ExchangeOnlineManagement') {
  if (-not (Get-Module -ListAvailable -Name $m)) {
    Write-Host "Installing $m (CurrentUser)..."
    Install-Module $m -Scope CurrentUser -Force -AllowClobber
  }
  Import-Module $m
}

Write-Host "`n== Connecting to Microsoft Graph - sign in as an Application/Global admin ==" -ForegroundColor Cyan
Connect-MgGraph -TenantId $TenantId -NoWelcome `
  -Scopes 'Application.ReadWrite.All','AppRoleAssignment.ReadWrite.All','Directory.Read.All'

# --- 1. App registration (create or reuse) ---------------------------------
$app = Get-MgApplication -Filter "displayName eq '$AppName'" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $app) {
  Write-Host "Creating app registration '$AppName'..."
  $app = New-MgApplication -DisplayName $AppName -SignInAudience 'AzureADMyOrg'
}
$appId = $app.AppId
Write-Host "App (client) id: $appId"

$sp = Get-MgServicePrincipal -Filter "appId eq '$appId'" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $sp) { $sp = New-MgServicePrincipal -AppId $appId }

# --- 2. Client secret (fresh each run) -------------------------------------
$secret = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{
  displayName = "reply-ingestion $(Get-Date -Format o)"
  endDateTime = (Get-Date).AddYears(2)
}
$clientSecret = $secret.SecretText

# --- 3. Grant Microsoft Graph Mail.Read (application) + admin consent -------
$graphSp  = Get-MgServicePrincipal -Filter "appId eq '$GraphAppId'" | Select-Object -First 1
$mailRead = ($graphSp.AppRoles | Where-Object { $_.Value -eq 'Mail.Read' -and $_.AllowedMemberTypes -contains 'Application' }).Id
$already  = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue |
            Where-Object { $_.AppRoleId -eq $mailRead -and $_.ResourceId -eq $graphSp.Id }
if (-not $already) {
  New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -PrincipalId $sp.Id `
    -ResourceId $graphSp.Id -AppRoleId $mailRead | Out-Null
  Write-Host "Granted Microsoft Graph Mail.Read (application) with admin consent."
} else { Write-Host "Mail.Read already granted." }

# --- 4. Exchange Online: mailbox + scope group + access policy -------------
Write-Host "`n== Connecting to Exchange Online - sign in as an Exchange admin ==" -ForegroundColor Cyan
Connect-ExchangeOnline -ShowBanner:$false

if (-not (Get-Mailbox -Identity $MailboxAddr -ErrorAction SilentlyContinue)) {
  Write-Host "Creating shared mailbox $MailboxAddr..."
  New-Mailbox -Shared -Name $MailboxName -DisplayName $MailboxName -PrimarySmtpAddress $MailboxAddr | Out-Null
} else { Write-Host "Mailbox $MailboxAddr exists." }

if (-not (Get-DistributionGroup -Identity $ScopeGroup -ErrorAction SilentlyContinue)) {
  Write-Host "Creating mail-enabled security group $ScopeGroup..."
  New-DistributionGroup -Name $ScopeGroupName -PrimarySmtpAddress $ScopeGroup -Type Security | Out-Null
  Start-Sleep -Seconds 10
}
try {
  Add-DistributionGroupMember -Identity $ScopeGroup -Member $MailboxAddr -ErrorAction Stop
  Write-Host "Added $MailboxAddr to $ScopeGroup."
} catch { if ("$_" -notmatch 'already a member') { throw }; Write-Host "$MailboxAddr already in $ScopeGroup." }

if (-not (Get-ApplicationAccessPolicy -ErrorAction SilentlyContinue | Where-Object { $_.AppId -eq $appId })) {
  Write-Host "Creating Application Access Policy (restrict app to the scope group)..."
  New-ApplicationAccessPolicy -AppId $appId -PolicyScopeGroupId $ScopeGroup -AccessRight RestrictAccess `
    -Description "KP reply-ingestion: Graph app reads only $MailboxAddr" | Out-Null
} else { Write-Host "Application Access Policy for this app already exists." }

Write-Host "`nVerifying the policy (EXO can take up to ~30 min to fully enforce)..." -ForegroundColor Cyan
Test-ApplicationAccessPolicy -Identity $MailboxAddr -AppId $appId | Format-List AppId,Mailbox,AccessCheckResult

# --- 5. Print + save the exact worker wiring -------------------------------
$lines = @(
  "AZURE_GRAPH_TENANT_ID         = $TenantId"
  "KP_WORKER_GRAPH_CLIENT_ID     = $appId"
  "KP_WORKER_GRAPH_CLIENT_SECRET = $clientSecret"
  "KP_WORKER_GRAPH_MAILBOX       = $MailboxAddr"
)
Write-Host "`n================= REPLY-INGESTION WORKER CONFIG =================" -ForegroundColor Green
$lines | ForEach-Object { Write-Host $_ }
Write-Host "================================================================" -ForegroundColor Green
if ($ConfigOut) {
  $lines | Set-Content -Path $ConfigOut
  Write-Host "Saved to $ConfigOut (contains the SECRET - move it to Key Vault, then delete)."
}
Write-Host "Send me TENANT_ID, CLIENT_ID and MAILBOX (not the secret) and I'll wire the worker."

Disconnect-ExchangeOnline -Confirm:$false | Out-Null
Disconnect-MgGraph | Out-Null
PWSH

echo "Running provisioning via pwsh (you'll be prompted to sign in twice)..."
KP_REPLY_CONFIG_OUT="$CONFIG_OUT" pwsh -NoProfile -File "$PS1_FILE"
echo
echo "Done. Worker config written to: $CONFIG_OUT"
echo "That file contains the client secret - move it to Key Vault and delete it when done."
