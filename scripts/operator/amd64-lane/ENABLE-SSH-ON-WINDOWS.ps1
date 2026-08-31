# AMD64 lane - enable SSH access to the Windows build host (192.168.1.36).
#
# RUN THIS ON THE WINDOWS PC AT 192.168.1.36.
# Right-click the Start button -> "Terminal (Admin)" or "Windows PowerShell (Admin)",
# then paste this whole file in and press Enter.
#
# It installs Microsoft's OpenSSH Server, starts it, opens ONLY port 22 to the
# local network, and authorises the Mac's public key. It does not disable the
# firewall and does not open anything to the internet.

Write-Host "== 1. Installing OpenSSH Server ==" -ForegroundColor Cyan
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

Write-Host "== 2. Starting sshd and enabling it at boot ==" -ForegroundColor Cyan
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic

Write-Host "== 3. Allowing TCP 22 from the local network only ==" -ForegroundColor Cyan
New-NetFirewallRule -Name "KP-SSH-22" -DisplayName "KP AMD64 lane SSH (22)" `
  -Enabled True -Direction Inbound -Protocol TCP -LocalPort 22 `
  -Action Allow -RemoteAddress 192.168.1.0/24 -ErrorAction SilentlyContinue

Write-Host "== 4. Authorising the Mac's public key ==" -ForegroundColor Cyan
$key = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIITBRwZIq1csp00CQLDsBOWPlPmr+3cuhO35dv+4L+AH edierks-mac-crow'
$dir = "$env:USERPROFILE\.ssh"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
Add-Content -Path "$dir\authorized_keys" -Value $key

# Windows requires admin-group users to use this file instead:
$admin = "$env:ProgramData\ssh\administrators_authorized_keys"
Add-Content -Path $admin -Value $key
icacls $admin /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F" | Out-Null

Write-Host ""
Write-Host "== DONE. Report these two lines back ==" -ForegroundColor Green
Write-Host "USERNAME: $env:USERNAME"
(Get-Service sshd).Status
Get-NetIPAddress -AddressFamily IPv4 |
  Where-Object { $_.IPAddress -like '192.168.*' } |
  Select-Object -ExpandProperty IPAddress
