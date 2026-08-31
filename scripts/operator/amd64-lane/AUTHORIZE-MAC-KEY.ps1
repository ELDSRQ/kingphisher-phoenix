# AMD64 lane - authorise the Mac's SSH key on the Windows host 192.168.1.36.
#
# RUN THIS ON THE WINDOWS PC AT 192.168.1.36, in an ADMIN terminal:
#   Right-click the Start button -> "Terminal (Admin)"
#
# OpenSSH Server is already installed and running on that box; this only adds
# the key so the Mac can log in without a password. Windows checks a different
# file for administrator accounts, which is why both are written.

$key = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIITBRwZIq1csp00CQLDsBOWPlPmr+3cuhO35dv+4L+AH edierks-mac-crow'

New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.ssh" | Out-Null
Add-Content -Path "$env:USERPROFILE\.ssh\authorized_keys" -Value $key

$admin = "$env:ProgramData\ssh\administrators_authorized_keys"
Add-Content -Path $admin -Value $key
icacls $admin /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F" | Out-Null

Restart-Service sshd
Write-Host "key authorised for $env:USERNAME"
