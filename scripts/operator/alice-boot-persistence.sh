#!/usr/bin/env bash
# alice-boot-persistence.sh — B1: make the on-prem aggregation model survive a
# reboot of Alice. Run this FROM THIS MAC; it does the SSH to Alice for you.
#
# WHY: WSL systemd `kp-aggregate.service` is enabled inside Ubuntu-24.04, but the
# Windows-side trigger that starts WSL was deleted during earlier clean-state
# work. Without it a reboot silently drops the A3B model and aggregation stops
# with no signal.
#
# THE TRIGGER MUST BE AN S4U TASK, NOT A LOGON TASK AND NOT SYSTEM. Measured on
# Alice 2026-09-25:
#   * `/SC ONLOGON` only fires when erikd logs in interactively. An unattended
#     reboot leaves the model down until someone sits at the console, which is
#     exactly the failure this script exists to prevent.
#   * `/RU SYSTEM` is not merely wrong, it is impossible. The task runs and
#     returns Last Result -1; the captured stderr is
#       Running WSL as local system is not supported.
#       Error code: Wsl/WSL_E_LOCAL_SYSTEM_NOT_SUPPORTED
#     No amount of task configuration works around that.
#   * S4U ("service for user") as alice\erikd runs at startup with no stored
#     password, no interactive logon and no MSA password prompt, and WSL starts
#     normally under it. Verified: task state Running, holder resident,
#     llama-server loaded in 9.1s, :18082 answering 200.
# schtasks.exe cannot express S4U (`/NP` still prompts for a password here), so
# the task is registered through PowerShell's Register-ScheduledTask with
# -LogonType S4U.
#
# WHAT IT DOES
#   1. proves Alice is reachable over SSH
#   2. reports whether the scheduled task already exists
#   3. creates it (skips if present unless FORCE=1)
#   4. verifies it now exists
#   5. optionally starts it and checks the model answers on :18082
#
# Alice is Windows: SSH lands in cmd.exe, so the remote commands are cmd syntax.
#
# The task must STAY RESIDENT, not just start the unit. kp-aggregate-start.sh
# runs llama-server in the foreground precisely so a live WSL session keeps it
# and the distro alive. A task that ran `systemctl start` and exited left
# nothing holding that session, so every wsl.exe invocation created a
# short-lived session whose teardown sent SIGINT to the foreground process
# group: llama-server logged 637 starts and 633 "Received second interrupt"
# deaths, each ~17-20s after a ~3.7s load. Holding one session open for 120s
# produced zero kills. /usr/local/bin/kp-hold-session.sh starts the unit and
# then sleeps forever; the sleep IS the fix.
#
# The task runs WSL as ROOT *inside* the distro (-u root) while the Windows-side
# principal is erikd; those are two different things and both matter. The command previously
# recorded in the readiness plan omitted `-u root` and invoked the start script
# directly; WSL's default user on Alice is `erikd`, who cannot execute a
# root-owned script in /root, so that task would have been created fine and
# then failed silently at every logon. `systemctl start` is also idempotent, so
# it is a no-op when WSL's systemd has already brought the unit up.
#
# Overrides:
#   ALICE=erikd@192.168.1.36      host (default shown)
#   SSH_KEY=~/.ssh/alice_dr_ed25519
#                                 identity to use (default shown; set SSH_KEY=""
#                                 to rely on ~/.ssh/config instead)
#   FORCE=1                       recreate the task even if it already exists
#   RUN_NOW=1                     run the task now and probe the model endpoint
#
# Run: bash /Users/edierks/projects/codex-test/phishing-awareness-platform/scripts/operator/alice-boot-persistence.sh
set -euo pipefail

ALICE="${ALICE:-erikd@192.168.1.36}"
SSH_KEY="${SSH_KEY-$HOME/.ssh/alice_dr_ed25519}"
TASK="KP-Aggregate-Model"
WSL_DISTRO="Ubuntu-24.04"
START_SH="/root/kp-aggregate-start.sh"
HOLD_SH="/usr/local/bin/kp-hold-session.sh"
TASK_USER="alice\\erikd"
UNIT="kp-aggregate"
MODEL_PORT=18082

say(){  printf "\033[1;34m==>\033[0m %s\n" "$*"; }
ok(){   printf "\033[1;32m  ok\033[0m %s\n" "$*"; }
warn(){ printf "\033[1;33m  !!\033[0m %s\n" "$*"; }
die(){  printf "\033[1;31m  xx\033[0m %s\n" "$*"; exit 1; }

SSH_OPTS=(-o ConnectTimeout=10 -o BatchMode=yes)
if [ -n "$SSH_KEY" ] && [ -f "$SSH_KEY" ]; then
  SSH_OPTS+=(-o IdentitiesOnly=yes -i "$SSH_KEY")
  KEYNOTE="$SSH_KEY"
else
  KEYNOTE="(from ~/.ssh/config)"
fi
# shellcheck disable=SC2029  # remote command is built here deliberately; all
# interpolated values are local constants, never untrusted input.
alice() { ssh "${SSH_OPTS[@]}" "$ALICE" "$@"; }

echo "     ALICE   = $ALICE"
echo "     SSH_KEY = $KEYNOTE"
echo "     TASK    = $TASK"

# ------------------------------------------------------------ 1. reachability
say "Checking Alice is reachable"
whoami_out="$(alice "echo %USERNAME%" 2>/dev/null | tr -d '\r')" \
  || die "cannot SSH to $ALICE. Check the host is on, and try: ssh $ALICE"
[ -n "$whoami_out" ] || die "SSH connected but returned nothing; is this the Windows host?"
ok "connected as $whoami_out"

say "Checking the WSL distro and start script exist"
alice "wsl -d $WSL_DISTRO -u root -e test -f $START_SH" >/dev/null 2>&1 \
  || die "$START_SH not found inside WSL $WSL_DISTRO on Alice — fix that before creating a task that runs it"
ok "$WSL_DISTRO has $START_SH"

say "Checking the systemd unit that owns it"
unit_enabled="$(alice "wsl -d $WSL_DISTRO -u root -e systemctl is-enabled $UNIT" 2>/dev/null | tr -d '\r' | head -1)"
[ "$unit_enabled" = "enabled" ] \
  || die "systemd unit $UNIT is '${unit_enabled:-missing}', not enabled — enable it inside WSL before adding a logon trigger"
ok "$UNIT is enabled"

# -------------------------------------------------------- 2. existing task?
say "Checking for an existing scheduled task"
if alice "schtasks /Query /TN \"$TASK\"" >/dev/null 2>&1; then
  if [ "${FORCE:-0}" = "1" ]; then
    warn "task exists; FORCE=1 so it will be recreated"
  else
    ok "task $TASK already exists — nothing to do"
    alice "schtasks /Query /TN \"$TASK\" /V /FO LIST" 2>/dev/null | tr -d '\r' \
      | grep -Ei "TaskName|Status|Run As User|Schedule Type|Task To Run" || true
    echo
    say "To recreate it anyway: FORCE=1 bash $0"
    exit 0
  fi
else
  ok "task does not exist yet"
fi

# --------------------------------------------------------------- 3. create
# Registered through PowerShell, not schtasks.exe, because only
# Register-ScheduledTask can set -LogonType S4U. See the header for why S4U is
# the only principal that works. The PowerShell is shipped base64-encoded: the
# path Mac -> ssh -> cmd.exe -> powershell mangles quoting otherwise, and this
# script had already been bitten by that several times.
say "Registering the S4U boot task on Alice"

read -r -d '' PS_SCRIPT <<PSEOF || true
\$ErrorActionPreference = 'Stop'
\$a = New-ScheduledTaskAction -Execute 'C:\Windows\System32\wsl.exe' \`
     -Argument '-d $WSL_DISTRO -u root -e $HOLD_SH'
\$t1 = New-ScheduledTaskTrigger -AtStartup
\$t2 = New-ScheduledTaskTrigger -AtLogOn -User '$TASK_USER'
\$p  = New-ScheduledTaskPrincipal -UserId '$TASK_USER' -LogonType S4U -RunLevel Highest
\$s  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries \`
       -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 \`
       -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew -StartWhenAvailable
\$s.DisallowStartOnRemoteAppSession = \$false
Register-ScheduledTask -TaskName '$TASK' -Action \$a -Trigger \$t1,\$t2 \`
  -Principal \$p -Settings \$s -Force | Out-Null
Write-Output 'REGISTERED_OK'
PSEOF

# ExecutionTimeLimit 0 matters: the task is a resident holder, so the default
# 3-day limit would eventually stop it and resurrect the kill cycle.
PS_B64="$(printf '%s\n' "$PS_SCRIPT" | base64 | tr -d '\n')"
reg_out="$(alice "powershell -NoProfile -Command \"\$d=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$PS_B64')); Set-Content -Path \$env:TEMP\\kp-boot-task.ps1 -Value \$d -Encoding UTF8; powershell -NoProfile -ExecutionPolicy Bypass -File \$env:TEMP\\kp-boot-task.ps1\"" 2>&1 | tr -d '\r')"
printf '%s\n' "$reg_out" | grep -q REGISTERED_OK \
  || die "Register-ScheduledTask failed:
$reg_out"
ok "registered as S4U (no password stored, fires at startup)"

# --------------------------------------------------------------- 4. verify
say "Verifying the task exists and has the right principal"
task_info="$(alice "schtasks /Query /TN \"$TASK\" /V /FO LIST" 2>/dev/null | tr -d '\r')"
printf '%s\n' "$task_info" \
  | grep -Ei "TaskName|Status|Run As User|Schedule Type|Task To Run" \
  || die "task was not found after creation"
# A task that came back as SYSTEM would run and fail with
# WSL_E_LOCAL_SYSTEM_NOT_SUPPORTED, so fail closed here rather than at boot.
if printf '%s\n' "$task_info" | grep -Eiq "Run As User: *(SYSTEM|NT AUTHORITY)"; then
  die "task is registered as SYSTEM; WSL cannot run as SYSTEM. Re-run with FORCE=1."
fi
ok "task verified on Alice"

# ------------------------------------------------- 5. optional run + probe
if [ "${RUN_NOW:-0}" != "1" ]; then
  echo
  say "Not started. To start it now and probe the model:"
  echo "  RUN_NOW=1 bash $0"
  echo
  say "Or reboot Alice and confirm the model comes back by itself:"
  echo "  curl -s http://192.168.1.36:$MODEL_PORT/v1/models"
  exit 0
fi

say "Running the task now"
alice "schtasks /Run /TN \"$TASK\"" 2>&1 | tr -d '\r' || warn "schtasks /Run reported a problem"
say "Waiting for the model to load (up to 3 minutes)"
for _ in $(seq 1 18); do
  body="$(curl -s --max-time 10 "http://${ALICE#*@}:$MODEL_PORT/v1/models" 2>/dev/null || true)"
  if printf '%s' "$body" | grep -q '"id"'; then
    ok "model endpoint is answering:"
    printf '%s\n' "$body" | head -c 400; echo
    exit 0
  fi
  sleep 10
done
warn "model did not answer on :$MODEL_PORT within 3 minutes"
echo "     check on Alice:  wsl -d $WSL_DISTRO -e systemctl status $UNIT"
exit 1
