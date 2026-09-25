#!/usr/bin/env bash
# Rolling health log for Alice (192.168.1.36), to catch what the Windows event
# log cannot.
#
# WHY: Alice has had four unexpected shutdowns (Kernel-Power Event 41) — 8/1,
# 8/2, and TWICE on 9/23. Every one recorded BugcheckCode=0 with
# PowerButtonTimestamp=0 and NO WHEA hardware errors, meaning the machine died
# without logging anything: consistent with abrupt power loss, a thermal cutout,
# or a hard hang rather than a software crash. Windows cannot tell us why,
# because it was never given the chance to write anything.
#
# This samples the conditions that would precede such a failure and flushes each
# line to disk immediately, so the tail of the log survives a hard power cut and
# shows the state seconds before it happened.
#
# Captured per sample: GPU temperature, power draw against limit, utilisation,
# VRAM, plus kp-aggregate service state and whether the model is serving. A
# power-related death should show power.draw spiking toward the limit; a thermal
# one should show temperature climbing.
#
# Run it as a systemd unit inside WSL, NOT with nohup. The first attempt used
# nohup and was killed by the very 9/23 shutdown it was meant to explain,
# leaving nine lines and nothing watching for the next one. Install
# kp-alice-health.service from this directory alongside it:
#   install -m 0755 alice-health-monitor.sh /usr/local/bin/
#   install -m 0644 kp-alice-health.service /etc/systemd/system/
#   systemctl daemon-reload && systemctl enable --now kp-alice-health.service
#
# Read the log:
#   tail -40 /var/log/alice-health.log
#
# Overrides: INTERVAL=10 (seconds)  LOG=/var/log/alice-health.log
set -uo pipefail

LOG="${LOG:-/var/log/alice-health.log}"
INTERVAL="${INTERVAL:-10}"
export PATH="/usr/lib/wsl/lib:$PATH"   # nvidia-smi lives here on WSL, not on PATH

mkdir -p "$(dirname "$LOG")" 2>/dev/null || true
if ! : >>"$LOG" 2>/dev/null; then
  LOG="$HOME/alice-health.log"
  echo "cannot write the default log; using $LOG" >&2
fi

# A boot marker makes it obvious where an unexpected restart cut the log: the
# lines immediately BEFORE a marker are the last moments of the previous life.
{
  echo "==== monitor start $(date -u +%Y-%m-%dT%H:%M:%SZ) boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null | cut -c1-8) ===="
  echo "ts_utc gpu_temp_c power_w power_limit_w gpu_util_pct vram_used_mib unit model"
} >>"$LOG"
sync

while :; do
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  g="$(nvidia-smi --query-gpu=temperature.gpu,power.draw,power.limit,utilization.gpu,memory.used \
        --format=csv,noheader,nounits 2>/dev/null | head -1 | tr -d ' ')"
  if [ -z "$g" ]; then g="NA,NA,NA,NA,NA"; fi
  unit="$(systemctl is-active kp-aggregate 2>/dev/null || echo unknown)"
  if curl -s --max-time 4 http://127.0.0.1:18082/v1/models 2>/dev/null | grep -q '"models"'; then
    model=serving
  else
    model=not_serving
  fi
  printf '%s %s %s %s\n' "$ts" "$(echo "$g" | tr ',' ' ')" "$unit" "$model" >>"$LOG"
  # Flush every line: a hard power cut gives no chance to flush later, and an
  # unflushed buffer is exactly the evidence we need.
  sync
  sleep "$INTERVAL"
done
