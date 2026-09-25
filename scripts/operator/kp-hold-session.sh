#!/usr/bin/env bash
# kp-hold-session.sh — started by the Windows KP-Aggregate-Model logon task.
#
# WHY THIS EXISTS: kp-aggregate-start.sh runs llama-server in the foreground
# specifically so a live WSL session keeps it, and the distro, alive. Nothing
# was doing that: the logon task ran `systemctl start` and exited immediately,
# so every wsl.exe invocation created a short-lived session whose teardown sent
# SIGINT to the foreground process group. llama-server logged 637 starts and
# 633 "Received second interrupt" deaths, each about 17-20s after loading in
# ~3.7s. Holding one session open for 120s produced ZERO kills.
#
# So this starts the unit and then stays resident. Do not "simplify" it by
# removing the sleep - the sleep IS the fix.
set -uo pipefail
export PATH=/usr/lib/wsl/lib:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
logger -t kp-hold-session "starting kp-aggregate and holding the WSL session open" 2>/dev/null || true
systemctl start kp-aggregate 2>/dev/null || true
exec sleep infinity
