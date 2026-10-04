#!/usr/bin/env bash
# Install the on-prem app supervisor as a systemd --user unit on the .105 WSL2
# worker so the stack (operator-api, tracking-api, workers) auto-starts on boot
# and auto-restarts on a child crash.
#
# Context: the ai-gateway is a root-owned *system* unit and already survives
# reboots; the app supervisor was a plain detached process and did NOT, so a
# WSL restart left operator-api/tracking down until a manual relaunch. This unit
# closes that gap. `builder` has no sudo, so the one privileged step (enabling
# linger, required for a --user unit to start at boot) is printed for the
# operator to run; everything else runs unprivileged as `builder`.
#
# Run as `builder` on .105:  bash scripts/operator/onprem-supervisor/install.sh
set -euo pipefail

REPO="${REPO:-$HOME/phishing-awareness-platform}"
UNIT_SRC="$REPO/scripts/operator/onprem-supervisor/kp-supervisor.service"
UNIT_DST="$HOME/.config/systemd/user/kp-supervisor.service"

[ -f "$UNIT_SRC" ] || { echo "missing unit: $UNIT_SRC" >&2; exit 1; }

mkdir -p "$(dirname "$UNIT_DST")"
install -m 0644 "$UNIT_SRC" "$UNIT_DST"
systemctl --user daemon-reload
systemctl --user enable kp-supervisor.service

echo "installed + enabled: kp-supervisor.service (inactive until started)"
echo

linger="$(loginctl show-user "$USER" 2>/dev/null | sed -n 's/^Linger=//p')"
if [ "$linger" != "yes" ]; then
  cat >&2 <<EOF
NOT boot-persistent yet. A --user unit only starts at boot when lingering is on,
and enabling it needs root (this account has no sudo). Run ONE of these, once:

  # inside WSL as a sudoer:
  sudo loginctl enable-linger $USER

  # or from Windows (erikd), as root in the distro:
  wsl -u root -- loginctl enable-linger $USER

Then cut over with no further privilege:
  # stop the old detached supervisor, if any:
  pkill -f "python scripts/supervisor.py" || true
  systemctl --user start kp-supervisor.service
  systemctl --user status kp-supervisor.service --no-pager
EOF
  exit 0
fi

echo "linger is enabled; safe to cut over:"
echo "  pkill -f 'python scripts/supervisor.py' || true"
echo "  systemctl --user start kp-supervisor.service"
