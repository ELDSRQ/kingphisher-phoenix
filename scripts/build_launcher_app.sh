#!/usr/bin/env bash
# Build the double-clickable Kingphisher Launcher.app for macOS.
#
# Produces:  Kingphisher Launcher.app
# (a Finder-double-clickable bundle that runs scripts/run_console.sh)
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

APP_DIR="$PROJECT_ROOT/Kingphisher Launcher.app"
STAGING_DIR="$PROJECT_ROOT/Kingphisher Launcher.app.next"
CONTENTS="$STAGING_DIR/Contents"
MACOS="$CONTENTS/MacOS"
RESOURCES="$CONTENTS/Resources"

if [ -e "$STAGING_DIR" ]; then
  echo "refusing to overwrite the preserved launcher staging bundle: $STAGING_DIR" >&2
  echo "safe next action: inspect or move that bundle, then rerun this builder." >&2
  exit 1
fi
mkdir -p "$MACOS" "$RESOURCES"

# Info.plist: the Finder uses CFBundleExecutable to run the launch stub.
cat > "$CONTENTS/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>
  <string>Kingphisher Launcher</string>
  <key>CFBundleDisplayName</key>
  <string>Kingphisher Launcher</string>
  <key>CFBundleIdentifier</key>
  <string>com.kingphisher.launcher</string>
  <key>CFBundleVersion</key>
  <string>0.1.0</string>
  <key>CFBundleShortVersionString</key>
  <string>0.1.0</string>
  <key>CFBundleExecutable</key>
  <string>launch</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>LSMinimumSystemVersion</key>
  <string>12.0</string>
</dict>
</plist>
PLIST

# Launch stub: resolves the project path relative to the bundle and runs the
# console launcher without a terminal.  The app process remains attached to
# the supervisor so startup failures can become a visible alert; operators
# still stop/restart from the console's Settings page via marker files.
cat > "$MACOS/launch" <<'EOF'
#!/bin/zsh
set -euo pipefail
umask 077

PROJECT_ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
LAUNCHER="$PROJECT_ROOT/scripts/run_console.sh"
PID_FILE="$PROJECT_ROOT/data/run/operator-api.pid"
LOG_FILE="$PROJECT_ROOT/data/logs/launcher-$(date -u +%Y%m%dT%H%M%SZ)-$$.log"

pidfile_is_live() {
  local pid
  [ -f "$PID_FILE" ] || return 1
  # Accept legacy PID files without a final newline. `read` still populates
  # the value even though it returns EOF in that case.
  IFS= read -r pid < "$PID_FILE" || [ -n "$pid" ] || return 1
  case "$pid" in
    ''|*[!0-9]*) return 1 ;;
  esac
  [ "$pid" -gt 0 ] 2>/dev/null || return 1
  kill -0 "$pid" 2>/dev/null
}

if [ ! -x "$LAUNCHER" ]; then
  osascript -e 'display alert "Kingphisher Launcher" message "The launcher script was not found at: '"$LAUNCHER"'" as critical'
  exit 1
fi

if pidfile_is_live; then
  osascript -e 'display alert "Kingphisher Launcher" message "The stack is already running."'
  open "http://127.0.0.1:8000/console"
  exit 0
fi

mkdir -p "$PROJECT_ROOT/data/logs"
if ! "$LAUNCHER" >"$LOG_FILE" 2>&1; then
  osascript -e 'display alert "Kingphisher Launcher" message "The local stack could not start. Review the newest data/logs/launcher-*.log for the actionable error." as critical'
  exit 1
fi
EOF
chmod +x "$MACOS/launch"

if command -v zsh >/dev/null 2>&1; then
  zsh -n "$MACOS/launch"
fi
if command -v plutil >/dev/null 2>&1; then
  plutil -lint "$CONTENTS/Info.plist" >/dev/null
fi

# Re-running install should not consume disk by preserving a byte-identical
# launcher backup. These are the only files this invocation created, so this
# exact cleanup cannot touch an existing bundle or recovery evidence.
if [ -x "$APP_DIR/Contents/MacOS/launch" ] \
  && cmp -s "$CONTENTS/Info.plist" "$APP_DIR/Contents/Info.plist" \
  && cmp -s "$MACOS/launch" "$APP_DIR/Contents/MacOS/launch"; then
  rm -- "$MACOS/launch" "$CONTENTS/Info.plist"
  rmdir "$RESOURCES" "$MACOS" "$CONTENTS" "$STAGING_DIR"
  echo "unchanged: $APP_DIR"
  exit 0
fi

BACKUP_DIR=""
publication_pending=0
restore_previous_launcher() {
  if [ "$publication_pending" -eq 1 ] \
    && [ -n "$BACKUP_DIR" ] \
    && [ ! -e "$APP_DIR" ] \
    && [ -e "$BACKUP_DIR" ]; then
    mv "$BACKUP_DIR" "$APP_DIR"
  fi
}
trap restore_previous_launcher EXIT
if [ -e "$APP_DIR" ]; then
  BACKUP_DIR="$PROJECT_ROOT/Kingphisher Launcher.app.backup-$(date -u +%Y%m%dT%H%M%SZ)"
  if [ -e "$BACKUP_DIR" ]; then
    echo "refusing to overwrite the preserved launcher backup: $BACKUP_DIR" >&2
    echo "safe next action: inspect or move that backup, then rerun this builder." >&2
    exit 1
  fi
  mv "$APP_DIR" "$BACKUP_DIR"
  publication_pending=1
fi

if ! mv "$STAGING_DIR" "$APP_DIR"; then
  if [ -n "$BACKUP_DIR" ] && [ ! -e "$APP_DIR" ]; then
    mv "$BACKUP_DIR" "$APP_DIR"
  fi
  echo "launcher publication failed; the prior launcher was preserved." >&2
  echo "safe next action: inspect the filesystem error and rerun the builder." >&2
  exit 1
fi
publication_pending=0

echo "built: $APP_DIR"
if [ -n "$BACKUP_DIR" ]; then
  echo "preserved prior launcher: $BACKUP_DIR"
fi
echo "double-click it in Finder to start the stack and open the console."
