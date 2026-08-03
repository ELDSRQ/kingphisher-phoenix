#!/usr/bin/env bash
# Build the double-clickable Kingphisher Launcher.app for macOS.
#
# Produces:  Kingphisher Launcher.app
# (a Finder-double-clickable bundle that runs scripts/run_console.sh)
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

APP_DIR="$PROJECT_ROOT/Kingphisher Launcher.app"
CONTENTS="$APP_DIR/Contents"
MACOS="$CONTENTS/MacOS"
RESOURCES="$CONTENTS/Resources"

rm -rf "$APP_DIR"
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
# console launcher in the background. There is no terminal: the launcher opens
# the browser console itself, and the operator stops/restarts the stack from
# the console's Settings page (the supervisor watches the marker files).
cat > "$MACOS/launch" <<'EOF'
#!/bin/zsh
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
LAUNCHER="$PROJECT_ROOT/scripts/run_console.sh"

if [ ! -x "$LAUNCHER" ]; then
  osascript -e 'display alert "Kingphisher Launcher" message "The launcher script was not found at: '"$LAUNCHER"'" as critical'
  exit 1
fi

if [ -f "$PROJECT_ROOT/data/run/operator-api.pid" ]; then
  osascript -e 'display alert "Kingphisher Launcher" message "The stack already appears to be running."'
  open "http://127.0.0.1:8000/console"
  exit 0
fi

nohup "$LAUNCHER" >/dev/null 2>&1 &
exit 0
EOF
chmod +x "$MACOS/launch"

touch "$APP_DIR"
echo "built: $APP_DIR"
echo "double-click it in Finder to start the stack and open the console."
