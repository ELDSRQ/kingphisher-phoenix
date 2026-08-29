#!/bin/bash
# Double-click this file on the designated remote Mac. It enables SSH for the
# current user, installs the supplied public key, and starts a project-isolated
# Colima/Docker engine stored on DockerExternal. It never selects or modifies
# the shared Docker Desktop engine and never opens a Docker TCP socket.

set -euo pipefail

export PATH="/usr/local/bin:/opt/homebrew/bin:$PATH"

KP_SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KP_PUBLIC_KEY_FILE="$KP_SCRIPT_DIR/controller_ed25519.pub"
KP_EXTERNAL_ENGINE="$KP_SCRIPT_DIR/external-engine.sh"
KP_PROJECT_DIR="$HOME/Projects/kingphisher-phoenix"
KP_EXTERNAL_VOLUME=/Volumes/DockerExternal
KP_EXTERNAL_ROOT="$KP_EXTERNAL_VOLUME/KingPhisher-Phoenix"
KP_EXTERNAL_VOLUME_UUID=FD7BE277-8CB4-3ADA-8CA2-11F8EBBBADF4

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  /usr/bin/osascript -e "display dialog \"KingPhisher worker setup stopped: $*\" buttons {\"OK\"} default button \"OK\" with icon stop" >/dev/null 2>&1 || true
  exit 1
}

[ "$(uname -s)" = "Darwin" ] || fail "this bootstrap is only for macOS"
[ "$(uname -m)" = arm64 ] \
  || fail "this worker must be native Apple Silicon; Rosetta and x86 hosts are unsupported"
[ -s "$KP_PUBLIC_KEY_FILE" ] || fail "controller_ed25519.pub is missing from the setup kit"
[ -x "$KP_EXTERNAL_ENGINE" ] || fail "external-engine.sh is missing or not executable"
[ -d "$KP_EXTERNAL_VOLUME" ] || fail "attach and mount DockerExternal before continuing"
[ -w "$KP_EXTERNAL_VOLUME" ] || fail "DockerExternal is not writable"
KP_MOUNT_POINT="$(/usr/sbin/diskutil info "$KP_EXTERNAL_VOLUME" \
  | /usr/bin/awk -F: '$1 ~ /^[[:space:]]*Mount Point[[:space:]]*$/ {sub(/^[[:space:]]*/, "", $2); print $2}')"
KP_VOLUME_UUID="$(/usr/sbin/diskutil info "$KP_EXTERNAL_VOLUME" \
  | /usr/bin/awk -F: '$1 ~ /^[[:space:]]*Volume UUID[[:space:]]*$/ {sub(/^[[:space:]]*/, "", $2); print $2}')"
[ "$KP_MOUNT_POINT" = "$KP_EXTERNAL_VOLUME" ] \
  || fail "DockerExternal is not mounted at the reviewed path"
[ "$KP_VOLUME_UUID" = "$KP_EXTERNAL_VOLUME_UUID" ] \
  || fail "DockerExternal has the wrong fixed-volume identity"

KP_PUBLIC_KEY="$(sed -n '1p' "$KP_PUBLIC_KEY_FILE")"
case "$KP_PUBLIC_KEY" in
  ssh-ed25519\ *) ;;
  *) fail "the supplied controller key is not an Ed25519 public key" ;;
esac

/usr/bin/install -d -m 700 "$HOME/.ssh"
/usr/bin/touch "$HOME/.ssh/authorized_keys"
/bin/chmod 600 "$HOME/.ssh/authorized_keys"
if ! /usr/bin/grep -Fqx "$KP_PUBLIC_KEY" "$HOME/.ssh/authorized_keys"; then
  printf '%s\n' "$KP_PUBLIC_KEY" >> "$HOME/.ssh/authorized_keys"
fi

# Docker contexts invoke `docker system dial-stdio` through a non-interactive
# SSH shell. macOS omits /usr/local/bin from that shell even when Docker
# Desktop installed its supported CLI symlink there.
KP_ZSHENV="$HOME/.zshenv"
# PATH expansion is intentionally deferred to the remote shell.
# shellcheck disable=SC2016
KP_DOCKER_PATH_LINE='export PATH="/usr/local/bin:/opt/homebrew/bin:$PATH"'
/usr/bin/touch "$KP_ZSHENV"
if ! /usr/bin/grep -Fqx "$KP_DOCKER_PATH_LINE" "$KP_ZSHENV"; then
  printf '%s\n' "$KP_DOCKER_PATH_LINE" >> "$KP_ZSHENV"
fi

if ! /usr/sbin/systemsetup -getremotelogin 2>/dev/null | /usr/bin/grep -q 'On$'; then
  printf 'macOS will request an administrator password to enable Remote Login.\n'
  if ! /usr/bin/sudo /usr/sbin/systemsetup -setremotelogin on; then
    /usr/bin/open 'x-apple.systempreferences:com.apple.Sharing-Settings.extension' >/dev/null 2>&1 || true
    fail "enable System Settings > General > Sharing > Remote Login, then run this file again"
  fi
fi

command -v brew >/dev/null 2>&1 \
  || fail "Homebrew is required to install the isolated Docker worker dependencies"
if ! command -v docker >/dev/null 2>&1; then
  brew install docker || fail "Docker CLI installation failed"
fi
if ! command -v docker-credential-osxkeychain >/dev/null 2>&1; then
  brew install docker-credential-helper || fail "Docker Keychain credential helper installation failed"
fi
KP_DOCKER_DESKTOP_PLUGIN_DIR=/Applications/Docker.app/Contents/Resources/cli-plugins
KP_HOMEBREW_PLUGIN_DIR=/opt/homebrew/lib/docker/cli-plugins
if { [ ! -x "$KP_DOCKER_DESKTOP_PLUGIN_DIR/docker-compose" ] \
  || [ ! -x "$KP_DOCKER_DESKTOP_PLUGIN_DIR/docker-buildx" ]; } \
  && { [ ! -x "$KP_HOMEBREW_PLUGIN_DIR/docker-compose" ] \
  || [ ! -x "$KP_HOMEBREW_PLUGIN_DIR/docker-buildx" ]; }; then
  brew install docker-compose docker-buildx \
    || fail "Docker Compose and Buildx plugin installation failed"
fi
if [ ! -x /opt/homebrew/bin/colima ]; then
  brew install colima || fail "Colima installation failed"
fi

/usr/bin/install -d -m 700 "$KP_PROJECT_DIR"
"$KP_EXTERNAL_ENGINE" start || fail "the external project Docker engine did not pass preflight"
KP_DOCKER_BIN="$(command -v docker)"
KP_DOCKER_VERSION="$("$KP_EXTERNAL_ENGINE" docker version --format '{{.Server.Version}}')"
KP_LOCAL_HOSTNAME="$(/usr/sbin/scutil --get LocalHostName 2>/dev/null || hostname)"
KP_PRIMARY_IP="$(/usr/sbin/ipconfig getifaddr en0 2>/dev/null || /usr/sbin/ipconfig getifaddr en1 2>/dev/null || true)"
KP_FREE_KIB="$(df -k "$KP_EXTERNAL_VOLUME" | awk 'NR == 2 {print $4}')"
KP_RESULT_DIRECTORY="$KP_EXTERNAL_ROOT/qualification-evidence"
/usr/bin/install -d -m 700 "$KP_RESULT_DIRECTORY"
KP_RESULT_FILE="$(/usr/bin/mktemp "$KP_RESULT_DIRECTORY/remote-worker-result.XXXXXX")" \
  || fail "could not create no-clobber worker qualification evidence"
/bin/chmod 600 "$KP_RESULT_FILE"

printf '%s\n' \
  'KingPhisher remote Docker worker ready' \
  "configured_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  "user=$(id -un)" \
  "hostname=$KP_LOCAL_HOSTNAME" \
  "ip_address=$KP_PRIMARY_IP" \
  "architecture=$(uname -m)" \
  "macos_version=$(sw_vers -productVersion)" \
  "docker_binary=$KP_DOCKER_BIN" \
  "docker_server_version=$KP_DOCKER_VERSION" \
  "external_volume=$KP_EXTERNAL_VOLUME" \
  "external_volume_uuid=$KP_VOLUME_UUID" \
  "external_root=$KP_EXTERNAL_ROOT" \
  "external_free_kib=$KP_FREE_KIB" \
  "docker_socket=$KP_EXTERNAL_ROOT/colima/kingphisher/docker.sock" \
  "project_directory=$KP_PROJECT_DIR" \
  'native_worker_platform=linux/arm64' \
  'rosetta_required=false' \
  'docker_desktop_modified=false' \
  'global_docker_context_changed=false' \
  'docker_tcp_socket=disabled' \
  > "$KP_RESULT_FILE"

/usr/bin/osascript -e 'display dialog "KingPhisher remote Docker worker is ready. Return to the controller Mac to continue the verified migration." buttons {"OK"} default button "OK" with icon note' >/dev/null 2>&1 || true
printf 'Remote worker ready. Evidence: %s\n' "$KP_RESULT_FILE"
