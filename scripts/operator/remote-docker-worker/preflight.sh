#!/bin/bash
# Read-only controller-side qualification of the designated external Docker host.

set -euo pipefail

KP_REMOTE_HOST='edierks@192.168.1.140'
KP_REMOTE_PROJECT_DIR='/Users/edierks/Projects/kingphisher-phoenix'
KP_REMOTE_MIN_FREE_GIB="${KP_REMOTE_MIN_FREE_GIB:-100}"
KP_EXPECTED_CONTROLLER_CONTEXT=desktop-linux
KP_SSH_OPTIONS=(
  -o BatchMode=yes
  -o ConnectTimeout=10
  -o StrictHostKeyChecking=yes
)

case "$KP_REMOTE_MIN_FREE_GIB" in
  ''|*[!0-9]*|0) printf 'error: KP_REMOTE_MIN_FREE_GIB must be a positive whole number\n' >&2; exit 2 ;;
esac

[ -z "${DOCKER_HOST:-}" ] || { printf 'error: DOCKER_HOST must be unset for controller preflight\n' >&2; exit 3; }
[ -z "${DOCKER_CONTEXT:-}" ] || { printf 'error: DOCKER_CONTEXT must be unset for controller preflight\n' >&2; exit 3; }
[ -z "${DOCKER_CONFIG:-}" ] || { printf 'error: DOCKER_CONFIG must be unset for controller preflight\n' >&2; exit 3; }
KP_CONTROLLER_CONTEXT="$(docker context show)"
[ "$KP_CONTROLLER_CONTEXT" = "$KP_EXPECTED_CONTROLLER_CONTEXT" ] \
  || { printf 'error: controller Docker context must remain %s\n' "$KP_EXPECTED_CONTROLLER_CONTEXT" >&2; exit 3; }
KP_REMOTE_FACTS="$(ssh "${KP_SSH_OPTIONS[@]}" "$KP_REMOTE_HOST" \
  /usr/bin/env \
  "KP_EXTERNAL_MIN_FREE_GIB=$KP_REMOTE_MIN_FREE_GIB" \
  "$KP_REMOTE_PROJECT_DIR/scripts/operator/remote-docker-worker/external-engine.sh" \
  preflight)"
KP_REMOTE_CONTEXT_AFTER="$(docker context show)"
if [ "$KP_CONTROLLER_CONTEXT" != "$KP_REMOTE_CONTEXT_AFTER" ]; then
  printf 'error: controller Docker context changed during preflight\n' >&2
  exit 3
fi

KP_REMOTE_HOST_FACTS="$(ssh "${KP_SSH_OPTIONS[@]}" "$KP_REMOTE_HOST" '
  set -eu
  printf "user=%s\n" "$(id -un)"
  printf "architecture=%s\n" "$(uname -m)"
  printf "macos_version=%s\n" "$(sw_vers -productVersion)"
')"

KP_REMOTE_FREE_KIB="$(printf '%s\n' "$KP_REMOTE_FACTS" | awk -F= '$1 == "external_free_kib" {print $2}')"
case "$KP_REMOTE_FREE_KIB" in
  ''|*[!0-9]*) printf 'error: remote free-space evidence is malformed\n' >&2; exit 4 ;;
esac
KP_REQUIRED_KIB=$((KP_REMOTE_MIN_FREE_GIB * 1024 * 1024))
if [ "$KP_REMOTE_FREE_KIB" -lt "$KP_REQUIRED_KIB" ]; then
  printf 'error: remote worker has less than %s GiB free\n' "$KP_REMOTE_MIN_FREE_GIB" >&2
  exit 5
fi

printf '%s\n' "$KP_REMOTE_FACTS"
printf '%s\n' "$KP_REMOTE_HOST_FACTS"
printf 'controller_context=%s\n' "$KP_CONTROLLER_CONTEXT"
