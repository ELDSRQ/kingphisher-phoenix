#!/usr/bin/env bash
# Run the reviewed Docker Desktop recovery checkpoint on the fixed macOS worker.
#
# The controller Keychain remains the source of truth for the recovery identity.
# Only a uniquely named 0600 transfer file is copied to the worker, and both the
# controller and worker transfer files are removed on every exit path.

set -euo pipefail

KP_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
KP_LOCAL_CHECKPOINT="$KP_ROOT/scripts/operator/remote-docker-worker/checkpoint-state.sh"
KP_REMOTE_TARGET='edierks@192.168.1.140'
KP_REMOTE_SOURCE='/Users/edierks/Projects/kingphisher-phoenix'
KP_REMOTE_CHECKPOINT="$KP_REMOTE_SOURCE/scripts/operator/remote-docker-worker/checkpoint-state.sh"
KP_RECOVERY_KEYCHAIN_SERVICE='com.kingphisher.phishing-awareness-platform.migration-recovery.v1'
KP_RECOVERY_KEYCHAIN_ACCOUNT='phishing-awareness-platform-recovery'
KP_SECURITY_BIN="${KP_SECURITY_BIN:-/usr/bin/security}"
KP_AGE_KEYGEN_BIN="${KP_AGE_KEYGEN_BIN:-$(command -v age-keygen || true)}"
KP_SSH_BIN="${KP_SSH_BIN:-/usr/bin/ssh}"
KP_SCP_BIN="${KP_SCP_BIN:-/usr/bin/scp}"
KP_SHASUM_BIN="${KP_SHASUM_BIN:-/usr/bin/shasum}"
KP_APPLY=0
KP_LOCAL_IDENTITY_FILE=''
KP_REMOTE_IDENTITY_FILE=''
KP_SSH_OPTIONS=(
  -o BatchMode=yes
  -o ConnectTimeout=10
  -o StrictHostKeyChecking=yes
)

fail() {
  printf 'REMOTE CHECKPOINT BLOCKED: %s\n' "$*" >&2
  printf 'No container, volume, image, source, or unrelated Docker resource was removed or replaced.\n' >&2
  exit 1
}

usage() {
  printf 'usage: %s [--apply]\n' "$0" >&2
  exit 2
}

cleanup() {
  KP_EXIT_STATUS=$?
  trap - EXIT HUP INT TERM

  if [ -n "$KP_REMOTE_IDENTITY_FILE" ]; then
    if ! "$KP_SSH_BIN" "${KP_SSH_OPTIONS[@]}" "$KP_REMOTE_TARGET" \
      /bin/rm -f -- "$KP_REMOTE_IDENTITY_FILE" >/dev/null 2>&1; then
      printf 'REMOTE CHECKPOINT BLOCKED: exact remote transfer file cleanup failed\n' >&2
      KP_EXIT_STATUS=1
    fi
  fi
  if [ -n "$KP_LOCAL_IDENTITY_FILE" ] && [ -e "$KP_LOCAL_IDENTITY_FILE" ]; then
    if ! /bin/rm -f -- "$KP_LOCAL_IDENTITY_FILE"; then
      printf 'REMOTE CHECKPOINT BLOCKED: exact controller transfer file cleanup failed\n' >&2
      KP_EXIT_STATUS=1
    fi
  fi

  exit "$KP_EXIT_STATUS"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [ "$#" -gt 1 ]; then
  usage
fi
if [ "$#" -eq 1 ]; then
  [ "$1" = --apply ] || usage
  KP_APPLY=1
fi

[ "$(uname -s)" = Darwin ] || fail "the controller must be macOS"
[ -x "$KP_SECURITY_BIN" ] || fail "macOS Keychain command is unavailable"
[ -n "$KP_AGE_KEYGEN_BIN" ] && [ -x "$KP_AGE_KEYGEN_BIN" ] \
  || fail "age-keygen is unavailable"
[ -x "$KP_SSH_BIN" ] || fail "SSH is unavailable"
[ -x "$KP_SCP_BIN" ] || fail "SCP is unavailable"
[ -x "$KP_SHASUM_BIN" ] || fail "SHA-256 command is unavailable"
[ -f "$KP_LOCAL_CHECKPOINT" ] && [ ! -L "$KP_LOCAL_CHECKPOINT" ] \
  || fail "the checked-in checkpoint script is absent, non-regular, or symbolic"
[ -d /private/tmp ] && [ ! -L /private/tmp ] \
  || fail "the fixed private transfer directory is unavailable"

umask 077
KP_LOCAL_IDENTITY_CANDIDATE="$(/usr/bin/mktemp /private/tmp/kp-recovery-controller.XXXXXX)" \
  || fail "could not create the controller transfer file"
[[ "$KP_LOCAL_IDENTITY_CANDIDATE" =~ ^/private/tmp/kp-recovery-controller\.[[:alnum:]]{6}$ ]] \
  || fail "controller transfer file escaped the fixed private namespace"
KP_LOCAL_IDENTITY_FILE="$KP_LOCAL_IDENTITY_CANDIDATE"
[ -f "$KP_LOCAL_IDENTITY_FILE" ] && [ ! -L "$KP_LOCAL_IDENTITY_FILE" ] \
  || fail "controller transfer file is not an exact regular file"
chmod 600 "$KP_LOCAL_IDENTITY_FILE"

"$KP_SECURITY_BIN" find-generic-password \
  -a "$KP_RECOVERY_KEYCHAIN_ACCOUNT" \
  -s "$KP_RECOVERY_KEYCHAIN_SERVICE" \
  -w > "$KP_LOCAL_IDENTITY_FILE" 2>/dev/null \
  || fail "the controller recovery identity is absent from the fixed Keychain item"
chmod 600 "$KP_LOCAL_IDENTITY_FILE"
KP_IDENTITY_KEY_COUNT="$(grep -Ec '^AGE-SECRET-KEY-1[0-9A-Z]+$' "$KP_LOCAL_IDENTITY_FILE" || true)"
[ "$KP_IDENTITY_KEY_COUNT" = 1 ] \
  || fail "the controller recovery identity has an unexpected record count"
! grep -Evq '^AGE-SECRET-KEY-1[0-9A-Z]+$' "$KP_LOCAL_IDENTITY_FILE" \
  || fail "the controller recovery identity has an invalid format"
KP_PUBLIC_RECIPIENT="$("$KP_AGE_KEYGEN_BIN" -y "$KP_LOCAL_IDENTITY_FILE" 2>/dev/null)" \
  || fail "the controller recovery identity cannot derive a public recipient"
[[ "$KP_PUBLIC_RECIPIENT" =~ ^age1[0-9a-z]+$ ]] \
  || fail "the derived public recovery recipient has an invalid format"

KP_LOCAL_CHECKPOINT_SHA="$("$KP_SHASUM_BIN" -a 256 "$KP_LOCAL_CHECKPOINT" \
  | /usr/bin/awk 'NR == 1 {print $1} NR > 1 {exit 2}')" \
  || fail "the checked-in checkpoint script could not be hashed"
[[ "$KP_LOCAL_CHECKPOINT_SHA" =~ ^[0-9a-f]{64}$ ]] \
  || fail "the checked-in checkpoint script digest is malformed"
KP_REMOTE_HASH_LINE="$("$KP_SSH_BIN" "${KP_SSH_OPTIONS[@]}" "$KP_REMOTE_TARGET" \
  /usr/bin/shasum -a 256 "$KP_REMOTE_CHECKPOINT" 2>/dev/null)" \
  || fail "the exact remote checkpoint script could not be hashed"
if [[ ! "$KP_REMOTE_HASH_LINE" =~ ^([0-9a-f]{64})[[:space:]]+(/Users/edierks/Projects/kingphisher-phoenix/scripts/operator/remote-docker-worker/checkpoint-state\.sh)$ ]]; then
  fail "the remote checkpoint script digest response is malformed"
fi
KP_REMOTE_CHECKPOINT_SHA="${BASH_REMATCH[1]}"
[ "$KP_REMOTE_CHECKPOINT_SHA" = "$KP_LOCAL_CHECKPOINT_SHA" ] \
  || fail "the remote checkpoint script does not match the checked-in controller copy"

KP_REMOTE_IDENTITY_CANDIDATE="$("$KP_SSH_BIN" "${KP_SSH_OPTIONS[@]}" "$KP_REMOTE_TARGET" \
  /usr/bin/mktemp /private/tmp/kp-recovery-transfer.XXXXXX 2>/dev/null)" \
  || fail "could not create the exact remote transfer file"
[[ "$KP_REMOTE_IDENTITY_CANDIDATE" =~ ^/private/tmp/kp-recovery-transfer\.[[:alnum:]]{6}$ ]] \
  || fail "remote transfer file escaped the fixed private namespace"
KP_REMOTE_IDENTITY_FILE="$KP_REMOTE_IDENTITY_CANDIDATE"

"$KP_SCP_BIN" -q "${KP_SSH_OPTIONS[@]}" \
  "$KP_LOCAL_IDENTITY_FILE" "$KP_REMOTE_TARGET:$KP_REMOTE_IDENTITY_FILE" >/dev/null \
  || fail "the recovery identity transfer failed"
"$KP_SSH_BIN" "${KP_SSH_OPTIONS[@]}" "$KP_REMOTE_TARGET" \
  /bin/chmod 600 "$KP_REMOTE_IDENTITY_FILE" >/dev/null \
  || fail "the remote recovery identity mode could not be fixed"
KP_REMOTE_IDENTITY_MODE="$("$KP_SSH_BIN" "${KP_SSH_OPTIONS[@]}" "$KP_REMOTE_TARGET" \
  /usr/bin/stat -f %Lp "$KP_REMOTE_IDENTITY_FILE" 2>/dev/null)" \
  || fail "the remote recovery identity mode could not be verified"
[ "$KP_REMOTE_IDENTITY_MODE" = 600 ] \
  || fail "the remote recovery identity is not mode 0600"

KP_REMOTE_COMMAND=(
  /usr/bin/env
  "KP_RECOVERY_IDENTITY_FILE=$KP_REMOTE_IDENTITY_FILE"
  /bin/bash
  "$KP_REMOTE_CHECKPOINT"
  --recipient
  "$KP_PUBLIC_RECIPIENT"
)
if [ "$KP_APPLY" -eq 1 ]; then
  KP_REMOTE_COMMAND+=(--apply)
fi
"$KP_SSH_BIN" "${KP_SSH_OPTIONS[@]}" "$KP_REMOTE_TARGET" "${KP_REMOTE_COMMAND[@]}"

if [ "$KP_APPLY" -eq 1 ]; then
  KP_MODE=apply
else
  KP_MODE=dry-run
fi
printf 'REMOTE CHECKPOINT CONTROLLER PASSED: target=%s mode=%s\n' \
  "$KP_REMOTE_TARGET" "$KP_MODE"
printf 'recovery_recipient=%s\n' "$KP_PUBLIC_RECIPIENT"
