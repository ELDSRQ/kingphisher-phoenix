#!/usr/bin/env bash
# Create or verify the narrowly scoped age identity used for migration recovery.
#
# The private identity is held only in a 0600 temporary file and the macOS
# Keychain.  This command deliberately prints only the public age recipient.

set -euo pipefail

KP_RECOVERY_KEYCHAIN_SERVICE="${KP_RECOVERY_KEYCHAIN_SERVICE:-com.kingphisher.phishing-awareness-platform.migration-recovery.v1}"
KP_RECOVERY_KEYCHAIN_ACCOUNT="${KP_RECOVERY_KEYCHAIN_ACCOUNT:-phishing-awareness-platform-recovery}"
KP_RECOVERY_EXPECTED_RECIPIENT="${KP_RECOVERY_EXPECTED_RECIPIENT:-}"
KP_SECURITY_BIN="${KP_SECURITY_BIN:-/usr/bin/security}"
KP_AGE_KEYGEN_BIN="${KP_AGE_KEYGEN_BIN:-$(command -v age-keygen || true)}"
KP_SECURE_TMP_ROOT="${KP_SECURE_TMP_ROOT:-/private/tmp}"
KP_IDENTITY_TEMP_DIR=''

fail() {
  printf 'RECOVERY IDENTITY BLOCKED: %s\n' "$*" >&2
  printf 'The existing Keychain identity was preserved and was not replaced.\n' >&2
  exit 1
}

usage() {
  printf 'usage: %s {create|verify}\n' "$0" >&2
  exit 2
}

cleanup() {
  if [ -n "$KP_IDENTITY_TEMP_DIR" ] && [ -d "$KP_IDENTITY_TEMP_DIR" ]; then
    /bin/rm -R -- "$KP_IDENTITY_TEMP_DIR"
  fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

require_runtime() {
  [ "$(uname -s)" = Darwin ] || fail "macOS Keychain is required"
  [ -x "$KP_SECURITY_BIN" ] || fail "macOS Keychain command is unavailable"
  [ -n "$KP_AGE_KEYGEN_BIN" ] && [ -x "$KP_AGE_KEYGEN_BIN" ] \
    || fail "age-keygen is unavailable"
  [ -d "$KP_SECURE_TMP_ROOT" ] && [ ! -L "$KP_SECURE_TMP_ROOT" ] \
    || fail "secure temporary directory is unavailable"
  case "$KP_RECOVERY_KEYCHAIN_SERVICE" in
    com.kingphisher.phishing-awareness-platform.migration-recovery.*) ;;
    *) fail "Keychain service is outside the recovery namespace" ;;
  esac
  [ "$KP_RECOVERY_KEYCHAIN_ACCOUNT" = phishing-awareness-platform-recovery ] \
    || fail "Keychain account is outside the recovery namespace"
  umask 077
  KP_IDENTITY_TEMP_DIR="$(mktemp -d "$KP_SECURE_TMP_ROOT/kp-recovery-identity.XXXXXX")"
  [ -d "$KP_IDENTITY_TEMP_DIR" ] && [ ! -L "$KP_IDENTITY_TEMP_DIR" ] \
    || fail "could not create a private temporary directory"
}

validate_identity_file() {
  KP_IDENTITY_FILE="$1"
  [ -s "$KP_IDENTITY_FILE" ] || fail "Keychain identity is missing or empty"
  KP_IDENTITY_KEY_COUNT="$(grep -Ec '^AGE-SECRET-KEY-1[0-9A-Z]+$' "$KP_IDENTITY_FILE" || true)"
  [ "$KP_IDENTITY_KEY_COUNT" = 1 ] || fail "Keychain identity has an unexpected record count"
  ! grep -Evq '^(#.*|AGE-SECRET-KEY-1[0-9A-Z]+)$' "$KP_IDENTITY_FILE" \
    || fail "Keychain identity has an invalid format"
  KP_PUBLIC_RECIPIENT="$("$KP_AGE_KEYGEN_BIN" -y "$KP_IDENTITY_FILE" 2>/dev/null)" \
    || fail "Keychain identity cannot derive a public recipient"
  printf '%s\n' "$KP_PUBLIC_RECIPIENT" | grep -Eq '^age1[0-9a-z]+$' \
    || fail "derived age recipient has an invalid format"
  if [ -n "$KP_RECOVERY_EXPECTED_RECIPIENT" ]; then
    [ "$KP_PUBLIC_RECIPIENT" = "$KP_RECOVERY_EXPECTED_RECIPIENT" ] \
      || fail "derived recipient does not match KP_RECOVERY_EXPECTED_RECIPIENT"
  fi
}

retrieve_identity() {
  KP_RETRIEVED_IDENTITY="$KP_IDENTITY_TEMP_DIR/keychain-identity.txt"
  "$KP_SECURITY_BIN" find-generic-password \
    -a "$KP_RECOVERY_KEYCHAIN_ACCOUNT" \
    -s "$KP_RECOVERY_KEYCHAIN_SERVICE" \
    -w > "$KP_RETRIEVED_IDENTITY" 2>/dev/null \
    || fail "recovery identity is absent from the named Keychain item"
  chmod 600 "$KP_RETRIEVED_IDENTITY"
  validate_identity_file "$KP_RETRIEVED_IDENTITY"
}

verify_identity() {
  retrieve_identity
  printf 'recovery_identity=verified\n'
  printf 'keychain_service=%s\n' "$KP_RECOVERY_KEYCHAIN_SERVICE"
  printf 'recovery_recipient=%s\n' "$KP_PUBLIC_RECIPIENT"
}

create_identity() {
  KP_EXISTING_IDENTITY="$KP_IDENTITY_TEMP_DIR/existing-identity.txt"
  if "$KP_SECURITY_BIN" find-generic-password \
    -a "$KP_RECOVERY_KEYCHAIN_ACCOUNT" \
    -s "$KP_RECOVERY_KEYCHAIN_SERVICE" \
    -w > "$KP_EXISTING_IDENTITY" 2>/dev/null; then
    chmod 600 "$KP_EXISTING_IDENTITY"
    validate_identity_file "$KP_EXISTING_IDENTITY"
    printf 'recovery_identity=preserved\n'
    printf 'keychain_service=%s\n' "$KP_RECOVERY_KEYCHAIN_SERVICE"
    printf 'recovery_recipient=%s\n' "$KP_PUBLIC_RECIPIENT"
    return
  fi

  KP_NEW_IDENTITY="$KP_IDENTITY_TEMP_DIR/new-identity.txt"
  "$KP_AGE_KEYGEN_BIN" -o "$KP_NEW_IDENTITY" >/dev/null 2>&1 \
    || fail "could not generate an age identity"
  chmod 600 "$KP_NEW_IDENTITY"
  validate_identity_file "$KP_NEW_IDENTITY"
  KP_GENERATED_RECIPIENT="$KP_PUBLIC_RECIPIENT"

  KP_PRIVATE_IDENTITY="$(grep -E '^AGE-SECRET-KEY-1[0-9A-Z]+$' "$KP_NEW_IDENTITY")"
  [ -n "$KP_PRIVATE_IDENTITY" ] || fail "generated age identity is empty"
  "$KP_SECURITY_BIN" add-generic-password \
    -a "$KP_RECOVERY_KEYCHAIN_ACCOUNT" \
    -s "$KP_RECOVERY_KEYCHAIN_SERVICE" \
    -w "$KP_PRIVATE_IDENTITY" >/dev/null 2>&1 \
    || fail "could not store the recovery identity without replacing an existing item"
  unset KP_PRIVATE_IDENTITY

  retrieve_identity
  [ "$KP_PUBLIC_RECIPIENT" = "$KP_GENERATED_RECIPIENT" ] \
    || fail "stored Keychain identity does not match the generated recipient"
  printf 'recovery_identity=created\n'
  printf 'keychain_service=%s\n' "$KP_RECOVERY_KEYCHAIN_SERVICE"
  printf 'recovery_recipient=%s\n' "$KP_PUBLIC_RECIPIENT"
}

[ "$#" -eq 1 ] || usage
require_runtime
case "$1" in
  create) create_identity ;;
  verify) verify_identity ;;
  *) usage ;;
esac
