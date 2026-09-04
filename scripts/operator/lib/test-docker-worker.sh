#!/usr/bin/env bash
# Daemon-free, host-free tests for lib/docker-worker.sh. Mocks `ssh` and asserts
# the exact target, launcher, and DOCKER_HOST prefix each profile emits. Proves
# the .140 default behaviour is preserved and .105 routes through `wsl -e bash`
# with the native socket. Contacts no real host.
set -euo pipefail
KP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KP_LIB="$KP_DIR/docker-worker.sh"
KP_FAILURES=0
ok()  { printf 'PASS  %s\n' "$*"; }
bad() { printf 'FAIL  %s\n' "$*"; KP_FAILURES=$((KP_FAILURES + 1)); }

KP_TMP="$(mktemp -d)"; trap 'rm -rf "$KP_TMP"' EXIT
cat > "$KP_TMP/ssh" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$*" > "$KP_SSH_ARGS"
cat > "$KP_SSH_STDIN"
MOCK
chmod +x "$KP_TMP/ssh"
export KP_SSH_ARGS="$KP_TMP/args" KP_SSH_STDIN="$KP_TMP/stdin"

# Run kp_worker_run under a chosen worker and capture what the mock ssh received.
run_case() { # $1 KP_DOCKER_WORKER (empty = default)
  (
    PATH="$KP_TMP:$PATH"
    if [ -n "$1" ]; then export KP_DOCKER_WORKER="$1"; fi
    unset KP_DOCKER_WORKER_PROFILE KP_WORKER_LAUNCH KP_WORKER_DOCKER_HOST 2>/dev/null || true
    # shellcheck disable=SC1090
    . "$KP_LIB"
    kp_worker_run <<'SH'
docker ps -q
SH
  )
}

assert_contains() { # label file needle
  if grep -qF -- "$3" "$2"; then ok "$1"; else bad "$1 (missing: $3)"; fi
}
assert_absent() { # label file needle
  if grep -qF -- "$3" "$2"; then bad "$1 (unexpected: $3)"; else ok "$1"; fi
}

printf '== profile resolution ==\n'
# shellcheck disable=SC1090
prof() { ( if [ -n "$1" ]; then export KP_DOCKER_WORKER="$1"; fi; unset KP_DOCKER_WORKER_PROFILE; . "$KP_LIB"; kp_worker_profile ); }
[ "$(prof '')" = mac140 ]                        && ok "default -> mac140"        || bad "default -> mac140 (got $(prof ''))"
[ "$(prof edierks@192.168.1.140)" = mac140 ]     && ok ".140 -> mac140"           || bad ".140 -> mac140"
[ "$(prof erikd@192.168.1.105)" = wsl105 ]       && ok ".105 -> wsl105"           || bad ".105 -> wsl105"
[ "$(prof someone@10.0.0.9)" = mac140 ]          && ok "unknown -> mac140 (safe)" || bad "unknown -> mac140"

printf '\n== mac140 (default) emits the Colima socket over direct bash ==\n'
run_case '' >/dev/null 2>&1
assert_contains "mac140 ssh target"   "$KP_SSH_ARGS"  "edierks@192.168.1.140"
assert_contains "mac140 launcher"     "$KP_SSH_ARGS"  "bash -s"
assert_absent   "mac140 not wsl"      "$KP_SSH_ARGS"  "wsl -e"
assert_contains "mac140 DOCKER_HOST"  "$KP_SSH_STDIN" "export DOCKER_HOST=unix:///Volumes/DockerExternal/KingPhisher-Phoenix/colima/kingphisher/docker.sock"
assert_contains "mac140 script body"  "$KP_SSH_STDIN" "docker ps -q"

printf '\n== wsl105 routes through wsl -e bash with the native socket ==\n'
run_case 'erikd@192.168.1.105' >/dev/null 2>&1
assert_contains "wsl105 ssh target"   "$KP_SSH_ARGS"  "erikd@192.168.1.105"
assert_contains "wsl105 launcher"     "$KP_SSH_ARGS"  "wsl -e bash -s"
assert_absent   "wsl105 no DOCKER_HOST" "$KP_SSH_STDIN" "DOCKER_HOST"
assert_contains "wsl105 script body"  "$KP_SSH_STDIN" "docker ps -q"

printf '\n== local profile: runs on THIS host, no ssh ==\n'
[ "$(prof local)" = local ]      && ok "local -> local"        || bad "local -> local (got $(prof local))"
[ "$(prof localhost)" = local ]  && ok "localhost -> local"    || bad "localhost -> local"
# is_local predicate
( export KP_DOCKER_WORKER=local; . "$KP_LIB"; kp_worker_is_local ) && ok "is_local true for local" || bad "is_local true for local"
if ( export KP_DOCKER_WORKER=erikd@192.168.1.105; . "$KP_LIB"; kp_worker_is_local ); then bad "is_local false for .105"; else ok "is_local false for .105"; fi
# local run executes locally and does NOT invoke ssh
rm -f "$KP_SSH_ARGS"
LOCAL_OUT="$(
  PATH="$KP_TMP:$PATH" KP_DOCKER_WORKER=local bash -c '
    unset KP_DOCKER_WORKER_PROFILE KP_WORKER_LAUNCH KP_WORKER_DOCKER_HOST 2>/dev/null || true
    # shellcheck disable=SC1090
    . "'"$KP_LIB"'"
    printf "echo LOCALOK\n" | kp_worker_run
  ' 2>/dev/null
)"
printf '%s' "$LOCAL_OUT" | grep -qx LOCALOK && ok "local run executes locally" || bad "local run executes locally (got: $LOCAL_OUT)"
[ ! -f "$KP_SSH_ARGS" ] && ok "local run did not invoke ssh" || bad "local run invoked ssh"

printf '\n== summary ==\n'
if [ "$KP_FAILURES" -eq 0 ]; then printf 'ALL DOCKER-WORKER TESTS PASSED\n'; exit 0
else printf '%d TEST(S) FAILED\n' "$KP_FAILURES"; exit 1; fi
