#!/usr/bin/env bash
# Static, daemon-free tests for the WSL2/.105 migration tooling. Safe to run on
# the macOS controller: it never contacts .105 or .140 and starts no container.
#
# Covers: bash syntax, shellcheck (when present), docker-compose.yml parseability,
# and a unit test of the restore engine guard with a mocked `docker`.
set -euo pipefail
KP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KP_ROOT="$(cd "$KP_DIR/../../.." && pwd)"
KP_SCRIPTS=(preflight-105.sh restore-state-wsl2.sh test-tooling.sh)
KP_FAILURES=0
ok()   { printf 'PASS  %s\n' "$*"; }
bad()  { printf 'FAIL  %s\n' "$*"; KP_FAILURES=$((KP_FAILURES + 1)); }

printf '== bash -n (syntax) ==\n'
for s in "${KP_SCRIPTS[@]}"; do
  if bash -n "$KP_DIR/$s"; then ok "syntax $s"; else bad "syntax $s"; fi
done

printf '\n== shellcheck ==\n'
if command -v shellcheck >/dev/null 2>&1; then
  for s in "${KP_SCRIPTS[@]}"; do
    if shellcheck -S error "$KP_DIR/$s"; then ok "shellcheck $s"; else bad "shellcheck $s"; fi
  done
else
  printf 'skip  shellcheck not installed\n'
fi

printf '\n== docker-compose.yml parses ==\n'
if python3 -c "import yaml,sys; yaml.safe_load(open('$KP_ROOT/docker-compose.yml'))"; then
  ok "compose YAML parse"
else
  bad "compose YAML parse"
fi

printf '\n== restore engine guard (mocked docker) ==\n'
# Extract the guard function so it can be exercised without running the restore.
KP_TMP="$(mktemp -d)"
trap 'rm -rf "$KP_TMP"' EXIT
awk '/^require_wsl2_native_engine\(\) \{/{p=1} p{print} p&&/^\}/{exit}' \
  "$KP_DIR/restore-state-wsl2.sh" > "$KP_TMP/guard.sh"

# Mock docker: honours only `docker info`; identity comes from $KP_MOCK_IDENTITY.
cat > "$KP_TMP/docker" <<'MOCK'
#!/usr/bin/env bash
if [ "${1:-}" = info ]; then
  case " $* " in
    *--format*) printf '%s\n' "${KP_MOCK_IDENTITY:-}";;
    *) exit 0;;
  esac
  exit 0
fi
exit 0
MOCK
chmod +x "$KP_TMP/docker"

run_guard() { # $1 identity  -> echoes the guard's exit code
  PATH="$KP_TMP:$PATH" KP_MOCK_IDENTITY="$1" GUARD="$KP_TMP/guard.sh" \
    bash -c '
      KP_MAC_ENGINE_NAME=colima-kingphisher
      fail() { printf "guard-reject: %s\n" "$*" >&2; exit 1; }
      # shellcheck disable=SC1090
      . "$GUARD"
      require_wsl2_native_engine
    ' >/dev/null 2>&1
  echo $?
}

expect() { # $1 label  $2 identity  $3 expected-rc
  rc="$(run_guard "$2")"
  if [ "$rc" = "$3" ]; then ok "guard $1 (rc=$rc)"; else bad "guard $1 (rc=$rc, want $3)"; fi
}

expect "accepts wsl2 linux/x86_64" 'docker-desktop|linux|x86_64|/var/lib/docker' 0
expect "accepts amd64 alias"       'wsl-engine|linux|amd64|/var/lib/docker'      0
expect "rejects .140 colima"       'colima-kingphisher|linux|aarch64|/var/lib/docker' 1
expect "rejects arm64 arch"        'some-engine|linux|aarch64|/var/lib/docker'   1
expect "rejects non-linux"         'docker-desktop|windows|x86_64|C:\\ProgramData' 1

printf '\n== summary ==\n'
if [ "$KP_FAILURES" -eq 0 ]; then
  printf 'ALL TOOLING TESTS PASSED\n'; exit 0
else
  printf '%d TEST(S) FAILED\n' "$KP_FAILURES"; exit 1
fi
