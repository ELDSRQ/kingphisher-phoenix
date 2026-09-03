#!/usr/bin/env bash
# Read-only controller-side qualification of the WSL2 Docker worker on .105.
#
# Mutates nothing on the target. It confirms SSH reachability, a native
# linux/x86_64 Docker engine inside WSL2, sufficient free space, the required
# toolchain, and a CLEAN target (no pre-existing project containers, volumes, or
# networks). This is the .105/WSL2 analogue of the macOS/.140 preflight.sh and
# never selects, changes, or stops any Docker resource.
set -euo pipefail

KP_WSL2_HOST="${KP_WSL2_HOST:-edierks@192.168.1.105}"
KP_MIN_FREE_GIB="${KP_MIN_FREE_GIB:-100}"
KP_PROJECT_NAME=phishing-awareness-platform
KP_MAC_ENGINE_NAME='colima-kingphisher'   # must NOT be the target

case "$KP_MIN_FREE_GIB" in
  ''|*[!0-9]*|0) printf 'error: KP_MIN_FREE_GIB must be a positive whole number\n' >&2; exit 2 ;;
esac

KP_SSH_OPTIONS=(
  -o BatchMode=yes
  -o ConnectTimeout=10
  -o StrictHostKeyChecking=yes
)

fail() { printf 'PREFLIGHT BLOCKED: %s\n' "$*" >&2; exit 1; }
pass() { printf 'pass\t%s\n' "$*"; }

# Local controller must not carry an ambient DOCKER_HOST that could shadow the
# remote engine facts we are about to read.
[ -z "${DOCKER_HOST:-}" ] || fail "DOCKER_HOST must be unset on the controller for a clean read"

# One remote read collects every fact; parsed locally so the target is touched
# exactly once and only with read-only commands.
KP_FACTS="$(ssh "${KP_SSH_OPTIONS[@]}" "$KP_WSL2_HOST" '
  set -eu
  printf "wsl_interop=%s\n" "${WSL_INTEROP:-}${WSL_DISTRO_NAME:-}"
  printf "uname_s=%s\n" "$(uname -s)"
  printf "uname_m=%s\n" "$(uname -m)"
  if command -v docker >/dev/null 2>&1; then
    printf "docker_cli=present\n"
    printf "engine_name=%s\n"  "$(docker info --format "{{.Name}}" 2>/dev/null || echo UNREACHABLE)"
    printf "engine_os=%s\n"    "$(docker info --format "{{.OSType}}" 2>/dev/null || echo unknown)"
    printf "engine_arch=%s\n"  "$(docker info --format "{{.Architecture}}" 2>/dev/null || echo unknown)"
    printf "engine_root=%s\n"  "$(docker info --format "{{.DockerRootDir}}" 2>/dev/null || echo unknown)"
    printf "proj_containers=%s\n" "$(docker ps -aq --filter label=com.docker.compose.project='"$KP_PROJECT_NAME"' 2>/dev/null | wc -l | tr -d " ")"
    printf "proj_volumes=%s\n"    "$(docker volume ls -q --filter label=com.docker.compose.project='"$KP_PROJECT_NAME"' 2>/dev/null | wc -l | tr -d " ")"
    printf "proj_networks=%s\n"   "$(docker network ls -q --filter label=com.docker.compose.project='"$KP_PROJECT_NAME"' 2>/dev/null | wc -l | tr -d " ")"
  else
    printf "docker_cli=absent\n"
  fi
  printf "uv=%s\n" "$(command -v uv >/dev/null 2>&1 && echo present || echo absent)"
  printf "py=%s\n" "$(python3 --version 2>/dev/null || echo absent)"
  printf "free_kib=%s\n" "$(df -Pk "$HOME" | awk "NR==2 {print \$4}")"
' 2>/dev/null)" || fail "cannot SSH to $KP_WSL2_HOST (enable OpenSSH into WSL2 and authorize the controller key)"

get() { printf '%s\n' "$KP_FACTS" | awk -F= -v k="$1" '$1==k {sub(/^[^=]*=/,""); print; exit}'; }

[ "$(get uname_s)" = Linux ] || fail "target is not Linux (got '$(get uname_s)'); expected WSL2 Ubuntu"
[ -n "$(get wsl_interop)" ] || printf 'warn\ttarget does not look like WSL2 (no WSL_* env); continuing\n' >&2
pass "reachable WSL2 Linux host: $KP_WSL2_HOST ($(get uname_m))"

[ "$(get docker_cli)" = present ] || fail "docker CLI absent on target; install Docker Engine inside WSL2 (Phase 1)"
KP_ENGINE_NAME="$(get engine_name)"
[ "$KP_ENGINE_NAME" != UNREACHABLE ] || fail "docker engine unreachable on target (is the daemon running / user in the docker group?)"
[ "$KP_ENGINE_NAME" != "$KP_MAC_ENGINE_NAME" ] || fail "target engine is the .140 Colima engine ($KP_MAC_ENGINE_NAME); refusing"
[ "$(get engine_os)" = linux ] || fail "docker engine OSType is '$(get engine_os)', expected linux"
case "$(get engine_arch)" in
  x86_64|amd64) pass "native linux/amd64 engine: $KP_ENGINE_NAME ($(get engine_root))" ;;
  *) fail "docker engine Architecture is '$(get engine_arch)', expected x86_64 for the .105 AMD64 lane" ;;
esac

for kind in containers volumes networks; do
  n="$(get "proj_$kind")"
  [ "${n:-0}" = 0 ] || fail "target already holds $n project $kind; restore requires a CLEAN engine"
done
pass "clean target: no pre-existing '$KP_PROJECT_NAME' containers/volumes/networks"

KP_FREE_KIB="$(get free_kib)"
case "$KP_FREE_KIB" in ''|*[!0-9]*) fail "could not read free space on target" ;; esac
KP_REQ_KIB=$((KP_MIN_FREE_GIB * 1024 * 1024))
[ "$KP_FREE_KIB" -ge "$KP_REQ_KIB" ] || fail "target free space $((KP_FREE_KIB/1024/1024)) GiB < required $KP_MIN_FREE_GIB GiB"
pass "free space $((KP_FREE_KIB/1024/1024)) GiB >= $KP_MIN_FREE_GIB GiB"

[ "$(get uv)" = present ] || printf 'warn\tuv not found on target; needed for the test/qualification gates (Phase 1)\n' >&2
[ "$(get py)" != absent ] || printf 'warn\tpython3 not found on target; needed for the qualification gates (Phase 1)\n' >&2

printf 'PREFLIGHT PASSED: %s is a clean, reachable linux/amd64 WSL2 Docker worker.\n' "$KP_WSL2_HOST"
