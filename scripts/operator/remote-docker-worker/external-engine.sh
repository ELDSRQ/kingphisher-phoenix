#!/bin/bash
# Operate the project-isolated Docker engine on the designated remote Mac.
#
# The Colima VM, cache, Docker client metadata, and socket are rooted on the
# external volume.  Docker Desktop is deliberately not selected or modified:
# it is a separate shared engine that contains unrelated workloads.

set -euo pipefail

KP_EXTERNAL_VOLUME=/Volumes/DockerExternal
KP_EXTERNAL_VOLUME_UUID=FD7BE277-8CB4-3ADA-8CA2-11F8EBBBADF4
KP_EXTERNAL_ROOT="$KP_EXTERNAL_VOLUME/KingPhisher-Phoenix"
KP_EXTERNAL_MIN_FREE_GIB="${KP_EXTERNAL_MIN_FREE_GIB:-100}"
KP_COLIMA_PROFILE=kingphisher
KP_COLIMA_HOME="$KP_EXTERNAL_ROOT/colima"
KP_COLIMA_CACHE_HOME="$KP_EXTERNAL_ROOT/colima-cache"
KP_PROJECT_DOCKER_CONFIG="$KP_EXTERNAL_ROOT/docker-client"
KP_PROJECT_SOURCE=/Users/edierks/Projects/kingphisher-phoenix
KP_EXPECTED_AMBIENT_CONTEXT=desktop-linux
KP_DOCKER_SOCKET="$KP_COLIMA_HOME/$KP_COLIMA_PROFILE/docker.sock"
KP_COLIMA_BIN=/opt/homebrew/bin/colima
KP_DOCKER_DESKTOP_CLI_PLUGIN_DIR='/Applications/Docker.app/Contents/Resources/cli-plugins'
KP_HOMEBREW_CLI_PLUGIN_DIR='/opt/homebrew/lib/docker/cli-plugins'
KP_DOCKER_CLI_PLUGIN_DIR="$KP_DOCKER_DESKTOP_CLI_PLUGIN_DIR"
if { [ ! -x "$KP_DOCKER_CLI_PLUGIN_DIR/docker-compose" ] \
  || [ ! -x "$KP_DOCKER_CLI_PLUGIN_DIR/docker-buildx" ]; } \
  && [ -x "$KP_HOMEBREW_CLI_PLUGIN_DIR/docker-compose" ] \
  && [ -x "$KP_HOMEBREW_CLI_PLUGIN_DIR/docker-buildx" ]; then
  KP_DOCKER_CLI_PLUGIN_DIR="$KP_HOMEBREW_CLI_PLUGIN_DIR"
fi

fail() {
  printf 'EXTERNAL ENGINE BLOCKED: %s\n' "$*" >&2
  printf 'Docker Desktop is not a fallback. Preserve both engines and all project state.\n' >&2
  exit 1
}

usage() {
  printf 'usage: %s {preflight|start|status|env|docker|compose|run} [arguments...]\n' "$0" >&2
  exit 2
}

positive_integer() {
  case "$1" in
    ''|*[!0-9]*|0) return 1 ;;
    *) return 0 ;;
  esac
}

diskutil_value() {
  /usr/sbin/diskutil info "$KP_EXTERNAL_VOLUME" \
    | /usr/bin/awk -F: -v key="$1" '$1 ~ "^[[:space:]]*" key "[[:space:]]*$" {sub(/^[[:space:]]*/, "", $2); print $2}'
}

require_external_volume() {
  [ "$(uname -s)" = Darwin ] || fail "the external worker helper supports macOS only"
  [ "$(uname -m)" = arm64 ] \
    || fail "the external worker must be native Apple Silicon; Rosetta and x86 hosts are unsupported"
  positive_integer "$KP_EXTERNAL_MIN_FREE_GIB" \
    || fail "KP_EXTERNAL_MIN_FREE_GIB must be a positive whole number"
  [ -d "$KP_EXTERNAL_VOLUME" ] || fail "$KP_EXTERNAL_VOLUME is not mounted"
  [ -w "$KP_EXTERNAL_VOLUME" ] || fail "$KP_EXTERNAL_VOLUME is not writable"

  KP_MOUNT_POINT="$(diskutil_value 'Mount Point')"
  KP_VOLUME_UUID_ACTUAL="$(diskutil_value 'Volume UUID')"
  KP_VOLUME_READ_ONLY="$(diskutil_value 'Volume Read-Only')"
  [ "$KP_MOUNT_POINT" = "$KP_EXTERNAL_VOLUME" ] \
    || fail "external mount identity is wrong: expected $KP_EXTERNAL_VOLUME, got ${KP_MOUNT_POINT:-missing}"
  [ "$KP_VOLUME_UUID_ACTUAL" = "$KP_EXTERNAL_VOLUME_UUID" ] \
    || fail "external volume UUID is wrong: expected $KP_EXTERNAL_VOLUME_UUID, got ${KP_VOLUME_UUID_ACTUAL:-missing}"
  [ "$KP_VOLUME_READ_ONLY" = No ] || fail "$KP_EXTERNAL_VOLUME is read-only"

  KP_FREE_KIB="$(df -Pk "$KP_EXTERNAL_VOLUME" | awk 'NR == 2 {print $4}')"
  positive_integer "$KP_FREE_KIB" || fail "external free-space evidence is malformed"
  KP_REQUIRED_KIB=$((KP_EXTERNAL_MIN_FREE_GIB * 1024 * 1024))
  [ "$KP_FREE_KIB" -ge "$KP_REQUIRED_KIB" ] \
    || fail "$KP_EXTERNAL_VOLUME has less than $KP_EXTERNAL_MIN_FREE_GIB GiB free"
}

require_external_layout() {
  for KP_PATH in \
    "$KP_EXTERNAL_ROOT" \
    "$KP_COLIMA_HOME" \
    "$KP_COLIMA_CACHE_HOME" \
    "$KP_PROJECT_DOCKER_CONFIG"; do
    [ -d "$KP_PATH" ] || fail "required external directory is absent: $KP_PATH"
    [ ! -L "$KP_PATH" ] || fail "external engine path must not be a symbolic link: $KP_PATH"
    case "$(cd "$KP_PATH" && pwd -P)" in
      "$KP_EXTERNAL_VOLUME"/*) ;;
      *) fail "external engine path escaped $KP_EXTERNAL_VOLUME: $KP_PATH" ;;
    esac
  done
}

require_project_source() {
  [ -d "$KP_PROJECT_SOURCE" ] && [ ! -L "$KP_PROJECT_SOURCE" ] \
    || fail "canonical project source is missing or symbolic: $KP_PROJECT_SOURCE"
  [ -d "$KP_PROJECT_SOURCE/.git" ] && [ ! -L "$KP_PROJECT_SOURCE/.git" ] \
    || fail "canonical project source has no regular .git directory: $KP_PROJECT_SOURCE"
  KP_CANONICAL_HELPER="$KP_PROJECT_SOURCE/scripts/operator/remote-docker-worker/external-engine.sh"
  [ -x "$KP_CANONICAL_HELPER" ] && [ ! -L "$KP_CANONICAL_HELPER" ] \
    || fail "canonical project source is incomplete: external worker helper is missing or symbolic"
}

require_docker_credential_policy() {
  KP_DOCKER_CLIENT_CONFIG="$KP_PROJECT_DOCKER_CONFIG/config.json"
  [ -f "$KP_DOCKER_CLIENT_CONFIG" ] || fail "project Docker client configuration is missing"
  [ ! -L "$KP_DOCKER_CLIENT_CONFIG" ] || fail "project Docker client configuration must not be a symbolic link"
  command -v docker-credential-osxkeychain >/dev/null 2>&1 \
    || fail "macOS Keychain Docker credential helper is unavailable"
  [ -x "$KP_DOCKER_CLI_PLUGIN_DIR/docker-compose" ] \
    || fail "reviewed Docker Compose CLI plugin is unavailable"
  [ -x "$KP_DOCKER_CLI_PLUGIN_DIR/docker-buildx" ] \
    || fail "reviewed Docker Buildx CLI plugin is unavailable"
  /usr/bin/python3 -c '
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
if data.get("credsStore") != "osxkeychain":
    raise SystemExit(1)
if data.get("cliPluginsExtraDirs") != [sys.argv[2]]:
    raise SystemExit(1)
for value in data.get("auths", {}).values():
    if isinstance(value, dict) and any(key.lower() in {"auth", "identitytoken", "registrytoken"} for key in value):
        raise SystemExit(1)
' "$KP_DOCKER_CLIENT_CONFIG" "$KP_DOCKER_CLI_PLUGIN_DIR" \
    || fail "Docker client must use Keychain credentials and the reviewed external Compose plugin path; inline registry tokens are prohibited"
}

require_profile_config() {
  KP_PROFILE_CONFIG="$KP_COLIMA_HOME/$KP_COLIMA_PROFILE/colima.yaml"
  [ -f "$KP_PROFILE_CONFIG" ] || fail "Colima profile configuration is missing from the external volume"
  [ ! -L "$KP_PROFILE_CONFIG" ] || fail "Colima profile configuration must not be a symbolic link"
  grep -Eq '^autoActivate:[[:space:]]+false[[:space:]]*$' "$KP_PROFILE_CONFIG" \
    || fail "Colima profile must disable automatic Docker-context activation"
  grep -Eq '^arch:[[:space:]]+aarch64[[:space:]]*$' "$KP_PROFILE_CONFIG" \
    || fail "Colima profile architecture is not native aarch64"
  grep -Eq '^vmType:[[:space:]]+vz[[:space:]]*$' "$KP_PROFILE_CONFIG" \
    || fail "Colima profile must use the macOS virtualization framework"
  grep -Eq '^rosetta:[[:space:]]+false[[:space:]]*$' "$KP_PROFILE_CONFIG" \
    || fail "Colima profile unexpectedly enables Rosetta"
  grep -Eq '^binfmt:[[:space:]]+false[[:space:]]*$' "$KP_PROFILE_CONFIG" \
    || fail "Colima profile unexpectedly enables foreign-architecture binfmt"
  /usr/bin/awk '
    $1 == "kubernetes:" {in_kubernetes = 1; next}
    in_kubernetes && $1 == "enabled:" {found = 1; disabled = ($2 == "false"); exit}
    END {exit(found && disabled ? 0 : 1)}
  ' "$KP_PROFILE_CONFIG" \
    || fail "Colima profile unexpectedly enables Kubernetes"
  ! grep -Eq '^[[:space:]]*writable:[[:space:]]+true[[:space:]]*$' "$KP_PROFILE_CONFIG" \
    || fail "Colima profile must not expose a writable host mount"
  /usr/bin/awk -v source="$KP_PROJECT_SOURCE" '
    $1 == "-" && $2 == "location:" && $3 == source {matched = 1; next}
    matched && $1 == "writable:" {exit($2 == "false" ? 0 : 1)}
    END {if (!matched) exit 1}
  ' "$KP_PROFILE_CONFIG" \
    || fail "canonical source must be mounted into Colima read-only"
}

colima() {
  env \
    COLIMA_HOME="$KP_COLIMA_HOME" \
    COLIMA_CACHE_HOME="$KP_COLIMA_CACHE_HOME" \
    DOCKER_CONFIG="$KP_PROJECT_DOCKER_CONFIG" \
    "$KP_COLIMA_BIN" "$@"
}

project_environment() {
  env -u DOCKER_CONTEXT \
    DOCKER_HOST="unix://$KP_DOCKER_SOCKET" \
    DOCKER_CONFIG="$KP_PROJECT_DOCKER_CONFIG" \
    COMPOSE_PROJECT_NAME=phishing-awareness-platform \
    "$@"
}

project_docker() {
  project_environment docker "$@"
}

ambient_context() {
  env -u DOCKER_CONTEXT -u DOCKER_HOST -u DOCKER_CONFIG docker context show
}

require_project_engine() {
  require_external_volume
  require_external_layout
  require_project_source
  require_profile_config
  require_docker_credential_policy
  [ -S "$KP_DOCKER_SOCKET" ] && [ ! -L "$KP_DOCKER_SOCKET" ] \
    || fail "project Docker socket is absent or symbolic: $KP_DOCKER_SOCKET"
  project_docker info >/dev/null 2>&1 || fail "project Docker engine is not reachable"
  KP_ENGINE_IDENTITY="$(project_docker info --format '{{.Name}}|{{.Architecture}}|{{.DockerRootDir}}')"
  [ "$KP_ENGINE_IDENTITY" = "colima-$KP_COLIMA_PROFILE|aarch64|/var/lib/docker" ] \
    || fail "unexpected project engine identity: $KP_ENGINE_IDENTITY"
  KP_AMBIENT_CONTEXT="$(ambient_context)"
  [ "$KP_AMBIENT_CONTEXT" = "$KP_EXPECTED_AMBIENT_CONTEXT" ] \
    || fail "ambient Docker context must remain $KP_EXPECTED_AMBIENT_CONTEXT, got $KP_AMBIENT_CONTEXT"
}

preflight() {
  require_project_engine
  project_docker compose version >/dev/null 2>&1 || fail "Docker Compose plugin is unavailable"
  printf '%s\n' \
    "qualification=passed" \
    "worker_host=$(hostname)" \
    "worker_architecture=$(uname -m)" \
    "external_volume=$KP_EXTERNAL_VOLUME" \
    "external_volume_uuid=$KP_VOLUME_UUID_ACTUAL" \
    "external_free_kib=$KP_FREE_KIB" \
    "colima_home=$KP_COLIMA_HOME" \
    "colima_profile=$KP_COLIMA_PROFILE" \
    "docker_socket=$KP_DOCKER_SOCKET" \
    "docker_engine=colima-$KP_COLIMA_PROFILE" \
    'docker_architecture=aarch64' \
    'docker_root=/var/lib/docker' \
    "canonical_source=$KP_PROJECT_SOURCE" \
    "ambient_context=$KP_AMBIENT_CONTEXT" \
    'rosetta_required=false' \
    'docker_desktop_fallback=prohibited'
}

start() {
  require_external_volume
  command -v docker >/dev/null 2>&1 || fail "Docker CLI is not installed"
  [ -x "$KP_COLIMA_BIN" ] || fail "Colima is not installed at $KP_COLIMA_BIN"
  /usr/bin/install -d -m 700 \
    "$KP_EXTERNAL_ROOT" \
    "$KP_COLIMA_HOME" \
    "$KP_COLIMA_CACHE_HOME" \
    "$KP_PROJECT_DOCKER_CONFIG"
  require_external_layout
  require_project_source
  if [ ! -f "$KP_PROJECT_DOCKER_CONFIG/config.json" ]; then
    /usr/bin/printf \
      '{"credsStore":"osxkeychain","cliPluginsExtraDirs":["%s"]}\n' \
      "$KP_DOCKER_CLI_PLUGIN_DIR" \
      > "$KP_PROJECT_DOCKER_CONFIG/config.json"
    /bin/chmod 600 "$KP_PROJECT_DOCKER_CONFIG/config.json"
  fi
  require_docker_credential_policy

  KP_CONTEXT_BEFORE="$(ambient_context)"
  if [ -f "$KP_COLIMA_HOME/$KP_COLIMA_PROFILE/colima.yaml" ]; then
    require_profile_config
    colima start "$KP_COLIMA_PROFILE" --activate=false
  else
    colima start "$KP_COLIMA_PROFILE" \
      --activate=false \
      --arch aarch64 \
      --vm-type vz \
      --vz-rosetta=false \
      --binfmt=false \
      --cpus 4 \
      --memory 6 \
      --disk 200 \
      --runtime docker \
      --kubernetes=false \
      --mount "$KP_PROJECT_SOURCE"
  fi
  KP_CONTEXT_AFTER="$(ambient_context)"
  [ "$KP_CONTEXT_BEFORE" = "$KP_CONTEXT_AFTER" ] \
    || fail "ambient Docker context changed from $KP_CONTEXT_BEFORE to $KP_CONTEXT_AFTER"
  preflight
}

case "${1:-}" in
  preflight)
    [ "$#" -eq 1 ] || usage
    preflight
    ;;
  start)
    [ "$#" -eq 1 ] || usage
    start
    ;;
  status)
    [ "$#" -eq 1 ] || usage
    require_external_volume
    require_external_layout
    require_profile_config
    colima status "$KP_COLIMA_PROFILE"
    ;;
  env)
    [ "$#" -eq 1 ] || usage
    require_project_engine
    printf '%s\n' 'unset DOCKER_CONTEXT'
    printf "export DOCKER_HOST='%s'\n" "unix://$KP_DOCKER_SOCKET"
    printf "export DOCKER_CONFIG='%s'\n" "$KP_PROJECT_DOCKER_CONFIG"
    printf "export COMPOSE_PROJECT_NAME='%s'\n" 'phishing-awareness-platform'
    printf "export KP_PROJECT_SOURCE='%s'\n" "$KP_PROJECT_SOURCE"
    ;;
  docker)
    shift
    require_project_engine
    project_docker "$@"
    ;;
  compose)
    shift
    require_project_engine
    project_docker compose "$@"
    ;;
  run)
    shift
    [ "$#" -gt 0 ] || usage
    require_project_engine
    cd "$KP_PROJECT_SOURCE"
    project_environment "$@"
    ;;
  *) usage ;;
esac
