#!/usr/bin/env bash
# Select Compose v2 from already configured Debian/Ubuntu package sources.
# Source-only helper: never adds repositories, installs packages or touches data.

linux_docker_engine_present() {
  local package status
  for package in docker.io docker-ce; do
    status="$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null)" || status=""
    [ "$status" != "install ok installed" ] || return 0
  done
  command -v dockerd >/dev/null 2>&1
}

linux_docker_endpoint_is_local_default() {
  local endpoint
  # Docker gives an explicit context precedence over DOCKER_HOST. Do not let
  # a local-looking host hide a different or uninspectable selected context.
  [ -z "${DOCKER_CONTEXT:-}" ] || [ "$DOCKER_CONTEXT" = default ] || return 1
  if [ -z "${DOCKER_CONTEXT:-}" ] && [ -n "${DOCKER_HOST:-}" ]; then
    case "$DOCKER_HOST" in
      unix:///var/run/docker.sock|unix:///run/docker.sock) return 0 ;;
      *) return 1 ;;
    esac
  fi
  if ! command -v docker >/dev/null 2>&1; then
    [ -z "${DOCKER_CONTEXT:-}" ]
    return
  fi
  endpoint="$(bounded "$DOCKER_TIMEOUT_SECONDS" docker context inspect \
    --format '{{(index .Endpoints "docker").Host}}' 2>/dev/null)" || return 1
  case "$endpoint" in
    unix:///var/run/docker.sock|unix:///run/docker.sock) return 0 ;;
    *) return 1 ;;
  esac
}

linux_compose_package() {
  local package status candidate
  # Preserve an existing provider before considering a new package candidate.
  for package in docker-compose-plugin docker-compose-v2; do
    status="$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null)" || status=""
    if [ "$status" = "install ok installed" ]; then
      printf '%s\n' "$package"
      return 0
    fi
  done
  for package in docker-compose-plugin docker-compose-v2; do
    candidate="$(LC_ALL=C apt-cache policy "$package" 2>/dev/null \
      | awk '$1 == "Candidate:" { print $2; exit }')" || candidate=""
    if [ -n "$candidate" ] && [ "$candidate" != "(none)" ]; then
      printf '%s\n' "$package"
      return 0
    fi
  done
  return 1
}
