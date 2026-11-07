#!/usr/bin/env bash
# Select Docker CLI plugins from configured Debian/Ubuntu package sources.
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

linux_docker_cli_package() {
  local package status candidate
  # Preserve an existing provider before considering a new package candidate.
  for package in "$@"; do
    status="$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null)" || status=""
    if [ "$status" = "install ok installed" ]; then
      printf '%s\n' "$package"
      return 0
    fi
  done
  for package in "$@"; do
    candidate="$(LC_ALL=C apt-cache policy "$package" 2>/dev/null \
      | awk '$1 == "Candidate:" { print $2; exit }')" || candidate=""
    if [ -n "$candidate" ] && [ "$candidate" != "(none)" ]; then
      printf '%s\n' "$package"
      return 0
    fi
  done
  return 1
}

linux_compose_package() {
  linux_docker_cli_package docker-compose-plugin docker-compose-v2
}

linux_buildx_package() {
  linux_docker_cli_package docker-buildx-plugin docker-buildx
}

# --no-remove does not prevent dependencies from installing/upgrading an engine.
# Before a CLI-only repair, inspect the same plugin transaction in C locale.
# Unknown output is a refusal, never permission to change an existing provider.
linux_cli_apt_plan_is_safe() {
  local privilege plan
  privilege="$1"
  shift
  [ "$#" -gt 0 ] || return 1
  if [ -n "$privilege" ]; then
    plan="$(LC_ALL=C bounded 120 "$privilege" apt-get --simulate --no-remove install -y "$@" 2>&1)" || return 1
  else
    plan="$(LC_ALL=C bounded 120 apt-get --simulate --no-remove install -y "$@" 2>&1)" || return 1
  fi
  [ "${#plan}" -le 1048576 ] || return 1
  printf '%s\n' "$plan" | LC_ALL=C awk '
    function engine_package(package) {
      sub(/:.*/, "", package)
      if (package ~ /^(docker-buildx|docker-buildx-plugin|docker-compose-plugin|docker-compose-v2)$/) return 0
      return package ~ /^(docker|containerd|runc|moby|podman|cri-o|crun|buildkit)/
    }
    function invalid() { bad = 1; exit 1 }
    /^[[:space:]]*$/ { next }
    /^(Reading package lists|Building dependency tree|Reading state information)[.][.][.]( Done)?$/ { section = 0; next }
    /^(The following additional packages will be installed:|The following NEW packages will be installed:|The following packages will be upgraded:|Suggested packages:|Recommended packages:|The following packages were automatically installed and are no longer required:)$/ { section = 1; next }
    /^  [a-z0-9][a-z0-9+.:~-]*([[:space:]]+[a-z0-9][a-z0-9+.:~-]*)*[[:space:]]*$/ {
      if (!section) invalid()
      next
    }
    /^Use \047apt autoremove\047 to remove them[.]$/ { section = 0; next }
    /^[a-z0-9][a-z0-9+.:-]* is already the newest version \([^()]+\)[.]$/ { section = 0; next }
    /^[a-z0-9][a-z0-9+.:-]* set to manually installed[.]$/ { section = 0; next }
    /^Need to get [0-9.,]+ [A-Za-z]+(\/[0-9.,]+ [A-Za-z]+)? of archives[.]$/ { section = 0; next }
    /^After this operation, [0-9.,]+ [A-Za-z]+ (of additional disk space will be used|disk space will be freed)[.]$/ { section = 0; next }
    /^[0-9]+ upgraded, [0-9]+ newly installed, 0 to remove and [0-9]+ not upgraded[.]$/ {
      if (summary++) invalid()
      expected = $1 + $3
      section = 0
      next
    }
    /^(Inst|Conf) / {
      section = 0
      if ($2 !~ /^[a-z0-9][a-z0-9+.-]*(:[a-z0-9][a-z0-9-]*)?$/ || engine_package($2)) invalid()
      if ($1 == "Inst") {
        if ($0 !~ /^Inst [^ ]+ (\[[^][]+\] )?\([^()]+\)( \[[^][]+\])?$/ || installed[$2]++) invalid()
        install_count++
      } else {
        if ($0 !~ /^Conf [^ ]+ \([^()]+\)$/ || configured[$2]++) invalid()
        configure_count++
      }
      next
    }
    { invalid() }
    END {
      if (bad || summary != 1 || install_count != expected || configure_count != install_count) exit 1
      for (package in installed) if (!configured[package]) exit 1
      for (package in configured) if (!installed[package]) exit 1
    }
  '
}
