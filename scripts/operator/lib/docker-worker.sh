#!/usr/bin/env bash
# Shared Docker-worker abstraction so operator tooling is not hardcoded to the
# .140 macOS/Colima host. Source this; do not execute it.
#
#   . "$(dirname "$0")/../lib/docker-worker.sh"
#   kp_worker_run <<'SH'
#     docker ps
#   SH
#   ssh -N "$(kp_worker_target)" -L ...    # tunnels
#
# Selection is via KP_DOCKER_WORKER (an ssh target). The DEFAULT is the current
# .140 worker, so existing workflows are unchanged until an operator opts in with
#   KP_DOCKER_WORKER=erikd@192.168.1.105 ...
#
# Two profiles, auto-detected from the target (override with KP_DOCKER_WORKER_PROFILE):
#   mac140  - macOS/Colima: reach the project-isolated Colima socket over direct ssh.
#   wsl105  - Windows/WSL2:  ssh lands in cmd, so route through `wsl -e bash` and
#             use WSL2's native default socket.

KP_DOCKER_WORKER="${KP_DOCKER_WORKER:-edierks@192.168.1.140}"
KP_DOCKER_WORKER_PROFILE="${KP_DOCKER_WORKER_PROFILE:-auto}"
KP_COLIMA_SOCK='unix:///Volumes/DockerExternal/KingPhisher-Phoenix/colima/kingphisher/docker.sock'

kp_worker_resolve() {
  case "$KP_DOCKER_WORKER_PROFILE" in
    mac140|wsl105|local) : ;;
    auto)
      case "$KP_DOCKER_WORKER" in
        local|localhost)        KP_DOCKER_WORKER_PROFILE=local ;;
        *192.168.1.105*|*@*105) KP_DOCKER_WORKER_PROFILE=wsl105 ;;
        *)                      KP_DOCKER_WORKER_PROFILE=mac140 ;;  # safe default = current behavior
      esac ;;
    *) printf 'docker-worker: unknown KP_DOCKER_WORKER_PROFILE=%s\n' "$KP_DOCKER_WORKER_PROFILE" >&2; return 2 ;;
  esac
  case "$KP_DOCKER_WORKER_PROFILE" in
    mac140)
      KP_WORKER_LAUNCH="${KP_WORKER_LAUNCH:-bash -s}"
      KP_WORKER_DOCKER_HOST="${KP_WORKER_DOCKER_HOST-$KP_COLIMA_SOCK}"
      ;;
    wsl105)
      KP_WORKER_LAUNCH="${KP_WORKER_LAUNCH:-wsl -e bash -s}"
      KP_WORKER_DOCKER_HOST="${KP_WORKER_DOCKER_HOST-}"   # native default socket in WSL2
      ;;
    local)
      # Docker is on THIS host: run scripts directly, no ssh, native socket.
      KP_WORKER_LAUNCH="${KP_WORKER_LAUNCH:-bash -s}"
      KP_WORKER_DOCKER_HOST="${KP_WORKER_DOCKER_HOST-}"
      ;;
  esac
}

# True when the worker is this host (no ssh, services reachable on localhost).
kp_worker_is_local() {
  kp_worker_resolve || return
  [ "$KP_DOCKER_WORKER_PROFILE" = local ]
}

# Echo the ssh target (for tunnels / plain ssh). Resolves first so a bad profile
# fails loudly.
kp_worker_target() {
  kp_worker_resolve || return
  printf '%s' "$KP_DOCKER_WORKER"
}

# Echo the resolved profile name.
kp_worker_profile() {
  kp_worker_resolve || return
  printf '%s' "$KP_DOCKER_WORKER_PROFILE"
}

# Run a bash script (read from stdin) on the worker with the correct docker
# environment. The script is prefixed with the profile's DOCKER_HOST export when
# one applies (Colima socket on .140; nothing on WSL2 native).
kp_worker_run() {
  kp_worker_resolve || return
  # KP_WORKER_LAUNCH is intentionally word-split into remote-command args.
  # shellcheck disable=SC2086
  if [ "$KP_DOCKER_WORKER_PROFILE" = local ]; then
    # Run the script on THIS host; no ssh, native docker socket.
    {
      if [ -n "${KP_WORKER_DOCKER_HOST:-}" ]; then
        printf 'export DOCKER_HOST=%s\n' "$KP_WORKER_DOCKER_HOST"
      fi
      cat
    } | $KP_WORKER_LAUNCH
  else
    {
      if [ -n "${KP_WORKER_DOCKER_HOST:-}" ]; then
        printf 'export DOCKER_HOST=%s\n' "$KP_WORKER_DOCKER_HOST"
      fi
      cat
    } | ssh -o BatchMode=yes "$KP_DOCKER_WORKER" $KP_WORKER_LAUNCH
  fi
}
