#!/usr/bin/env bash
# Stop everything start-console.sh started. Docker on the worker is left running
# (it is the project's only engine); the disposable console database container is
# stopped but preserved, never removed. The worker defaults to .140 macOS/Colima;
# set KP_DOCKER_WORKER=erikd@192.168.1.105 to target the .105 WSL2 worker.
set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)" || exit 1
RUN=.dep010-run
# shellcheck source=scripts/operator/lib/docker-worker.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/docker-worker.sh"
for p in supervisor tunnel; do
  if [ -f "$RUN/$p.pid" ]; then
    kill "$(cat "$RUN/$p.pid")" 2>/dev/null
    rm -f "$RUN/$p.pid"
    echo "stopped $p"
  fi
done
pkill -f "scripts/supervisor.py" 2>/dev/null
echo "stopping the disposable console database on $(kp_worker_target) (preserved, not removed)"
kp_worker_run <<'SCRIPT' >/dev/null 2>&1
docker stop kp-console-postgres
SCRIPT
echo "done - no Docker ran on this Mac at any point"
