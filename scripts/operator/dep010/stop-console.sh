#!/usr/bin/env bash
# Stop everything start-console.sh started. Docker on 192.168.1.140 is left
# running (it is the project's only engine); the disposable console database
# container is stopped but preserved, never removed.
set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)" || exit 1
RUN=.dep010-run
for p in supervisor tunnel; do
  if [ -f "$RUN/$p.pid" ]; then
    kill "$(cat "$RUN/$p.pid")" 2>/dev/null
    rm -f "$RUN/$p.pid"
    echo "stopped $p"
  fi
done
pkill -f "scripts/supervisor.py" 2>/dev/null
echo "stopping the disposable console database on 192.168.1.140 (preserved, not removed)"
ssh -o BatchMode=yes edierks@192.168.1.140 \
  "DOCKER_HOST=unix:///Volumes/DockerExternal/KingPhisher-Phoenix/colima/kingphisher/docker.sock docker stop kp-console-postgres" >/dev/null 2>&1
echo "done - no Docker ran on this Mac at any point"
