#!/usr/bin/env bash
# Stop everything start-console.sh started, and return Docker to "only .140 runs".
set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)" || exit 1
RUN=.dep010-run
for p in supervisor forward; do
  [ -f "$RUN/$p.pid" ] && { kill "$(cat "$RUN/$p.pid")" 2>/dev/null; rm -f "$RUN/$p.pid"; echo "stopped $p"; }
done
pkill -f "scripts/supervisor.py" 2>/dev/null
echo "stopping local containers (preserved, not removed)"
docker stop kp-e2e-postgres phishing-awareness-platform-redis-1 \
  phishing-awareness-platform-mailpit-1 phishing-awareness-platform-mock-idp-1 \
  phishing-awareness-platform-mock-graph-1 phishing-awareness-platform-mock-ai-1 \
  phishing-awareness-platform-otel-collector-1 >/dev/null 2>&1
echo "done - local Docker is idle; .140 is unaffected"
