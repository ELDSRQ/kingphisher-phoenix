#!/usr/bin/env bash
# Conduct the live end-to-end campaign-lifecycle gate in one command:
# bring up the full local stack (operator API :8000, tracking API :8001, all
# workers) against the .140 infra over an SSH tunnel, run the E2E suite with the
# right authorization env, then tear the stack down again.
#
#   ./scripts/operator/e2e/run-e2e.sh
#
# DOCKER RUNS ONLY ON 192.168.1.140. This reuses start-console.sh, which starts
# a disposable console database on .140 and tunnels redis/mailpit/mock services;
# nothing runs on this Mac's Docker. The live .140 `kingphisher` database is
# never touched.
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

START=scripts/operator/dep010/start-console.sh
STOP=scripts/operator/dep010/stop-console.sh
[ -x "$START" ] && [ -x "$STOP" ] || { echo "error: start/stop-console scripts missing" >&2; exit 2; }

# The E2E console login uses the same password the running console is configured
# with, which start-console reads from .env.
CONSOLE_PW="$(python3 - <<'PY'
import pathlib
for line in pathlib.Path(".env").read_text().splitlines():
    line = line.strip()
    if line.startswith("KP_CONSOLE_PASSWORD="):
        v = line.split("=", 1)[1]
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"": v = v[1:-1]
        print(v); break
PY
)"
[ -n "$CONSOLE_PW" ] || { echo "error: KP_CONSOLE_PASSWORD not found in .env" >&2; exit 2; }

teardown() {
  echo "== tearing the E2E stack down =="
  "$STOP" || true
}
trap teardown EXIT

echo "== bringing up the full local stack (start-console) =="
"$START"

echo "== waiting for operator :8000 and tracking :8001 to be ready =="
for url in http://127.0.0.1:8000/readyz http://127.0.0.1:8001/readyz; do
  ready=""
  for _ in $(seq 1 60); do
    if curl -sf --max-time 2 "$url" >/dev/null 2>&1; then ready=1; break; fi
    sleep 1
  done
  [ -n "$ready" ] || { echo "error: $url did not become ready" >&2; exit 1; }
  echo "   ready: $url"
done

# The APIs report ready before the supervisor finishes spawning all workers, and
# the console-smoke test asserts every worker is healthy. Wait for all eight
# worker pid files (supervisor writes data/run/worker-<name>.pid on spawn) so
# the health assertion is not raced.
echo "== waiting for all 8 workers to register =="
workers_ready=""
for _ in $(seq 1 90); do
  n=$(ls data/run/worker-*.pid 2>/dev/null | wc -l | tr -d ' ')
  if [ "$n" -ge 8 ]; then workers_ready=1; break; fi
  sleep 1
done
[ -n "$workers_ready" ] || { echo "error: workers did not all register (saw ${n:-0}/8)" >&2; exit 1; }
echo "   all 8 workers registered"

echo "== running the live E2E gate (make test-e2e) =="
set +e
KP_E2E_PASSWORD="$CONSOLE_PW" \
KP_E2E_LIFECYCLE=1 \
KP_E2E_OPERATOR_URL="http://127.0.0.1:8000" \
KP_E2E_TRACKING_URL="http://127.0.0.1:8001" \
  make test-e2e
rc=$?
set -e

echo
if [ "$rc" -eq 0 ]; then
  echo "================ E2E PASSED ================"
else
  echo "================ E2E FAILED (exit $rc) ================"
  echo " Console log: $(pwd)/.dep010-run/console.log"
fi
exit "$rc"
