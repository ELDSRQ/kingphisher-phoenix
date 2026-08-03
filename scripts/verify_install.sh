#!/usr/bin/env bash
# Kingphisher-Phoenix install verification.
#
# Health-checks a running local install: docker infrastructure, the operator
# and tracking APIs, the console login endpoint, every worker pidfile, and the
# append-only audit chain. Exits non-zero if anything is broken.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m    ok:\033[0m %s\n' "$*"; }
bad()  { printf '\033[1;31m    FAIL:\033[0m %s\n' "$*"; }

FAIL=0
check() {
  if eval "$2"; then ok "$1"; else bad "$1"; FAIL=1; fi
}

step "docker infrastructure"
check "postgres"   'docker compose ps postgres | grep -q healthy'
check "redis"      'docker compose ps redis | grep -q healthy'
check "mailpit"    'docker compose ps mailpit | grep -q healthy'
check "mock-idp"   'docker compose ps mock-idp | grep -q "Up"'
check "mock-graph" 'docker compose ps mock-graph | grep -q "Up"'
check "mock-ai"    'docker compose ps mock-ai | grep -q "Up"'

step "application services"
check "operator-api :8000 /healthz" 'curl -fsS http://127.0.0.1:8000/healthz >/dev/null'
check "tracking-api :8001 /healthz" 'curl -fsS http://127.0.0.1:8001/healthz >/dev/null'
check "console SPA reachable"       'curl -fsS http://127.0.0.1:8000/console/ >/dev/null'
check "console session enforces auth" '[ "$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" -d "{}" http://127.0.0.1:8000/api/v1/console/session)" = "422" ]'

step "workers (pidfiles)"
for name in operator-api tracking-api \
            worker-ingestion worker-generation worker-delivery \
            worker-retention worker-mailbox worker-reminder; do
  pidfile="data/run/$name.pid"
  if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
    ok "$name (pid $(cat "$pidfile"))"
  else
    bad "$name (pidfile $pidfile missing or stale)"
    FAIL=1
  fi
done

step "audit chain integrity"
if uv run python scripts/verify_audit.py; then
  ok "audit chain"
else
  FAIL=1
fi

step
if [ "$FAIL" -eq 0 ]; then
  echo "  All checks passed."
  exit 0
fi
echo "  Some checks failed. See data/logs/*.log for service output."
exit 1
