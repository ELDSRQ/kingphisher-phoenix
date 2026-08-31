#!/usr/bin/env bash
# DEP-010 / A11Y-030 - start the operator console on THIS Mac and print the
# exact URL and password to use. Run it, read the last 6 lines, open the URL.
#
#   ./scripts/operator/dep010/start-console.sh
#
# Stop it again with:  ./scripts/operator/dep010/stop-console.sh
#
# It starts the local Docker services the console needs, brings the database to
# the current schema, seeds demo data, then runs the operator API on port 8000
# and the tracking API on 8001. The platform's .140 database is left untouched.
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RUN=.dep010-run; mkdir -p "$RUN"

echo "== 1/5 starting Docker Desktop and the local services =="
if ! docker info >/dev/null 2>&1; then
  echo "   Docker Desktop is not running; starting it"
  open -a Docker 2>/dev/null || true
  for _ in $(seq 1 120); do
    docker info >/dev/null 2>&1 && break
    sleep 2
  done
fi
if ! docker info >/dev/null 2>&1; then
  echo "   ERROR: Docker Desktop did not become ready." >&2
  echo "   Open the Docker Desktop app manually, wait for the whale icon to stop" >&2
  echo "   animating, then run this script again." >&2
  exit 1
fi
echo "   Docker daemon ready"
docker compose -f docker-compose.e2e.yml up -d >/dev/null
docker compose up -d redis mailpit mock-idp mock-graph mock-ai otel-collector >/dev/null
for _ in $(seq 1 60); do
  docker exec kp-e2e-postgres pg_isready -U kingphisher -d kingphisher >/dev/null 2>&1 && break
  sleep 1
done

# Load .env as inert data (it contains quoted, space-bearing values).
eval "$(python3 - <<'PY'
import pathlib, shlex
for line in pathlib.Path(".env").read_text().splitlines():
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line: continue
    k, v = line.split("=", 1)
    if not k.replace("_", "").isalnum(): continue
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"": v = v[1:-1]
    print(f"export {k}={shlex.quote(v)}")
PY
)"

PG="postgresql+psycopg://kingphisher:${POSTGRES_PASSWORD}@127.0.0.1:5433/kingphisher"
AU="postgresql+psycopg://audit_writer:${AUDIT_WRITER_PASSWORD}@127.0.0.1:5433/kingphisher"
export DATABASE_URL="$PG" OPERATOR_API_DATABASE_URL="$PG" TRACKING_API_DATABASE_URL="$PG" KP_WORKER_DATABASE_URL="$PG"
export AUDIT_DATABASE_URL="$AU" OPERATOR_API_AUDIT_DATABASE_URL="$AU" KP_WORKER_AUDIT_DATABASE_URL="$AU"
export REDIS_URL="redis://:${REDIS_PASSWORD}@127.0.0.1:6379/0"
export OPERATOR_API_REDIS_URL="$REDIS_URL" TRACKING_API_REDIS_URL="$REDIS_URL" KP_WORKER_REDIS_URL="$REDIS_URL"

echo "== 2/5 bringing the database to the current schema =="
.venv/bin/python -m alembic -c packages/database/alembic.ini upgrade head >/dev/null
echo "== 3/5 seeding demo data =="
.venv/bin/python scripts/seed.py >/dev/null 2>&1 || true
.venv/bin/python scripts/bootstrap_local_audit.py >/dev/null 2>&1 || true

echo "== 4/5 forwarding 5432 -> 5433 so the console's health probe passes =="
if ! nc -z 127.0.0.1 5432 2>/dev/null; then
  nohup .venv/bin/python scripts/operator/dep010/_portforward.py 5432 5433 >"$RUN/forward.log" 2>&1 &
  echo $! > "$RUN/forward.pid"; sleep 1
fi

echo "== 5/5 starting the console =="
nohup .venv/bin/python scripts/supervisor.py > "$RUN/console.log" 2>&1 &
echo $! > "$RUN/supervisor.pid"
for _ in $(seq 1 90); do
  curl -sf --max-time 2 http://127.0.0.1:8000/readyz >/dev/null 2>&1 && break
  sleep 1
done

echo
echo "================ OPEN THIS ================"
echo " URL      : http://127.0.0.1:8000/console/"
echo " Username : admin"
echo " Password : ${KP_CONSOLE_PASSWORD}"
echo "==========================================="
echo " (password comes from line 63 of"
echo "  $(pwd)/.env )"
echo " Log: $(pwd)/$RUN/console.log"
echo " Stop with: ./scripts/operator/dep010/stop-console.sh"
