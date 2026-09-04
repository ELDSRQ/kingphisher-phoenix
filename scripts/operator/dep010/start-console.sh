#!/usr/bin/env bash
# DEP-010 / A11Y-030 - start the operator console and print the exact URL,
# username and password to use.
#
#   ./scripts/operator/dep010/start-console.sh
#
# Stop it again with:
#   ./scripts/operator/dep010/stop-console.sh
#
# DOCKER RUNS ON THE REMOTE WORKER, never on this Mac. The database, redis,
# mailpit and the mock services all live on the worker (default .140 macOS/Colima;
# set KP_DOCKER_WORKER=erikd@192.168.1.105 for the .105 WSL2 worker). This script
# opens an SSH tunnel so the console can reach them over loopback, then runs the
# operator API, tracking API and workers here as ordinary Python processes. The
# worker's live `kingphisher` database is never touched: a separate disposable
# container with its own volume is used instead.
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RUN=.dep010-run; mkdir -p "$RUN"

# Docker worker selection. Defaults to the .140 macOS/Colima host so existing
# runs are unchanged; override with KP_DOCKER_WORKER=erikd@192.168.1.105 to use
# the .105 WSL2 worker.
# shellcheck source=scripts/operator/lib/docker-worker.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/docker-worker.sh"
WORKER="$(kp_worker_target)"
PG_IMAGE='postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777'
PG_CONTAINER=kp-console-postgres
PG_VOLUME=kp_console_postgres_data
PG_REMOTE_PORT=5434

# Remote worker: publish the console DB on 5434 to avoid clashing with the
# worker's compose postgres, and tunnel local 5432 -> 5434 so the app/.env use
# 5432. Local worker: no tunnel and no compose postgres competing, so publish the
# console DB on the standard 5432 directly — a fresh .env (DATABASE_URL=...:5432)
# then works for both the app and `make test-e2e` with no edits.
if kp_worker_is_local; then
  KP_LOCAL=1; PUB_PORT=5432; APP_PG_PORT=5432
else
  KP_LOCAL=0; PUB_PORT=$PG_REMOTE_PORT; APP_PG_PORT=5432
fi

# Load .env as inert data (it holds quoted, space-bearing values).
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

echo "== 1/6 starting the disposable console database on $WORKER ($(kp_worker_profile)) =="
kp_worker_run <<SCRIPT
docker inspect $PG_CONTAINER >/dev/null 2>&1 \
  && docker start $PG_CONTAINER >/dev/null \
  || docker run -d --name $PG_CONTAINER \
       -e POSTGRES_USER=kingphisher \
       -e POSTGRES_PASSWORD='$POSTGRES_PASSWORD' \
       -e POSTGRES_DB=kingphisher \
       -p 127.0.0.1:$PUB_PORT:5432 \
       -v $PG_VOLUME:/var/lib/postgresql/data \
       --restart no $PG_IMAGE >/dev/null
SCRIPT
echo "   container $PG_CONTAINER up on $WORKER:$PUB_PORT"

if [ "$KP_LOCAL" = 1 ]; then
  echo "== 2/6 local worker: no tunnel; using localhost services directly =="
  for _ in $(seq 1 60); do
    nc -z 127.0.0.1 "$APP_PG_PORT" >/dev/null 2>&1 && break
    sleep 1
  done
  nc -z 127.0.0.1 "$APP_PG_PORT" >/dev/null 2>&1 \
    || { echo "   ERROR: console database on 127.0.0.1:$APP_PG_PORT is not reachable" >&2; exit 1; }
  echo "   console db reachable on 127.0.0.1:$APP_PG_PORT (redis/mailpit/mocks expected on their localhost ports)"
else
  echo "== 2/6 opening the SSH tunnel to the worker (no local Docker) =="
  pkill -f "kp-dep010-tunnel" 2>/dev/null || true
  ssh -N -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 \
    -o "SetEnv KPTUNNEL=kp-dep010-tunnel" \
    -L "127.0.0.1:5432:127.0.0.1:$PUB_PORT" \
    -L 127.0.0.1:6379:127.0.0.1:6379 \
    -L 127.0.0.1:1025:127.0.0.1:1025 \
    -L 127.0.0.1:8025:127.0.0.1:8025 \
    -L 127.0.0.1:8443:127.0.0.1:8443 \
    -L 127.0.0.1:8181:127.0.0.1:8181 \
    -L 127.0.0.1:8282:127.0.0.1:8282 \
    "$WORKER" > "$RUN/tunnel.log" 2>&1 &
  echo $! > "$RUN/tunnel.pid"
  for _ in $(seq 1 60); do
    nc -z 127.0.0.1 5432 >/dev/null 2>&1 && break
    sleep 1
  done
  nc -z 127.0.0.1 5432 >/dev/null 2>&1 || { echo "   ERROR: tunnel to the worker did not come up" >&2; exit 1; }
  echo "   tunnel up (5432 6379 1025 8025 8443 8181 8282)"
fi

PG="postgresql+psycopg://kingphisher:${POSTGRES_PASSWORD}@127.0.0.1:${APP_PG_PORT}/kingphisher"
AU="postgresql+psycopg://audit_writer:${AUDIT_WRITER_PASSWORD}@127.0.0.1:${APP_PG_PORT}/kingphisher"
export DATABASE_URL="$PG" OPERATOR_API_DATABASE_URL="$PG" TRACKING_API_DATABASE_URL="$PG" KP_WORKER_DATABASE_URL="$PG"
export AUDIT_DATABASE_URL="$AU" OPERATOR_API_AUDIT_DATABASE_URL="$AU" KP_WORKER_AUDIT_DATABASE_URL="$AU"
export REDIS_URL="redis://:${REDIS_PASSWORD}@127.0.0.1:6379/0"
export OPERATOR_API_REDIS_URL="$REDIS_URL" TRACKING_API_REDIS_URL="$REDIS_URL" KP_WORKER_REDIS_URL="$REDIS_URL"

echo "== 3/6 ensuring the audit role exists =="
for _ in $(seq 1 60); do
  .venv/bin/python - <<PY >/dev/null 2>&1 && break
import psycopg
psycopg.connect("host=127.0.0.1 port=${APP_PG_PORT} user=kingphisher password=${POSTGRES_PASSWORD} dbname=kingphisher", connect_timeout=3).close()
PY
  sleep 1
done
.venv/bin/python - <<PY
import psycopg
c = psycopg.connect("host=127.0.0.1 port=${APP_PG_PORT} user=kingphisher password=${POSTGRES_PASSWORD} dbname=kingphisher", connect_timeout=10)
c.autocommit = True
c.execute("DO \$\$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='audit_writer') "
          "THEN CREATE ROLE audit_writer LOGIN PASSWORD '${AUDIT_WRITER_PASSWORD}'; END IF; END \$\$;")
c.execute("GRANT USAGE ON SCHEMA public TO audit_writer")
c.close()
print("   audit_writer ready")
PY

echo "== 4/6 bringing the database to the current schema =="
.venv/bin/python -m alembic -c packages/database/alembic.ini upgrade head >/dev/null
echo "== 5/6 seeding demo data =="
.venv/bin/python scripts/seed.py >/dev/null 2>&1 || true
.venv/bin/python scripts/bootstrap_local_audit.py >/dev/null 2>&1 || true

echo "== 6/6 starting the console =="
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
echo " Docker containers run on the worker ($WORKER) only; none on this Mac."
echo " Log: $(pwd)/$RUN/console.log"
echo " Stop with: ./scripts/operator/dep010/stop-console.sh"
