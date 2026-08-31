#!/usr/bin/env bash
# DEP-010 / A11Y-030 - start the operator console and print the exact URL,
# username and password to use.
#
#   ./scripts/operator/dep010/start-console.sh
#
# Stop it again with:
#   ./scripts/operator/dep010/stop-console.sh
#
# DOCKER RUNS ONLY ON 192.168.1.140. Nothing is started on this Mac's Docker.
# The database, redis, mailpit and the mock services all live on .140; this
# script opens an SSH tunnel so the console can reach them over loopback, then
# runs the operator API, tracking API and workers here as ordinary Python
# processes. The .140 live `kingphisher` database is never touched: a separate
# disposable container with its own volume is used instead.
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RUN=.dep010-run; mkdir -p "$RUN"

WORKER=edierks@192.168.1.140
REMOTE_SOCK=unix:///Volumes/DockerExternal/KingPhisher-Phoenix/colima/kingphisher/docker.sock
PG_IMAGE='postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777'
PG_CONTAINER=kp-console-postgres
PG_VOLUME=kp_console_postgres_data
PG_REMOTE_PORT=5434

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

echo "== 1/6 starting the disposable console database on 192.168.1.140 =="
ssh -o BatchMode=yes "$WORKER" \
  "DOCKER_HOST=$REMOTE_SOCK docker inspect $PG_CONTAINER >/dev/null 2>&1 \
   && DOCKER_HOST=$REMOTE_SOCK docker start $PG_CONTAINER >/dev/null \
   || DOCKER_HOST=$REMOTE_SOCK docker run -d --name $PG_CONTAINER \
        -e POSTGRES_USER=kingphisher \
        -e POSTGRES_PASSWORD='$POSTGRES_PASSWORD' \
        -e POSTGRES_DB=kingphisher \
        -p 127.0.0.1:$PG_REMOTE_PORT:5432 \
        -v $PG_VOLUME:/var/lib/postgresql/data \
        --restart no $PG_IMAGE >/dev/null"
echo "   container $PG_CONTAINER up on .140:$PG_REMOTE_PORT"

echo "== 2/6 opening the SSH tunnel to .140 (no local Docker) =="
pkill -f "kp-dep010-tunnel" 2>/dev/null || true
ssh -N -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 \
  -o "SetEnv KPTUNNEL=kp-dep010-tunnel" \
  -L "127.0.0.1:5432:127.0.0.1:$PG_REMOTE_PORT" \
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
nc -z 127.0.0.1 5432 >/dev/null 2>&1 || { echo "   ERROR: tunnel to .140 did not come up" >&2; exit 1; }
echo "   tunnel up (5432 6379 1025 8025 8443 8181 8282)"

PG="postgresql+psycopg://kingphisher:${POSTGRES_PASSWORD}@127.0.0.1:5432/kingphisher"
AU="postgresql+psycopg://audit_writer:${AUDIT_WRITER_PASSWORD}@127.0.0.1:5432/kingphisher"
export DATABASE_URL="$PG" OPERATOR_API_DATABASE_URL="$PG" TRACKING_API_DATABASE_URL="$PG" KP_WORKER_DATABASE_URL="$PG"
export AUDIT_DATABASE_URL="$AU" OPERATOR_API_AUDIT_DATABASE_URL="$AU" KP_WORKER_AUDIT_DATABASE_URL="$AU"
export REDIS_URL="redis://:${REDIS_PASSWORD}@127.0.0.1:6379/0"
export OPERATOR_API_REDIS_URL="$REDIS_URL" TRACKING_API_REDIS_URL="$REDIS_URL" KP_WORKER_REDIS_URL="$REDIS_URL"

echo "== 3/6 ensuring the audit role exists =="
for _ in $(seq 1 60); do
  .venv/bin/python - <<PY >/dev/null 2>&1 && break
import psycopg
psycopg.connect("host=127.0.0.1 port=5432 user=kingphisher password=${POSTGRES_PASSWORD} dbname=kingphisher", connect_timeout=3).close()
PY
  sleep 1
done
.venv/bin/python - <<PY
import psycopg
c = psycopg.connect("host=127.0.0.1 port=5432 user=kingphisher password=${POSTGRES_PASSWORD} dbname=kingphisher", connect_timeout=10)
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
echo " Docker containers run on 192.168.1.140 only; none on this Mac."
echo " Log: $(pwd)/$RUN/console.log"
echo " Stop with: ./scripts/operator/dep010/stop-console.sh"
