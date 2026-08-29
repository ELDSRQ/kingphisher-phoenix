#!/usr/bin/env bash
# Run PostgreSQL integration tests without publishing their disposable jobs to
# the live application queue. Redis database 14 is reserved for this gate and
# is cleared before and after the run; the application queue database is never
# selected or modified.

set -euo pipefail

for required_name in DATABASE_URL_TEST AUDIT_DATABASE_URL_TEST REDIS_URL_POSTGRES_TEST; do
  if [ -z "${!required_name:-}" ]; then
    printf 'error: %s is required for the PostgreSQL integration gate\n' "$required_name" >&2
    exit 2
  fi
done

if ! python3 - <<'PY'
import ipaddress
import os
import re
import socket
from urllib.parse import unquote, urlsplit


RUNTIME_DATABASE_VARIABLES = (
    "DATABASE_URL",
    "AUDIT_DATABASE_URL",
    "OPERATOR_API_DATABASE_URL",
    "OPERATOR_API_AUDIT_DATABASE_URL",
    "TRACKING_API_DATABASE_URL",
    "KP_WORKER_DATABASE_URL",
    "KP_WORKER_AUDIT_DATABASE_URL",
)
ALLOWED_SCHEMES = frozenset({"postgresql", "postgresql+psycopg"})
DISPOSABLE_DATABASE = "kingphisher_test"


def host_identity(value: str) -> str:
    try:
        host = unquote(value).rstrip(".").lower()
    except UnicodeError:
        raise SystemExit(2) from None
    if not host:
        raise SystemExit(2)
    unscoped = host.split("%", 1)[0]
    if unscoped == "localhost" or unscoped.endswith(".localhost"):
        return "loopback"
    try:
        address = ipaddress.ip_address(unscoped)
        mapped = getattr(address, "ipv4_mapped", None)
        if address.is_loopback or (mapped is not None and mapped.is_loopback):
            return "loopback"
    except ValueError:
        # libc accepts shorthand/integer IPv4 spellings such as 127.1 and
        # 2130706433. inet_aton parses numeric forms without a DNS lookup.
        try:
            if ipaddress.ip_address(socket.inet_aton(unscoped)).is_loopback:
                return "loopback"
        except (OSError, ValueError):
            pass
    return host


def database_identity(value: str) -> tuple[tuple[str, int, str], str]:
    try:
        parsed = urlsplit(value)
        port = parsed.port or 5432
    except ValueError:
        raise SystemExit(2) from None
    if (
        parsed.scheme not in ALLOWED_SCHEMES
        or not parsed.hostname
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
        or "/" in parsed.path[1:]
        or re.search(r"%(?![0-9A-Fa-f]{2})", parsed.path) is not None
        or re.search(r"%(?![0-9A-Fa-f]{2})", parsed.username or "") is not None
    ):
        raise SystemExit(2)
    try:
        database = unquote(parsed.path[1:])
        role = unquote(parsed.username or "")
    except UnicodeError:
        raise SystemExit(2) from None
    if not database or not role.strip():
        raise SystemExit(2)
    return (host_identity(parsed.hostname), port, database), role


application_target, application_role = database_identity(os.environ["DATABASE_URL_TEST"])
audit_target, audit_role = database_identity(os.environ["AUDIT_DATABASE_URL_TEST"])
if (
    application_target != audit_target
    or application_target[2] != DISPOSABLE_DATABASE
    or application_role == audit_role
):
    raise SystemExit(3)

for variable_name in RUNTIME_DATABASE_VARIABLES:
    value = os.environ.get(variable_name, "").strip()
    if value:
        runtime_target = database_identity(value)[0]
        if runtime_target[2] == DISPOSABLE_DATABASE or runtime_target == application_target:
            raise SystemExit(4)
PY
then
  printf '%s\n' \
    'error: PostgreSQL test URLs must identify distinct roles on the dedicated kingphisher_test database and must not match an application database' >&2
  exit 2
fi

if ! python3 - <<'PY'
import ipaddress
import os
import socket
from urllib.parse import unquote, urlsplit


def host_identity(value: str) -> str:
    try:
        host = unquote(value).rstrip(".").lower()
    except UnicodeError:
        raise SystemExit(2) from None
    if not host:
        raise SystemExit(2)
    unscoped = host.split("%", 1)[0]
    if unscoped == "localhost" or unscoped.endswith(".localhost"):
        return "loopback"
    try:
        address = ipaddress.ip_address(unscoped)
        mapped = getattr(address, "ipv4_mapped", None)
        if address.is_loopback or (mapped is not None and mapped.is_loopback):
            return "loopback"
    except ValueError:
        try:
            if ipaddress.ip_address(socket.inet_aton(unscoped)).is_loopback:
                return "loopback"
        except (OSError, ValueError):
            pass
    return host


def database_number(path: str) -> int:
    if not path:
        return 0
    try:
        # Match redis-py: URL paths are decoded, every slash is removed, and
        # an invalid/missing integer falls back to the client's default DB 0.
        return int(unquote(path).replace("/", ""))
    except (UnicodeError, ValueError):
        return 0


def target(value: str, *, test_url: bool) -> tuple[str, int, int]:
    try:
        parsed = urlsplit(value)
        # redis-py uses the connection class's 6379 default for both schemes
        # when the URL omits a port. Match the client rather than a provider's
        # conventional TLS port so equivalent URLs cannot evade comparison.
        port = parsed.port or 6379
    except ValueError:
        raise SystemExit(2) from None
    if (
        parsed.scheme not in {"redis", "rediss"}
        or not parsed.hostname
        or parsed.query
        or parsed.fragment
    ):
        raise SystemExit(2)
    if test_url and parsed.path != "/14":
        raise SystemExit(2)
    return host_identity(parsed.hostname), port, database_number(parsed.path)


test_target = target(os.environ["REDIS_URL_POSTGRES_TEST"], test_url=True)
if test_target[2] != 14:
    raise SystemExit(2)
for variable_name in ("REDIS_URL", "OPERATOR_API_REDIS_URL", "TRACKING_API_REDIS_URL", "KP_WORKER_REDIS_URL"):
    value = os.environ.get(variable_name, "").strip()
    if value:
        runtime_target = target(value, test_url=False)
        if runtime_target[2] in {14, 15} or runtime_target == test_target:
            raise SystemExit(3)
PY
then
  printf '%s\n' \
    'error: REDIS_URL_POSTGRES_TEST must select dedicated Redis database 14 and must not match an application queue' >&2
  exit 2
fi

clear_test_queue() {
  REDIS_URL="$REDIS_URL_POSTGRES_TEST" uv run --frozen --no-sync python -c '
import os
import redis

client = redis.Redis.from_url(os.environ["REDIS_URL"], decode_responses=True)
try:
    client.ping()
    client.flushdb()
finally:
    client.close()
'
}

cleanup_required=0
# shellcheck disable=SC2329  # invoked by the EXIT trap
cleanup_on_exit() {
  if [ "$cleanup_required" -eq 1 ]; then
    clear_test_queue >/dev/null 2>&1 || \
      printf '%s\n' 'warning: dedicated PostgreSQL-test Redis database 14 could not be cleared' >&2
  fi
}
trap cleanup_on_exit EXIT

clear_test_queue
cleanup_required=1

# Selected integration tests receive only their reviewed disposable database
# and queue bindings. They cannot inherit provider endpoints, runtime secrets,
# pytest selectors, or any other value loaded by the calling shell.
postgres_test_environment=(
  env -i
  "PATH=$PATH"
  "KP_DISABLE_DOTENV=1"
  "KP_TEST_PROFILE=postgres"
  "DATABASE_URL_TEST=$DATABASE_URL_TEST"
  "AUDIT_DATABASE_URL_TEST=$AUDIT_DATABASE_URL_TEST"
  "DATABASE_URL=$DATABASE_URL_TEST"
  "AUDIT_DATABASE_URL=$AUDIT_DATABASE_URL_TEST"
  "OPERATOR_API_DATABASE_URL=$DATABASE_URL_TEST"
  "OPERATOR_API_AUDIT_DATABASE_URL=$AUDIT_DATABASE_URL_TEST"
  "TRACKING_API_DATABASE_URL=$DATABASE_URL_TEST"
  "KP_WORKER_DATABASE_URL=$DATABASE_URL_TEST"
  "KP_WORKER_AUDIT_DATABASE_URL=$AUDIT_DATABASE_URL_TEST"
  "REDIS_URL=$REDIS_URL_POSTGRES_TEST"
  "OPERATOR_API_REDIS_URL=$REDIS_URL_POSTGRES_TEST"
  "TRACKING_API_REDIS_URL=$REDIS_URL_POSTGRES_TEST"
  "KP_WORKER_REDIS_URL=$REDIS_URL_POSTGRES_TEST"
)
for variable_name in HOME TMPDIR LANG LC_ALL LC_CTYPE TZ USER LOGNAME UV_CACHE_DIR UV_PYTHON UV_PYTHON_DOWNLOADS; do
  variable_value="${!variable_name-}"
  if [[ -n "$variable_value" ]]; then
    postgres_test_environment+=("$variable_name=$variable_value")
  fi
done

set +e
"${postgres_test_environment[@]}" \
  uv run --frozen --no-sync python -m pytest -m postgres -p tests.no_skips_plugin
test_status=$?
set -e

if ! clear_test_queue; then
  printf '%s\n' 'error: dedicated PostgreSQL-test Redis database 14 could not be cleared after the test run' >&2
  exit 1
fi
cleanup_required=0
exit "$test_status"
