#!/usr/bin/env bash
# Run the Redis contract against reserved database 15 without inheriting any
# application queue binding. This gate never flushes or prunes preserved data;
# each contract must remove only the keys it creates.

set -euo pipefail

if [ -z "${REDIS_URL_TEST:-}" ]; then
  printf '%s\n' 'error: REDIS_URL_TEST is required for the Redis integration gate' >&2
  exit 2
fi

if ! python3 - <<'PY'
import ipaddress
import os
import socket
from urllib.parse import unquote, urlsplit


RUNTIME_VARIABLES = ("REDIS_URL", "OPERATOR_API_REDIS_URL", "TRACKING_API_REDIS_URL", "KP_WORKER_REDIS_URL")


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
        return int(unquote(path).replace("/", ""))
    except (UnicodeError, ValueError):
        return 0


def target(value: str, *, test_url: bool) -> tuple[str, int, int]:
    try:
        parsed = urlsplit(value)
        port = parsed.port or 6379
    except ValueError:
        raise SystemExit(2) from None
    if parsed.scheme not in {"redis", "rediss"} or not parsed.hostname or parsed.query or parsed.fragment:
        raise SystemExit(2)
    if test_url and parsed.path != "/15":
        raise SystemExit(2)
    return host_identity(parsed.hostname), port, database_number(parsed.path)


test_target = target(os.environ["REDIS_URL_TEST"], test_url=True)
if test_target[2] != 15:
    raise SystemExit(2)
for variable_name in RUNTIME_VARIABLES:
    value = os.environ.get(variable_name, "").strip()
    if value:
        runtime_target = target(value, test_url=False)
        if runtime_target[2] in {14, 15} or runtime_target == test_target:
            raise SystemExit(3)
PY
then
  printf '%s\n' \
    'error: REDIS_URL_TEST must select dedicated Redis database 15 and application queues must not use reserved databases 14 or 15' >&2
  exit 2
fi

redis_test_environment=(
  env -i
  "PATH=$PATH"
  "KP_DISABLE_DOTENV=1"
  "KP_TEST_PROFILE=redis"
  "REDIS_URL=$REDIS_URL_TEST"
  "OPERATOR_API_REDIS_URL=$REDIS_URL_TEST"
  "TRACKING_API_REDIS_URL=$REDIS_URL_TEST"
  "KP_WORKER_REDIS_URL=$REDIS_URL_TEST"
)
for variable_name in HOME TMPDIR LANG LC_ALL LC_CTYPE TZ USER LOGNAME UV_CACHE_DIR UV_PYTHON UV_PYTHON_DOWNLOADS; do
  variable_value="${!variable_name-}"
  if [[ -n "$variable_value" ]]; then
    redis_test_environment+=("$variable_name=$variable_value")
  fi
done

exec "${redis_test_environment[@]}" \
  uv run --frozen --no-sync python -m pytest -m redis -p tests.no_skips_plugin
