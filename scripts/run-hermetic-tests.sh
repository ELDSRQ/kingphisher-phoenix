#!/usr/bin/env bash
# Run unit tests without inheriting live service endpoints or reloading .env.

set -euo pipefail

case "${1:-}" in
  all)
    markers='not postgres and not redis and not e2e and not azure_live'
    ;;
  unit)
    markers='not contract and not postgres and not redis and not e2e and not azure_live'
    ;;
  *)
    printf '%s\n' 'usage: scripts/run-hermetic-tests.sh {all|unit}' >&2
    exit 2
    ;;
esac

# The controller-side recovery-checkpoint contract tests exercise macOS-only
# tooling (Keychain via `security`, `/private/tmp`, and a `uname = Darwin`
# guard). They run on the macOS controller and on the .140 worker, but a
# Linux CI runner has no `/private/tmp`, so they cannot pass there. Deselect
# them off Darwin. This is a deselection, not a skip, so the no-skips gate is
# unaffected.
if [ "$(uname -s)" != "Darwin" ]; then
  markers="$markers and not macos_only"
fi

# Pydantic settings normally read .env for the local GUI launcher. Tests must
# neither inherit process configuration nor reload that file. Explicit inert
# database/queue endpoints also keep application defaults from reaching a
# running local stack if a test constructs an app without supplying settings.
hermetic_environment=(
  env -i
  "PATH=$PATH"
  "KP_DISABLE_DOTENV=1"
  "KP_TEST_PROFILE=hermetic"
  "DATABASE_URL=postgresql+psycopg://hermetic:hermetic@127.0.0.1:1/kp_hermetic"
  "AUDIT_DATABASE_URL=postgresql+psycopg://hermetic_audit:hermetic@127.0.0.1:1/kp_hermetic"
  "DATABASE_URL_TEST=postgresql+psycopg://hermetic:hermetic@127.0.0.1:1/kp_hermetic_test"
  "AUDIT_DATABASE_URL_TEST=postgresql+psycopg://hermetic_audit:hermetic@127.0.0.1:1/kp_hermetic_test"
  "OPERATOR_API_DATABASE_URL=postgresql+psycopg://hermetic:hermetic@127.0.0.1:1/kp_hermetic"
  "OPERATOR_API_AUDIT_DATABASE_URL=postgresql+psycopg://hermetic_audit:hermetic@127.0.0.1:1/kp_hermetic"
  "TRACKING_API_DATABASE_URL=postgresql+psycopg://hermetic:hermetic@127.0.0.1:1/kp_hermetic"
  "KP_WORKER_DATABASE_URL=postgresql+psycopg://hermetic:hermetic@127.0.0.1:1/kp_hermetic"
  "KP_WORKER_AUDIT_DATABASE_URL=postgresql+psycopg://hermetic_audit:hermetic@127.0.0.1:1/kp_hermetic"
  "REDIS_URL=redis://127.0.0.1:1/14"
  "OPERATOR_API_REDIS_URL=redis://127.0.0.1:1/14"
  "TRACKING_API_REDIS_URL=redis://127.0.0.1:1/14"
  "KP_WORKER_REDIS_URL=redis://127.0.0.1:1/14"
)
for variable_name in HOME TMPDIR LANG LC_ALL LC_CTYPE TZ USER LOGNAME UV_CACHE_DIR UV_PYTHON UV_PYTHON_DOWNLOADS; do
  variable_value="${!variable_name-}"
  if [[ -n "$variable_value" ]]; then
    hermetic_environment+=("$variable_name=$variable_value")
  fi
done

exec "${hermetic_environment[@]}" \
  uv run --frozen --no-sync python -m pytest -m "$markers" -p tests.no_skips_plugin
