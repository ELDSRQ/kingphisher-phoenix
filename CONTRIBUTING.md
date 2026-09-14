# Contributing / local development

## Setup — use `make bootstrap`, not a bare `uv sync`

This is a **`uv` workspace** with multiple members (`apps/*`, `packages/*`). A bare
`uv sync` installs only the root project, so app packages such as
`kp_tracking_api` are missing and imports/tests fail. Always sync **all**
workspace members:

```bash
make bootstrap        # uv sync --frozen --all-packages + local infra + db init
# or, dependencies only:
uv sync --frozen --all-packages
```

`--frozen` keeps `uv.lock` untouched (normal development never mutates the lock).

## Running the tests

```bash
KP_DISABLE_DOTENV=1 uv run --frozen python -m pytest -q     # hermetic suite
make test                                                    # via the Makefile
make test-postgres   # integration gates (need local Postgres, marker: postgres)
make test-redis      # integration gates (need local Redis,    marker: redis)
```

- **`KP_DISABLE_DOTENV=1`** is required for the hermetic suite so a local `.env`
  cannot leak settings into settings-driven tests.
- Tests marked `postgres` / `redis` / `e2e` / `azure_live` need live
  infrastructure and are deselected by default.

## Before opening a PR

```bash
make lint         # ruff check + ruff format --check + node --check on the console bundle
make typecheck    # mypy
```

- The operator console bundle (`apps/operator-ui/src/console/app.js`) is built
  from `src/console-js/` by esbuild and is **checked in**; a bundle-drift test
  fails if it is stale. After editing `console-js/`, run `cd apps/operator-ui &&
  npm run build` and commit the rebuilt bundle. Avoid adding runtime npm
  dependencies (the frontend is deliberately near-zero-dependency).
- `main` uses strict branch protection; every change lands via a green PR.
