SHELL := /bin/bash
PY := uv run --frozen
COMPOSE := docker compose

.PHONY: bootstrap install verify-install operational-readiness dev mock-stack lock-mock-services test test-unit test-postgres test-redis test-contract test-fresh-migration test-live-azure test-e2e lint typecheck security-scan security-scan-bandit security-scan-semgrep security-scan-trivy security-scan-dependencies security-scan-images verify-images db-migrate db-rollback db-init seed build sbom sign verify-audit

## One-shot installer: installs all dependencies and starts the full system.
## See scripts/install.sh for supported platforms (macOS, Debian/Ubuntu).
install:
	@bash scripts/install.sh

## Health-check a running local install (infra, APIs, workers, audit chain).
verify-install:
	@bash scripts/verify_install.sh

## Disposable-local deployment gate (configuration, tests, audit, live lifecycle).
operational-readiness:
	@bash scripts/operational_readiness.sh

## Install pinned toolchain and dependencies, start local infra.
bootstrap:
	@UV_PYTHON_DOWNLOADS=never uv sync --frozen --all-packages
	@$(COMPOSE) up -d postgres redis otel-collector mock-graph mock-ai mock-idp mailpit
	@make db-init

## Regenerate the complete hash-verified dependency lock for disposable mocks.
lock-mock-services:
	@UV_PYTHON_DOWNLOADS=never uv pip compile infrastructure/mock-services/requirements.in --python-version 3.14 --python-platform linux --only-binary=:all: --generate-hashes --custom-compile-command 'make lock-mock-services' --output-file infrastructure/mock-services/requirements.txt

## Start application services for local development.
dev:
	@$(COMPOSE) up -d postgres redis otel-collector mock-graph mock-ai mock-idp mailpit
	@$(PY) uvicorn kp_operator_api.main:app --reload --port 8000 &
	@$(PY) uvicorn kp_tracking_api.main:app --reload --port 8001 &

## Run the hermetic suite and reject every skip. PostgreSQL, Redis, live E2E,
## and Azure checks have explicit opt-in targets below. The hermetic profile
## still requires zsh so the generated macOS launcher is syntax-checked rather
## than silently omitted on hosts missing that interpreter.
test:
	@bash scripts/run-hermetic-tests.sh all

## Run hermetic unit tests only and reject every skip.
test-unit:
	@bash scripts/run-hermetic-tests.sh unit

## Run every PostgreSQL integration test. The URL must name a disposable,
## migrated database; the role must have CREATEDB/CREATEROLE and audit_writer
## must be provisioned because fresh-install and privilege tests fail on skips.
## Disposable queue work is isolated in Redis database 14 and cleared by the
## gate so tests cannot publish into the running application's queue.
test-postgres:
	@[ -n "$$DATABASE_URL_TEST" ] || { echo "DATABASE_URL_TEST is required for the PostgreSQL integration gate" >&2; exit 2; }
	@[ -n "$$AUDIT_DATABASE_URL_TEST" ] || { echo "AUDIT_DATABASE_URL_TEST is required for the PostgreSQL integration gate" >&2; exit 2; }
	@[ -n "$$REDIS_URL_POSTGRES_TEST" ] || { echo "REDIS_URL_POSTGRES_TEST is required for the PostgreSQL integration gate" >&2; exit 2; }
	@bash scripts/run-postgres-tests.sh

## Run the live Redis queue contract in reserved database 15. The gate refuses
## application queues on either test-reserved database and never flushes data.
test-redis:
	@[ -n "$$REDIS_URL_TEST" ] || { echo "REDIS_URL_TEST is required for the Redis contract gate" >&2; exit 2; }
	@bash scripts/run-redis-tests.sh

## Backward-compatible name for the required Redis contract gate.
test-contract: test-redis

## Prove the complete Alembic chain on a newly-created isolated Postgres database.
test-fresh-migration:
	@[ -n "$$DATABASE_URL_TEST" ] || { echo "DATABASE_URL_TEST is required for the migration gate" >&2; exit 2; }
	@KP_DISABLE_DOTENV=1 KP_TEST_PROFILE=postgres $(PY) python -m pytest packages/database/tests/test_migrations_fresh_install.py -k fresh_postgres -p tests.no_skips_plugin

## Read-only live Azure smoke test. Requires explicit opt-in and subscription.
test-live-azure:
	@[ "$$KP_RUN_AZURE_LIVE" = "1" ] || { echo "set KP_RUN_AZURE_LIVE=1 to run live Azure checks" >&2; exit 2; }
	@$(PY) python -m pytest tests/test_azure_onboarding.py -m azure_live -p tests.no_skips_plugin

## Run end-to-end tests.
test-e2e:
	@[ -n "$$KP_E2E_PASSWORD" ] || { echo "KP_E2E_PASSWORD is required for the live E2E gate" >&2; exit 2; }
	@[ "$$KP_E2E_LIFECYCLE" = "1" ] || { echo "set KP_E2E_LIFECYCLE=1 to authorize the local campaign lifecycle E2E" >&2; exit 2; }
	@$(PY) python -m pytest tests/e2e -p tests.no_skips_plugin

lint:
	@$(PY) ruff check .
	@$(PY) ruff format --check .
	@command -v node >/dev/null 2>&1 || { echo "node is required to syntax-check the console" >&2; exit 1; }
	@node --check apps/operator-ui/src/console/app.js

typecheck:
	@$(PY) mypy packages apps

## Static security scanning. Every scanner is mandatory and uses a local ruleset where applicable.
security-scan: security-scan-bandit security-scan-semgrep security-scan-trivy security-scan-dependencies

security-scan-bandit:
	@command -v bandit >/dev/null 2>&1 || { echo "bandit is required (CI pins 1.9.4)" >&2; exit 2; }
	@bandit -r packages apps -q -x "*/tests/*" -ll

security-scan-semgrep:
	@command -v semgrep >/dev/null 2>&1 || { echo "semgrep is required (CI pins 1.171.0)" >&2; exit 2; }
	@SEMGREP_LOG_FILE="$${SEMGREP_LOG_FILE:-/tmp/kp-semgrep.log}" semgrep scan --metrics=off --disable-version-check --no-git-ignore --config=tests/support/semgrep.yml --error packages apps

security-scan-trivy:
	@command -v trivy >/dev/null 2>&1 || { echo "trivy is required (CI pins 0.74.0)" >&2; exit 2; }
	@trivy_version="$$(trivy --version | awk '$$1 == "Version:" { print $$2; exit }')"; \
		[ "$$trivy_version" = "0.74.0" ] \
		|| { echo "trivy 0.74.0 is required; found $${trivy_version:-unknown}" >&2; exit 2; }
	@trivy fs --scanners vuln,secret,misconfig --severity HIGH,CRITICAL --exit-code 1 --skip-dirs .git --skip-dirs .venv --skip-dirs .terraform --skip-dirs data/logs .

## Audit the exact non-development runtime closure exported from uv.lock.
security-scan-dependencies:
	@command -v pip-audit >/dev/null 2>&1 || { echo "pip-audit is required (CI pins 2.10.1)" >&2; exit 2; }
	@set -eu; \
		scan_dir="$$(mktemp -d "$${TMPDIR:-/tmp}/kp-dependency-scan.XXXXXX")"; \
		trap 'rm -rf "$$scan_dir"' EXIT; \
		requirements_file="$$scan_dir/requirements.txt"; \
		mkdir "$$scan_dir/uv-cache" "$$scan_dir/audit-cache"; \
		UV_CACHE_DIR="$$scan_dir/uv-cache" UV_PYTHON_DOWNLOADS=never uv export --quiet --frozen --all-packages --no-dev --no-emit-workspace --output-file "$$requirements_file"; \
		pip-audit --requirement "$$requirements_file" --strict --require-hashes --no-deps --disable-pip --cache-dir "$$scan_dir/audit-cache" --progress-spinner off

## Scan the exact local images produced by verify-images; absence is a failure.
security-scan-images:
	@command -v trivy >/dev/null 2>&1 || { echo "trivy is required (CI pins 0.74.0)" >&2; exit 2; }
	@trivy_version="$$(trivy --version | awk '$$1 == "Version:" { print $$2; exit }')"; \
		[ "$$trivy_version" = "0.74.0" ] \
		|| { echo "trivy 0.74.0 is required; found $${trivy_version:-unknown}" >&2; exit 2; }
	@set -eu; \
		image_prefix="$${KP_IMAGE_PREFIX:-kingphisher/verify}"; \
		[[ "$$image_prefix" =~ ^kingphisher/verify(-[a-z0-9][a-z0-9._-]{0,47})?$$ ]] \
			|| { echo "KP_IMAGE_PREFIX must be a dedicated kingphisher/verify[-unique-suffix] namespace" >&2; exit 2; }; \
		for image in operator-api tracking-api worker migration mock-services; do \
			trivy image --scanners vuln,secret --severity HIGH,CRITICAL --exit-code 1 "$${image_prefix}-$$image:local" || exit 1; \
	done

## Database migrations.
db-migrate:
	@$(PY) alembic -c packages/database/alembic.ini upgrade head

db-rollback:
	@$(PY) alembic -c packages/database/alembic.ini downgrade -1

db-init:
	@$(COMPOSE) exec -T postgres psql -U kingphisher -d postgres -c "SELECT 1 FROM pg_database WHERE datname='kingphisher_test'" | grep -q 1 || $(COMPOSE) exec -T postgres psql -U kingphisher -d postgres -c "CREATE DATABASE kingphisher_test"
	@$(PY) alembic -c packages/database/alembic.ini upgrade head

seed:
	@$(PY) python scripts/seed.py

## Audit verification.
verify-audit:
	@$(PY) python scripts/verify_audit.py

## Build and execute every release and disposable-mock image from an isolated source context.
verify-images:
	@bash scripts/operator/release/verify_images.sh

## Keep the familiar build target, but make it enforce the release contract.
build: verify-images

sbom:
	@set -eu; \
		sbom_cache="$$(mktemp -d "$${TMPDIR:-/tmp}/kp-sbom-cache.XXXXXX")"; \
		trap 'rm -rf "$$sbom_cache"' EXIT; \
		UV_CACHE_DIR="$$sbom_cache" UV_PYTHON_DOWNLOADS=never uv export --preview-features sbom-export --frozen --all-packages --no-dev --no-emit-workspace --format cyclonedx1.5

sign:
	@set -eu; \
		[ -n "$${IMAGE:-}" ] || { echo "IMAGE is required" >&2; exit 2; }; \
		[[ "$$IMAGE" =~ ^[a-z0-9][a-z0-9.-]*(:[0-9]+)?/([a-z0-9][a-z0-9._-]*/)*[a-z0-9][a-z0-9._-]*@sha256:[0-9a-f]{64}$$ ]] || { echo "IMAGE must be an immutable registry/path@sha256:<64 lowercase hex> reference" >&2; exit 2; }; \
		[ -n "$${COSIGN_KEY:-}" ] || { echo "COSIGN_KEY is required" >&2; exit 2; }; \
		command -v cosign >/dev/null 2>&1 || { echo "cosign is required" >&2; exit 2; }; \
		cosign sign --yes --key "$$COSIGN_KEY" "$$IMAGE"
