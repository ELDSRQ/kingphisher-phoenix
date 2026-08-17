SHELL := /bin/bash
PY := uv run
COMPOSE := docker compose

.PHONY: bootstrap install verify-install operational-readiness dev mock-stack test test-unit test-contract test-e2e lint typecheck security-scan db-migrate db-rollback db-init seed build sbom sign verify-audit

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
	@uv sync --all-packages
	@$(COMPOSE) up -d postgres redis otel-collector mock-graph mock-ai mock-idp mailpit
	@make db-init

## Start application services for local development.
dev:
	@$(COMPOSE) up -d postgres redis otel-collector mock-graph mock-ai mock-idp mailpit
	@uv run uvicorn kp_operator_api.main:app --reload --port 8000 &
	@uv run uvicorn kp_tracking_api.main:app --reload --port 8001 &

## Run full test suite.
test:
	@$(PY) pytest

## Run unit tests only.
test-unit:
	@$(PY) pytest packages -m "not contract and not e2e"

## Run contract tests.
test-contract:
	@$(PY) pytest -m contract

## Run end-to-end tests.
test-e2e:
	@$(PY) pytest tests/e2e

lint:
	@$(PY) ruff check .
	@$(PY) ruff format --check .
	@command -v node >/dev/null 2>&1 || { echo "node is required to syntax-check the console" >&2; exit 1; }
	@node --check apps/operator-ui/src/console/app.js

typecheck:
	@$(PY) mypy packages apps

## Static security scanning (fail on findings; tools must be installed).
security-scan:
	@$(PY) bandit -r packages apps -q -x "*/tests/*" -ll
	@if command -v semgrep >/dev/null 2>&1; then semgrep scan --config=auto --error packages apps; fi
	@if command -v trivy >/dev/null 2>&1; then trivy fs --scanners vuln,secret --skip-dirs data/logs .; fi

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

## Build containers.
build:
	@docker build -f infrastructure/containers/Dockerfile.operator-api -t kingphisher/operator-api:dev .
	@docker build -f infrastructure/containers/Dockerfile.tracking-api -t kingphisher/tracking-api:dev .
	@docker build -f infrastructure/containers/Dockerfile.worker -t kingphisher/worker:dev .

sbom:
	@$(PY) python -m pip freeze | syft -o cyclonedx-json -

sign:
	@echo "cosign signing wired in CI; local signing requires cosign + key"
