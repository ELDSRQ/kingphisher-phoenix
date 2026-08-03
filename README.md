# Kingphisher-Phoenix — Threat-Informed Phishing Awareness Platform

Internal phishing-awareness platform: **threat-informed, GUI-only, operator-facing**.
All configuration and interaction happens in a browser web console; there is no
CLI workflow. Built from the reconstructed build specification
(`KingPhisher-Reconstructed.md`).

## What you get

- **One-click operation.** On macOS, double-click `Kingphisher Launcher.app`; on
  any platform, run the installer. Everything starts: infrastructure, APIs, and
  six background workers.
- **Browser operator console** at `http://127.0.0.1:8000/console` — dashboard,
  campaigns, recipients, sources, patterns, audit, and settings (including
  Restart / Stop). Secrets are masked; every change is audited.
- **Deterministic safety model** enforced in code: append-only hash-chained
  audit, RBAC with a no-self-approval rule, deterministic safety validation
  outside the AI model, allowlisted sanitized fetching, and a kill switch.
- **Local mock stack** (Postgres, Redis, Mailpit, mock IdP/Graph/AI) so a full
  campaign lifecycle runs offline — including real email delivery into Mailpit.

## Fresh install from GitHub

Requires a 64-bit **macOS** (Apple Silicon or Intel) or **Debian/Ubuntu Linux**
and a working internet connection. Everything else is installed for you:
Homebrew (macOS) / apt (Linux), Docker (Colima on macOS, `docker.io` on Linux),
`uv`, Python 3.13, and all Python dependencies.

```bash
git clone git@github.com:ELDSRQ/kingphisher-phoenix.git
cd kingphisher-phoenix
./scripts/install.sh
```

What the installer does, end to end:

1. Installs missing dependencies (Homebrew, Docker + Colima, `uv`, Python).
2. Creates the project virtualenv and installs all Python packages.
3. Starts Postgres, Redis, Mailpit, the mocks, and the OTel collector.
4. Applies database migrations and seeds a reproducible demo dataset.
5. Builds `Kingphisher Launcher.app` (macOS).
6. Starts the operator API, tracking API, and the six workers.
7. Opens the operator console and prints the login password.

The console password is generated into `.env` (`KP_CONSOLE_PASSWORD`); the
installer prints it. You can change it from the console Settings page at any time.

Re-running `./scripts/install.sh` is safe (idempotent). To health-check a
running install, use `./scripts/verify_install.sh`.

### Stopping and restarting

The console is the control plane:

- **Restart** and **Stop** live in Settings. Stop shuts down every service
  cleanly via the supervisor.
- On macOS you can later relaunch everything by double-clicking
  `Kingphisher Launcher.app` again.

## Manual start (dependencies already installed)

```bash
make bootstrap        # uv sync + compose infra + db init
make seed             # idempotent demo dataset
make dev              # operator-api :8000, tracking-api :8001 (foreground)
```

Or the GUI path without the installer:

```bash
./scripts/run_console.sh   # starts infra, migrates, seeds, opens the console
```

## Development

```bash
make test             # full pytest suite
make lint             # ruff check + format check
make typecheck        # mypy (strict)
make verify-audit     # recompute + verify the audit hash chain
make security-scan    # bandit / semgrep / trivy (best-effort, non-gating)
make verify-install   # health-check a running local install
```

## Repository layout

```
apps/operator-api/     Operator API (:8000) + browser console endpoints + SPA mount
apps/operator-ui/      Vanilla-JS operator console (no build step)
apps/tracking-api/     Tracking API (:8001): stateless pixel/click endpoints
apps/workers/          kp-worker CLI: ingestion, generation, delivery,
                       retention, mailbox, reminder
packages/              Core packages (domain-models, database, auditing,
                       authorization, contracts, sanitization, safety-validation,
                       telemetry, templating, source-adapters, campaign-patterns,
                       test-fixtures)
scripts/               install.sh, verify_install.sh, run_console.sh,
                       supervisor.py, build_launcher_app.sh, seed.py,
                       verify_audit.py
infrastructure/        Dockerfiles, docker-compose services, mock services,
                       otel-collector config, postgres role bootstrap
Kingphisher Launcher.app   macOS double-click launcher (buildable artifact)
```

See `docs/architecture/` for the service and zone matrix, and
`scripts/verify_audit.py` for audit integrity.

## Security model

Non-negotiable boundaries enforced in code:

- Append-only, hash-chained audit (`kp_auditing`) — chain integrity verifiable
  with `make verify-audit`
- RBAC roles with a hard no-self-approval rule (`kp_authorization`)
- Deterministic safety validation outside any AI model (`kp_safety_validation`)
- Sanitization: allowlisted HTTPS fetching, HTML→plain-text, instruction/Unicode
  neutralization (`kp_sanitization`)
- Fail-closed error handling (error taxonomy `KP-001..010`)

Zone-crossing restrictions, secrets handling, and encryption-at-rest are
documented in `docs/architecture/` and enforced progressively as services are
completed.
