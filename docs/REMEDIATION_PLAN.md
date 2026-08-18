# Remediation task matrix

This matrix tracks the implementation response to the security, privacy, and
operator review. Work is split into conflict-free waves; shared interfaces are
integrated by the root task after each wave.

| ID | Outcome | Owner files | Acceptance | Depends | Conflict group | Priority | Status |
|---|---|---|---|---|---|---|---|
| SEC-1 | Tracking requests cannot leak identifiers or exhaust limiter memory | `packages/telemetry`, `apps/tracking-api` | Invalid tokens rejected; bounded limiter; emitted logs redact paths/IPs | none | TRACKING | P0 | Complete |
| UX-1 | GUI supports valid role-aware campaign approval and safe scheduling UX | `apps/operator-ui`, console/API approval tests | Approval body/rationale and both approval types work; UI explains identity separation | none | UI | P0 | Complete |
| PRIV-1 | DSR handlers, verification gates, export, erasure, and retention have enforceable postconditions | privacy routes/models/tests and retention worker tests | Non-deletion requests cannot be falsely completed; export gated/comprehensive; deletion removes identifiers; retention covers linked data | none | PRIVACY | P0 | Complete |
| ARCH-1 | Delivery messages are validated against campaign state/ownership and audit appends serialize | queue, delivery, audit store and tests | Cross-campaign assignments rejected; manifest verified; audit head locked and delayed scheduling prevents state race | none | RUNTIME | P0 | Complete |
| OPS-1 | Analysts receive campaign metrics, evidence export, lifecycle and recall outcomes | reporting/lifecycle API and UI | Campaign funnel/detail/export and terminal lifecycle visible | Wave 1 | API/UI | P1 | Complete |
| INT-1 | Sources, alerts, worker health, and deployment controls are operationally safe | source/alert/health/infrastructure | Supported adapters explicit; subscription ownership fixed; sources operable; containers hardened | Wave 1 | OPS/META | P1 | Complete |
| A11Y-1 | Console meets core WCAG 2.2 AA interaction requirements | UI HTML/CSS/JS | labels, focus, live regions, responsive layout and accessible status | UX-1 | UI | Complete |
| AUTH-2 | Browser OIDC uses authorization-code + PKCE and preserves separate principals | auth/console/UI | Login redirect, callback validation, token storage, logout, and dev fallback tests | UX-1 | AUTH/UI | P1 | Complete |
| PROVIDER-2 | Source, mailbox, reminder, and training integrations have working provider contracts | adapters/workers | STIX and bulk imports, mailbox report ingestion, reminders, provider contract tests | ARCH-1 | PROVIDER | P1 | Complete |
| E2E-2 | The complete browser workflow and operational gates are automated | tests/scripts/Makefile | Browser smoke plus lint/operational gates run locally | AUTH-2, PROVIDER-2 | META | P1 | Complete |
| ALERT-2 | Subscriptions produce retryable signed webhook deliveries | alert models/migration/API/worker | Destination validation, signed delivery, retry/DLQ, audit and tests | ARCH-1 | API/DB/RUNTIME | P1 | Complete |
| TENANT-2 | Deployment mode is explicitly single-tenant and fails closed for unsupported shared use | config/docs/runtime | Startup invariant and operator disclosure; multi-tenant mode rejected | none | DOMAIN | P1 | Complete |
| ONBOARD-API | Safe onboarding state, persistence, and connection tests | console API/tests | Secrets never returned/logged; allowlisted writes; bounded fail-closed tests | AUTH-2 | API | P1 | Complete |
| PROVIDER-WIRE | Local provider contracts accept production SMTP, mailbox, Graph, and AI configuration | worker provider/config/tests | Backward-compatible local defaults; optional auth; safe TLS and bounded calls | PROVIDER-2 | PROVIDER | P1 | Complete |
| ONBOARD-UI | Accessible guided setup wires and tests each supported external component | console JS/CSS | Automatic first-run launch; progress, save/test/skip/review/restart | ONBOARD-API, PROVIDER-WIRE | UI | P1 | Complete |
| ONBOARD-E2E | Wizard and provider wiring are documented and regression-tested | E2E/docs/env | No-credential local path passes; production prerequisites are explicit | ONBOARD-UI | META/DOCS | P1 | Complete |
| FRIENDLY-API | Setup metadata, glossary, and secret-safe AI guidance use plain language | console API/tests | Curated fallback; bounded AI; suggestions restricted to step-owned nonsecret fields | ONBOARD-API | API | P1 | Complete |
| FRIENDLY-UI | Wizard and help center explain terminology and guide recovery | console JS/CSS | Welcome, contextual help, searchable glossary, explicit AI suggestion review | FRIENDLY-API | UI | P1 | Complete |
| SETUP-AI | Local AI contract supports deterministic setup assistance | mock AI/tests | Bounded schema; no secrets accepted/echoed; all connector topics covered | PROVIDER-WIRE | PROVIDER | P1 | Complete |
| FRIENDLY-E2E | Help and AI-assisted setup behavior are documented and live-tested | E2E/docs | Local assistant path and fallback path pass without credentials | FRIENDLY-UI, SETUP-AI | META/DOCS | P1 | Complete |
| LOG-OPS | Worker failure logging is bounded and rotated | supervisor/worker runtime/runbook/tests | Connection failures back off; files rotate/compress; normal runtime remains bounded | PROVIDER-WIRE | RUNTIME/OPS | P0 | Complete |
| NTFY-INT | Operators can use ntfy as a minimal-cost alert receiver | alert onboarding/worker/tests/docs | Host allowlist, signed delivery, connection test, retry/DLQ, and explicit save work | ALERT-2, ONBOARD-UI | PROVIDER/UI | P1 | Complete |
| AZURE-AUTO | Single-tenant Azure infrastructure and release automation are reproducible | Terraform/workflow/scripts/docs | Hardened plan/apply, migrations, health checks, protected approval, and validation gates | TENANT-2 | INFRA/OPS | P1 | Complete |
| AZURE-WIZARD | Azure preparation is GUI-guided, explainable, and optionally AI-assisted | console API/UI/tests/docs | Non-secret four-stage wizard, field-source help, validation, reviewed exports, and no automatic deployment | AZURE-AUTO, FRIENDLY-API | API/UI/DOCS | P1 | Complete |
| AZURE-VISUAL | Qualify Azure wizard interaction through the in-app browser | Browser/live console | Focus, help, AI, validation errors/success, and downloads visually verified without real secrets | AZURE-WIZARD | ENVIRONMENT | P2 | Pending — fresh Browser-controller session required |
| SMB-FLOW | Let one authorized SMB administrator create and schedule campaigns without separate approvers | campaign API/UI/live E2E/docs | DRAFT schedules directly; audit, safety validation, cap, recall, and kill switch remain | UX-1 | API/UI/DOCS | P1 | Complete |
| LOCAL-TRAINING | Complete local click attribution without DNS or an external training service | tracking API/seed/config/tests | Seeded link records a click and lands on the loopback awareness page | SMB-FLOW | TRACKING/RUNTIME | P1 | Complete |
