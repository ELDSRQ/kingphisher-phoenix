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
