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
| AZURE-VISUAL | Qualify Azure wizard interaction through the in-app browser | Browser/live console | Focus, help, AI, validation errors/success, and downloads visually verified without real secrets | AZURE-WIZARD | ENVIRONMENT | P2 | Blocked (environmental) — browser controller not attachable (extension not connected). Backend layers qualified without a browser: schema, validation errors/success/warnings, Help, privacy-filtered AI assist, Terraform/GitHub export mapping (184 tests, no defects). Rendered visual/keyboard pass + on-disk downloads still need a working browser controller. |
| SMB-FLOW | Let one authorized SMB administrator create and schedule campaigns without separate approvers | campaign API/UI/live E2E/docs | DRAFT schedules directly; audit, safety validation, cap, recall, and kill switch remain | UX-1 | API/UI/DOCS | P1 | Complete |
| LOCAL-TRAINING | Complete local click attribution without DNS or an external training service | tracking API/seed/config/tests | Seeded link records a click and lands on the loopback awareness page | SMB-FLOW | TRACKING/RUNTIME | P1 | Complete |

---

## Status as of 2026-08-26

Closed since the consolidated review (see `RESUME-HERE.md` for the finding IDs):

| Finding | Status |
|---|---|
| NEW-1 zero-width / bidi validator bypass | Fixed (T-01) |
| NEW-2 two-person approval not enforced | Fixed (T-06) — and extended so the two approvals must come from different people |
| NEW-3 no template-approval endpoint | Fixed (T-11/T-14) |
| NEW-4 no external-recipient blocking | Fixed (T-06) |
| NEW-5 tracking API had no body cap | Fixed (T-02) |
| NEW-6 prompt-injection neutralizer dormant | Fixed (T-11) — wired onto the AI path, and the override patterns widened to cover "disregard prior instructions" |
| NEW-7 audit verification on demand only | Fixed (T-09) |
| NEW-8 stale `.env.bak-qa` | Fixed (T-03) |
| NEW-9 `.env.example` bind addresses | Fixed (T-03) |
| NEW-10 `Source.consecutive_failures` dead | Fixed (T-06) — incremented and trips a breaker |
| ARCH-1 oversized delivery message, per-recipient SMTP connect | Fixed (T-06) |
| ARCH-2 stuck QUEUED assignments never reconciled | Fixed (T-06) |
| ARCH-3 Redis persistence disabled | Fixed (T-10) |
| ARCH-4 RSS placeholder parser | Fixed (T-08) |
| ARCH-6 open/click dedup race | Fixed (T-02) |
| ARCH-8 testpaths excluded tests | Fixed (T-03), and `infrastructure/` added in T-11 |
| ARCH-9 zero tests on two packages | Fixed (T-04) |
| HIGH-02res non-UUID OIDC subjects | Fixed (T-05) |
| P-1 generation pipeline dead code | Fixed (T-11) |
| P-2 single-admin weaponization path | Fixed (T-06) |
| P-3 console writes `.env` on Container Apps | Fixed — `OPERATOR_API_CONFIG_STORE=managed` makes those endpoints refuse with guidance |

Found and fixed during the work, not in the original register:

- **Inverted `test_send` flag** (introduced in `d9c800a`): scheduled campaigns
  skipped the "delivery requires an approved template" check and never became
  ACTIVE, while test sends enforced approval and flipped the campaign live. No
  test covered it.
- **One approver could give both approvals**, since only the author was blocked.
- **`az acr build` / bootstrap gap**: a new Azure tenant could not be stood up at
  all without pre-existing VNet infrastructure.

Sender-realism workstream (2026-08-26, landed on `main`):

| Component | Status | Notes |
|---|---|---|
| Sender-persona foundation | Complete | `Campaign.sender_display_name` (migration 0012), `policy.resolve_sender` / `parse_sending_domains` |
| DNS-challenge domain verification | Complete | `kp-domain-verification`: HMAC token, fail-closed TXT observation, exact records (`required_dns_records`) |
| Verified domains + signed RoE models | Complete | migration 0013; signature binds `terms_hash\|signer\|signed_at` |
| RoE gate (schedule + delivery) | Complete | unconditional fail-closed; per-recipient `target_domain_not_roe_covered`; revocation stops delivery |
| Sender personas wired into delivery | Complete | From header display name (SMTP relay path), pool-resolved envelope address |
| Lookalike generator | Complete | candidates under an operator-controlled base + ready-to-paste DNS |
| Relay-agnostic send path | Complete | SMTP relay (SES/Mailgun/Postfix) already generic; persona honored through it |
| Onboarding wizard endpoints | Complete | challenge / verify / list / generate, RoE sign / list / revoke, RBAC `VERIFY_DOMAIN` + `SIGN_ROE` |
| Brand allowlist for neutralizer | Complete | `brand_allowlist` = operator-owned domains; lookalikes inside them are legit lure content |

New env keys: `KP_ROE_SIGNING_KEY`, `OPERATOR_API_DOMAIN_VERIFY_KEY`,
`KP_SENDING_DOMAINS`, `KP_BRAND_ALLOWLIST`. Deliverability truth: mail only
delivers from operator-controlled domains with valid SPF/DKIM/DMARC; the
wizard emits the exact records and the pool only accepts verified domains.

Still open:

| Finding | Note |
|---|---|
| NEW-11 global kill switch advisory-only | Accepted; per-campaign recall is enforced |
| NEW-12 pattern self-approval vacuous | Minor |
| ARCH-5 contracts package decorative | Partly addressed — the generation contract is now real and enforced |
| ARCH-7 in-memory rate limits vs multi-replica | Open. Limits are per-replica on Container Apps; needs a shared store |
