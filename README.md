# Kingphisher-Phoenix

Kingphisher-Phoenix is a single-tenant phishing simulation and security-awareness platform. The product direction is deliberately simple: an operator uses one browser console, while deterministic policy code—not an AI model—controls authorization, audience scope, content safety, delivery, and evidence.

The build is useful for local development and controlled demonstrations. It is **not yet approved for production or an RSA Conference campaign**. Live Azure/Entra, Graph/Outlook, ACS, browser-accessibility, recovery, AMD64, registry, and security release evidence is still required. The authoritative status, findings, and remaining work are in [the integrated build plan](docs/WAVE-BUILD-PLAN.md). Its goal-aligned policy now prioritizes the minimum two-operator/125-user workflow and explicitly defers commercial-parity breadth that does not support threat curation, safe simulation, training, defensible five-year outcomes, GUI deployment, or production qualification.

## Engineering worker architecture

The controller workspace remains on this Mac. The current engineering topology
uses the Apple Silicon worker at `192.168.1.140`, the canonical remote source at
`/Users/edierks/Projects/kingphisher-phoenix`, and a read-only source mount in
the project-only `kingphisher` Colima VM. Its VM, cache, client metadata, and
socket are rooted under `/Volumes/DockerExternal/KingPhisher-Phoenix`
on the attached 1 TB `DockerExternal` drive. Once verified, every project
command selects that socket explicitly. The inactive `kp-external-mac`
controller context has the exact endpoint
`ssh://edierks@192.168.1.140/Volumes/DockerExternal/KingPhisher-Phoenix/colima/kingphisher/docker.sock`
and returns `colima-kingphisher|aarch64|/var/lib/docker`;
the default context remains `desktop-linux`. A missing,
read-only, wrong-UUID, or
low-capacity drive fails closed; there is no fallback to Docker Desktop and the
global context remains `desktop-linux`.
The legacy Docker contexts named `DockerExternal` and `kp-remote-mac` omit the
reviewed socket path and can resolve to shared Docker Desktop; never use them
for this project. The similar `DockerExternal` volume label is storage, not a
Docker context.

The external-engine preflight passed with the fixed volume UUID, native
aarch64/VZ profile, external paths/socket, disabled Rosetta/binfmt, read-only
canonical source mount, isolated Compose plugin, and unchanged ambient
`desktop-linux` context. Snapshot `20260829T013332Z-tsX1WQ` (archive SHA-256
`e4fb16a735d0c9d3b6aa04381c4c9d7e24269006203c551f50abf671cc3637ff`)
passed decryption, structure, PostgreSQL, and Redis validation and was staged.
The earlier `20260828T213826Z-LtLsO5` snapshot is preserved but invalid for
restore because it contains AppleDouble `._redis.rdb`; the oldest legacy
snapshot remains unrecoverable because its identity is absent.

The internal seven Docker Desktop project containers are stopped and preserved;
unrelated containers remain running. As of 2026-08-31 the duplicate project
stack on the controller Mac is stopped as well, with every container and volume
preserved, so `192.168.1.140` is the only engine running this project. The non-deleting source sync excluded
secrets, data, `.git`, evidence, and environment state. External restore proved
39 PostgreSQL tables, Redis DB 0 at 766→766 keys and DB 15 at 12→12, then the
installer reached migration head `0029`, durable-canary seed, ready preflight,
and a running seven-container external infrastructure plus supervisor/APIs/workers.
The first cold installer invocation timed out at 120 seconds while containers
continued to completion; its idempotent rerun passed. The local installer fix
now defaults to 900 seconds, caps at 3600, validates strictly, and passed 42
tests. The fix is synced and its non-mutating remote `--check-uv` prerequisite
passed; no cold full installer rerun under the new default is claimed.

The pre-remediation local and external QA snapshot passed: operational readiness
reached migration head `0029`; 2,329 hermetic tests passed with 97 deselected;
PostgreSQL passed 86 with 2,340 deselected while isolated on Redis DB14; Redis
passed 2 with 2,424 deselected on DB15; audit and `verify_install.sh` passed;
and all 8 E2Es passed. Its 03Z API/worker log window contained no
error/critical event and no unknown-campaign or unknown-pattern job. After the
provider-aware GUI, privacy, OIDC, credential-rebinding, and release-verifier
repairs, the pre-Wave-36 hermetic `make test` passed 2,469 tests with 97
deselected and 0 failures in 158.15 seconds. The checked-in migration chain now
advances to `0032_source_explicit_curation`; the final local Wave 36 hermetic
suite passed 2,501 tests with 97 deselected and 0 failures in 183.40 seconds.
Wave 38's checkpoint then landed (commit `d25313d`): the retention P1 is
closed, the migration revision-id defect is fixed, and current-head hermetic
`make test` passes 2,620 tests with 103 deselected and 0 failures in 180.45
seconds. External PostgreSQL (92 passed, including fresh-install/historical
migration to `0032`) and Redis (2 passed on DB15) profiles passed on
2026-08-29; E2E and exact-image results remain pending. External
preflight re-proved the exact project engine and volume with approximately
744,006,440 KiB free. Ruff/format over 336 Python files, strict mypy over 124
source files, Bandit, Semgrep over 4 rules/125 targets with 0 findings, Trivy
repository scans with 0 HIGH/CRITICAL vulnerabilities, secrets, or
misconfigurations, pip-audit with no known vulnerabilities, Actionlint, and Zizmor are green
within their recorded scopes. Exact-final image qualification remains open. Production and
RSA Conference use remain **NO-GO** until live Azure/provider, real-browser/WCAG
and human assistive-technology, exact-final image/native AMD64/registry
attestation, and rollback evidence pass.

The evidence-conditional native image gate requires the exact Docker server platform with no
emulation, explicit `--platform`, OS/architecture/image-ID metadata for all
five images, unchanged source and context manifests, Trivy 0.74.0, retained
no-clobber `qualification.json` plus scan evidence, and proof that only labeled disposable
resources were cleaned up. It also requires the expected source-manifest digest,
binds the exact Trivy executable/hash/cache, retained empty config/ignore/secret policy files, rejects ambient `TRIVY_*`
overrides, records fresh database/check-bundle metadata, and makes the verified
cache immutable before scanning. The Azure workloads stage likewise scans each exact
immutable ACR `repository@sha256` subject with pinned Trivy before SBOM,
attestation, or deployment and retains scan JSON plus checksums. These controls
are implemented; only the retained evidence can establish an exact-final pass.

Recovery used the reviewed controller chain: `checkpoint-remote.sh`, then
`stage-remote.sh`/`stage-checkpoint.sh`, then external-engine-scoped
`restore-state.sh` consuming the reserved `migration-checkpoint/` payload. That
evidence completes `EXT-002`; it does not complete later release gates.
Loopback console/Mailpit URLs refer to whichever engine is actually running the
project on `.140` and require a browser there or an SSH tunnel. Rosetta is
disabled and unnecessary for native ARM64; native AMD64 remains a separate
release gate. See [the external-worker runbook](scripts/operator/remote-docker-worker/README.md)
and [the Wave 30 task matrix](docs/PRODUCTION-READINESS-TASK-MATRIX.md).

This USB/HFS+ worker is engineering infrastructure, not the Azure production
topology. It is unencrypted and lacks SMART telemetry, so use synthetic or
explicitly approved test data and retain encrypted recovery copies.

## Current shape

The production-oriented topology has three deployables:

1. **Operator API and web console** — the private control plane for setup, recipients, audiences, campaigns, training, reporting, audit, and emergency controls.
2. **Tracking and training API** — the public, deliberately narrow boundary for opaque open/click bearers and recipient training pages.
3. **Multi-role worker** — one supervised process for ingestion, generation, delivery, retention, reminders, alerts, directory synchronization, reported-mail ingestion, and audit-head witnessing. Delivery can be isolated as an optional scale/security choice.

Local development still runs the nine worker roles (ingestion, generation, delivery, retention, mailbox, reminder, alert, directory, audit-anchor) as separate child processes so that individual roles are easy to inspect. That is a development implementation detail, not the Azure deployment topology.

Implemented locally includes:

- Entra-compatible OIDC discovery, exact issuer/audience checks, PKCE, and role mapping, with a separate loopback-only development identity path.
- Exact campaign audiences using static or directory groups, filters, explicit inclusions/exclusions, deterministic samples, preview, and a frozen manifest. Legacy campaigns cannot silently fall back to all active recipients.
- Signed Rules of Engagement with bounded canonical fields, strict ASCII/A-label domain/suffix checks, aware ordered UTC windows, at most 100 domains, and a minimum 256-bit key; immutable typed RBAC snapshots; UUID-canonical self-approval; separated security/privacy approvals outside development; and a persistent emergency stop. Wildcard/malformed capabilities, unknown roles, ambiguous Unicode/IP/single-label domains, and identifying denial detail fail closed.
- Crash-aware delivery claims and provider correlation, opaque tracking bearers with keyed verifiers at rest, a Redis-backed atomic queue lifecycle, retry, delayed work, and dead-letter handling.
- Purpose- and assignment-bound awareness links: delivery resolves a mandatory placeholder to the recipient's tracking click, the click issues a separate lesson-open bearer, completion uses a different purpose, and reminders re-derive only the stored assignment's open credential. Static legacy training destinations fail delivery closed.
- A finite Program Planner that materializes 2–12 independently reviewed campaign occurrences on an allowlisted elapsed-day cadence, with duplicate-safe creation and forward-only pause/resume. It is not an adaptive scheduler and does not automate approval, targeting, or sending.
- Denominator-explicit campaign funnels and bounded longitudinal Executive Trends in JSON, CSV, and the GUI, plus the named close disposition, the confirmed-interaction distinction, basic repeat history, and the five-year pseudonymous ledger trend/repeat consumers (ANA-010). Advanced cohorts, causal training-efficacy claims, scheduled reports, and a general scanner/bot corrections workflow are explicitly deferred.
- Microsoft Graph directory preview/apply/discard with a latest-request-wins fence around provider I/O, plus Microsoft 365 reported-message polling with bounded cursors/paging, replay, MIME, and exact-correlation controls.
- SMTP for local development and Azure Communication Services Email support with custom-domain/DNS readiness, pacing, provider correlation, an explicit ACS managed-identity client ID, and Entra-authenticated Event Grid receipt ingestion. Live subscription and receipt qualification remain pending.
- Transactional business/audit/queue intent and a database-controlled append-only audit dispatcher. Completion preserves native UUID binding. Final local acceptance exposed and fixed an audit-store owner-fallback revocation defect, reconciled 36 stranded idempotent queue intents, and left the audit chain green without exposing statement, parameter, or driver detail.
- A create-only audit-head witness targeting a separate locked Azure Blob WORM container; the local permission boundary passes, while live Azure evidence remains pending.
- Dependency-aware API health, centrally redacted structured logs, and bounded worker metric snapshots; the managed workload gate requires exactly one active Healthy/Provisioned worker revision, two consecutive simultaneous ready observations for every enabled role, and a same-revision health recheck. Live Azure collection, alerting, dashboards, and execution of that gate are not yet qualified.
- A guided console for integrations and Azure preparation, with privacy-filtered advisory AI help. Email and reported-mailbox providers are explicit selects whose active fields alone are required, tested, saved, and shown to AI; inactive saved values remain preserved. SMTP and Mailpit retain their bounded probes, ACS is clearly labeled non-sending reachability-only, and Microsoft 365 uses one quoted, bounded Graph delta path with fail-closed bearer/status handling. Setup assistance receives active non-secret fields only, and provider/destination changes require validation before an atomic credential rebind. The current implementation requires an approved non-local HTTPS AI gateway implementing `/propose` and `/setup-assist`; pattern approval durably records a generation request and never reports asynchronous queue/provider completion as complete. The generation worker now enforces a pinned model identity (`KP_WORKER_AI_MODEL_ID`, fail-closed in managed mode, constant-time compare, with response-byte/pin/mismatch metrics — AI-010 worker increment). This remains an adapter contract, not a supported default deployment path: the goal-aligned plan prioritizes the digest-pinned internal model executed by the existing worker image/job and treats Foundry serverless as an optional fallback. Actual model benchmark/selection and the pinned llama.cpp deployment still require a live endpoint; live provider generation remains unqualified.
- Server-derived capabilities drive console session validity, visible navigation, and available actions; missing, unknown, or stale authority fails closed.
- Authorized operators can create supported sources and repeatedly enable, disable, or request ingestion from the GUI with audit evidence. A disable cannot abort provider I/O already executing, but the worker rechecks source state under a database lock after fetch and discards the result before content writes when disable wins. A returned job ID is a request reference, not a status link.
- Source ingestion now also requires a current, explicit terms acknowledgement. Operators can record, inspect, and revoke the bounded permission record in the GUI; enable/ingest and the worker both fail closed when terms are missing, expired, revoked, incomplete, or replaced during provider I/O.
- Generation uses one strict request/response contract from queue through AI provider, persistence, review, and recipient delivery. Inputs have field, collection, and aggregate byte limits; provider JSON is streamed with declared/decoded byte caps; generated subject/body fields match storage and preview limits; and a durable queue idempotency key prevents duplicate drafts/provider calls during retries and races.
- The governed training-resource library supports bounded text authoring, submit, independent approve/reject, approved-resource supersession, safe preview, and an assessed knowledge check with idempotent completion. Training assignments use one fixed 72-hour due policy; the former ignored reminder setting was removed. Migration `0026` creates the library and least-privilege grants, `0028` binds each campaign to one exact approved lesson, `0029` adds the durable reviewed-canary launch gate, and checked-in head `0030` persists a safe default privacy notice while enforcing one current notice with a unique partial index; head `0031` adds the PII-free 1,826-day awareness ledger, `0032` quarantines legacy auto-active threat evidence with migrated retention-policy bounds, and head `0033` adds the campaign-bound all-or-nothing knowledge check with deterministic evidence builder and digest pinning (TRN-010). The current-head external PostgreSQL profile passed 92 tests on 2026-08-29, including fresh-install/historical migration to `0033`. The server derives `can_submit`/`can_review` for each principal/resource/state, and the GUI fails closed if either flag is missing or malformed.
- Recipient management and reporting use server-side pages rather than unbounded lists. Authorized exclusion managers can create global or campaign-scoped exclusions, inspect bounded active/recent history, and explicitly revoke without deleting audit history; migration `0027` adds that lifecycle.
- Campaign launch is explicitly two-phase: review locks the exact configuration, RoE, audience, template, training lesson, and server-designated test accounts; scheduling sends only that canary cohort. Full publication is a separate GUI action and remains blocked until current provider-derived evidence is bound to the unchanged review. SMTP-like transports require provider acceptance, while ACS requires authenticated delivered receipts.
- Campaign reporting combines aggregate operational/funnel evidence with capability-protected named outcomes and capability-protected CSV exports. Alert subscriptions can be listed, created, and owner-disabled in the GUI; external webhook/ntfy destinations require an explicit HTTPS hostname allowlist.
- The public tracking boundary caps streamed/declared bodies and request targets, rejects ambiguous content lengths and untrusted forwarding, stamps hardening/privacy headers on early errors and redirects, and exposes only stable failure responses. Managed Azure supplies `TRACKING_API_TRUSTED_PROXIES` from the exact Container Apps infrastructure subnet plus loopback; the API accepts forwarding only from a trusted direct peer and resolves a bounded canonical `X-Forwarded-For` chain right-to-left while Uvicorn proxy rewriting remains disabled.
- Managed operator/tracking/worker configuration hides secret inputs and parser exception chains. Worker roles require only their own provider settings and reject local or credential-bearing provider URLs outside disposable development.
- Operator and tracking disable their public OpenAPI, Swagger, ReDoc, and HTTP metrics routes. Their former write-only internal metric registries were removed; dependency/security state remains available through bounded health and logs, while workers retain bounded operational snapshots.
- Audit verification publishes only aggregate status and a bounded problem count to readiness/health state; the scheduler does not retain or expose raw verification problems.
- The browser capability vocabulary exactly matches the backend, visible non-Azure actions are capability-gated, Help is available to aggregate-read roles, and template reviewers can safely preview without receiving authoring/cloning authority. A reviewed manifest covers all 113 operator routes: 103 capability-protected and 10 dedicated/public routes. Browser execution remains unqualified.
- Campaign/source/pattern/privacy/rationale request fields and results are normalized and bounded at the API, not trusted to browser validation. Campaign/pattern action flags are server-derived and fail closed. Operator and tracking validation responses expose capped structural locations/counts rather than rejected values, credentials, provider bodies, or unbounded validation detail.
- OIDC discovery/token/JWKS, setup-assistant, generation-provider, and GitHub deployment metadata/status/activity responses are streamed and byte-bounded before UTF-8/JSON/schema handling. Duplicate or malformed `Content-Length` fails closed, and dispatch classifies status without buffering hostile response bodies.
- OIDC endpoints are bound to the configured issuer origin, DNS-resolved once and pinned for the request while preserving TLS Host/SNI, and used with environment proxies, HTTP/2, and redirects disabled. Cross-origin authorization redirects fail before browser navigation, while cross-origin token/JWKS endpoints fail before code or credential transmission. Privacy exports are authenticated `POST` operations; privacy list/export data is `private, no-store`, and cookie-authenticated mutations require trusted same-origin CSRF metadata.
- Privacy has a persisted safe default at checked-in head `0030` and a database-enforced single-current invariant. The console loads request operations independently from the current notice, so a notice read failure produces a warning without disabling request listing or mutation.
- Operator HSTS, deployment preflight, and release-readiness behavior have local contract tests only. No production edge, custom-host header observation, WAF policy, restore, or rollback qualification is claimed.

The former shared-secret tracking correction endpoint is retired: `/v1/corrections` always returns HTTP 410 and records nothing, while its obsolete runtime/Terraform secret has been removed. Current analytics preserve observed evidence and explicitly do not subtract scanner/bot activity; a normalized, dual-reviewed correction workflow is deferred.

These are implemented capabilities, not proof that an Azure tenant, Graph consent, ACS domain, Outlook mailbox, or browser workflow has been qualified live.

## Local development

Supported hosts are 64-bit macOS and Debian/Ubuntu Linux. A working Docker engine and internet access are required for initial dependency installation.

```bash
git clone https://github.com/ELDSRQ/kingphisher-phoenix.git
cd kingphisher-phoenix
./scripts/install.sh
```

The installer creates local secrets, installs the Python workspace, starts PostgreSQL, Redis, Mailpit, mocks, and telemetry support, migrates and seeds the database, and starts the local supervisor. The console is normally available at `http://127.0.0.1:8000/console` and Mailpit at `http://127.0.0.1:8025`.

Both one-click local paths fail closed before changing a stopped stack. They require 8 GiB of available disk by default, validate preserved recovery credentials and cross-service key mirrors before dependency synchronization or any `.env` write, run the read-only deployment preflight in `prestart` mode to prove a clean first deployment or the exact preserved volume identity, qualify each stateful image digest and host-platform manifest with a hardened ephemeral probe, and only then start missing Compose services with `--no-recreate`. After frozen/no-sync migration, audit bootstrap, and the idempotent seed, the `ready` preflight requires healthy PostgreSQL/Redis and the current migration head before application processes start. `KP_LOCAL_MIN_FREE_GIB` may change the headroom threshold only to a positive whole-GiB integer. A low-disk, partial-volume, malformed/truncated inventory, or ambiguous PID/readiness result stops with preservation guidance; it never authorizes cleanup. A second launcher invocation opens the existing console only when both its supervised PID and `/readyz` are valid.

The disposable local stack uses a generated console credential and mock identity/provider services. Managed Azure mode does **not** use the shared development password or the local HS256 session as its identity authority; it uses Entra OIDC and refuses development-only configuration fallbacks.

Routine local restart remains available in console Settings. Full shutdown is deliberately not exposed through the browser or an HTTP endpoint because it would require an out-of-band relaunch; the obsolete stop capability and marker handling are absent from the browser, supervisor, and launcher. Use the OS launcher or a host signal for that recovery operation. The focused removal lane passed 39 tests.

Useful development commands:

```bash
make bootstrap
make seed
make dev
make lint
make typecheck
make test
make test-unit
make test-postgres
make test-redis
make test-fresh-migration
make security-scan
make operational-readiness
```

`make test` is hermetic. PostgreSQL, Redis, local E2E, and Azure-live tests have explicit opt-in profiles, and every invoked profile rejects skips. PostgreSQL integration jobs are isolated on Redis DB14 and flush only DB14 immediately before and after that profile; the Redis queue contract uses DB15, and neither test profile may touch application DB0. Bootstrap, development, and console launch use the frozen `uv.lock` without mutating it. Local Compose and mock-service base images are pinned by immutable manifest digest; the mock Python runtime is a fully pinned, hash-verified 17-package closure. `make security-scan` fails closed if frozen export or audit fails and audits the 58-package external production workspace closure in strict no-resolution/hash-verified mode. `make sbom` emits native CycloneDX 1.5 with 59 total components, including 58 external package PURLs. Seeding is intentionally source-checkout-only through `make seed`; the broken installed `kp-seed` wrapper was removed. `make sign` now fails closed unless `IMAGE` is an immutable digest reference, `COSIGN_KEY` is present, and `cosign` is installed; no external signature has been produced or verified in this build. `./scripts/run_console.sh` is a local convenience path. `./scripts/verify_install.sh` checks an already running local installation against the actual supervisor child map and dependency-aware `/readyz` endpoints. `make operational-readiness` fails fast on low disk, an unresponsive Docker engine, invalid Compose configuration, or unhealthy required services before running the strict local profiles, and it does not print connection URLs. These are engineering/qualification tools; the product goal remains GUI-driven routine setup and operation.

## Azure and mail integration

Terraform describes a single-tenant Azure deployment using Container Apps, PostgreSQL, Managed Redis, ACR, Key Vault references, managed identities, ACS Email, and bounded Azure logging. Runtime workloads use distinct identities and least-privilege database URLs; the migration job alone receives migration authority. Provider access can add separate directory and mailbox identities to the worker deployment without creating more continuously running applications.

The deployment workflow, Terraform, API, and GUI now share three explicit stages. `foundation_bootstrap` plans and applies the complete `deploy_workloads=false` foundation, including the ACR, private-network, data, ACS/email/domain, and DNS resources needed by later stages. It uses no Terraform targets, initiates Domain/SPF/DKIM/DKIM2 verification, and explicitly forbids sender/association changes. `foundation_finalize` requires fresh all-four Verified readback, permits only the exact association/sender changes, and proves both with authenticated post-apply readback. `workloads` revalidates the exact resources before immutable runtime deployment. The GUI rejects the seven obsolete human readiness fields, restores the owner's latest environment plan, advances only by creating a digest-bound next-stage plan, and displays the bounded `kp.acs-stage-result.v1` artifact and its scope limits. GUI-exported Terraform values and preflight now enforce the same exact ACS endpoint contract. Managed AI is required to use an approved HTTPS gateway, and pattern approval records a durable generation request rather than claiming asynchronous queue/provider completion. The workloads stage requires exactly one active Healthy/Provisioned worker revision, every enabled role ready in two consecutive simultaneous observations, and a same-revision final health recheck before the environment checkpoint can pass. Every stage refuses delete/replacement plans, and the connector is pinned to workflow SHA-256 `888c1764b3a15d6c2cbba7f690dc936e7607a3cf61d41b5eb39d008a3e6f4486`. The 2026-08-29 read-only GitHub re-audit proves valid `ELDSRQ` authentication with `repo`/`workflow` scopes; a public, enabled repository with default branch `main`; Actions enabled; and the Azure workflow active. It found no billing-disabled run signal, but also zero environments, variables, secrets, rulesets, or workflow runs, an unprotected `main`, disabled secret scanning and push protection, and remote `main` at old-tree SHA `1403d944a40214714b6cbfcf5cbabc4fa7225eb9` at re-audit time; the checkpoint push has since advanced remote `main` to `c9ea716`. Current Azure management-plane state could not be revalidated because sandbox DNS could not resolve `management.azure.com`; the older read-only inventory is historical, not current proof. No workflow dispatch/run, remote backend, Azure apply, DNS propagation, AI-provider generation, provider delivery, inbox placement, or human mailbox acceptance has passed. See [Azure deployment](docs/AZURE_DEPLOYMENT.md) and [the build plan](docs/WAVE-BUILD-PLAN.md).

The `private` Azure network mode is the required target, but its Terraform runner must already have VNet access; a new VNet cannot provide network access to the same hosted job that is creating it. The `starter` mode is therefore a narrowly bounded first-foundation option for an empty non-production tenant only. It exposes data planes, is refused for production, and must be replaced by `private` before recipient data or campaign workloads are introduced. Each reviewed request retains bounded hash-chained checkpoints and recovery evidence. An interrupted or ambiguous dispatch is reconciled against that same request and GitHub run; it is not blindly re-dispatched or treated as permission to remove existing resources.

Supported mail paths are:

- **Mailpit** for an offline/local simulation.
- **Generic SMTP** for an explicitly configured relay.
- **Azure Communication Services Email** for managed deployment, using an organization-controlled custom domain and current DNS/readiness evidence.

Microsoft 365 support includes Graph directory synchronization and polling an authorized reported-phishing mailbox. Live tenant consent and end-to-end provider evidence remain release gates.

## Security boundaries

- The operator, public tracking, worker, migration, directory-provider, and mailbox-provider authorities are separated in managed Azure deployment. Runtime applications do not receive the database administrator URL.
- Recipient identity fields are authenticated-encrypted; mailbox equality uses a salted digest. New ciphertext is a versioned, key-ID-bound AES-GCM format. Runtime configuration supports one active encryption key and at most four prior decrypt-only keys, including bounded legacy-unversioned reads. In managed Azure, prior-key input is metadata-bound legacy/recovery support only: the first foundation fixes the active key ID, later dispatches cannot change it, and active-key rotation is deliberately blocked. The active KEK is still Terraform-generated and remains in protected Terraform state/history; `prevent_destroy` also makes teardown an explicit reviewed exception. Safe pre-stage/prove/promote rotation, a database decrypt canary, bulk re-encryption, and proven prior-key retirement remain design debt. This is direct application-layer encryption, not envelope encryption.
- URLs carry random opaque tracking/training bearers. The database stores purpose-scoped keyed verifiers rather than a reusable bearer value.
- Mutations stage audit and queue intent in the same database transaction. A database-owned dispatcher serializes the hash chain and runtime roles cannot modify audit evidence directly.
- Failed queue dispatch persists only the fixed `queue_dispatch_failed` code in durable outbox state; provider/driver exception text is not retained there.
- Periodic audit verification retains only aggregate status and a bounded problem count; raw verification problem details are not kept in scheduler state, health output, or logs.
- The database audit root is periodically witnessed by a create-only, managed-identity worker into a separate locked Azure Blob WORM container. That boundary is implemented and permission-tested locally; independent tamper-evidence is not a production claim until the storage policy, identity, alerts, and recovery behavior pass live Azure qualification.
- Outbound fetching is HTTPS-allowlisted, DNS-pinned/revalidated, globally routable only, streamed, and size/content-type bounded.
- Public tracking rejects oversized requests and malformed or duplicate `Content-Length` fields before route work, minimizes forwarding trust, and applies no-store/no-referrer/frame/content hardening to redirects and errors.
- Settings and provider URL validation suppress input values and low-level exception chains so a failed startup or public request does not reflect credentials or internal locations.
- Redis rate limits are used in managed multi-replica mode; cookie-authenticated mutations enforce request-origin controls.
- `/livez` reports process liveness and `/readyz` fails when required dependencies or audit health are unavailable.
- Production unexpected-error logs expose only bounded event/type and safe operational references; 21 former traceback/exception-message sites across worker/outbox/supervisor and audit/scheduler/rate-limiter paths were hardened without changing operational behavior. Reviewed operator/auth/analytics boundaries also translate backend failures into stable allowlisted public messages.

For trust zones and data flows, read [the architecture description](docs/architecture/README.md).

## Repository layout

```text
apps/operator-api/     Private control plane and console host
apps/operator-ui/      Browser console (vanilla JavaScript, no build step)
apps/tracking-api/     Public tracking and training boundary
apps/workers/          Worker roles and provider adapters
packages/              Domain, database, queue, security, telemetry, and test packages
infrastructure/        Local containers, Azure Terraform, and image definitions
scripts/               Development, migration, release, and qualification tooling
docs/                  Architecture, deployment, handoff, and canonical build plan
```

## Release truth

Do not infer production readiness from a passing unit suite, Terraform validation, an image build, or a local Mailpit campaign. Evidence is labeled as:

- **Local/static:** code, unit/integration tests, linters, schema migration, Terraform validation, scanners, and container checks.
- **Local live:** running disposable PostgreSQL/Redis/APIs/workers and Mailpit workflow checks.
- **Cloud/provider live:** disposable Azure deployment, Entra principals/roles, Graph consent and delta behavior, ACS custom-domain delivery events, Outlook report ingestion, browser accessibility, backup/restore, edge controls, and operational recovery.

Only the first two evidence categories have substantial coverage. The historical pre-Wave-30 result was 1,994/87/2/8, the superseded intermediate external result was 2,230/86/2/8, and the now pre-remediation integrated snapshot was 2,329 hermetic/97 deselected, 86 PostgreSQL/2,340 deselected at head `0029` using Redis DB14, 2 Redis/2,424 deselected using DB15, and 8 E2Es, plus installation/audit verification and a clean 03Z error log window. The pre-Wave-36 local hermetic `make test` passed 2,469/97 deselected with 0 failures in 158.15 seconds. The final local Wave 36 hermetic suite at checked-in head `0030` passed 2,501/97 deselected with 0 failures in 183.40 seconds. Current-head `0032` hermetic passes 2,620/103 deselected with 0 failures in 180.45 seconds, and the external PostgreSQL (92) and Redis (2, DB15) profiles passed on 2026-08-29; E2E external reruns at `0032` remain pending. That durable-gate Mailpit canary is historical local-live evidence only. External preflight reports approximately 744,006,440 KiB free, and restore passes through snapshot `20260829T013332Z-tsX1WQ`, but exact-final images remain open. AMD64/registry, browser/WCAG, Azure/Entra/Graph/ACS/Event Grid/Outlook/DNS/inbox, final recovery/rotation, and human acceptance remain unwitnessed. This build is not claimed to have KnowBe4 parity. The decision remains **NO-GO**.
