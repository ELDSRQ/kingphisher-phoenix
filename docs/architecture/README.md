# Architecture

This document describes the implemented architecture and its trust boundaries. It does not certify a production deployment. Current release status and acceptance evidence live only in [the integrated build plan](../WAVE-BUILD-PLAN.md).

## Design rules

- Single tenant only. A shared multi-tenant mode is rejected rather than partially isolated.
- Browser console for normal product operation. Shell, Terraform, and release scripts remain bootstrap/engineering gaps, not product workflows.
- Three deployables by default. Add feature modules inside them instead of adding services.
- AI is advisory. Deterministic code owns authentication, authorization, scope, content policy, delivery safety, and audit.
- Public tracking is isolated from the private operator control plane.
- Managed deployments fail closed when production providers, secrets, Redis limits, or audit health are missing.

## Pending goal-alignment changes

The implemented architecture remains as described below, but new work follows
the [goal-aligned priority policy](../WAVE-BUILD-PLAN.md#goal-aligned-priority-policy-2026-08-29).
That policy targets one 125-person tenant operated by two IT staff and proposes
three material changes that are not yet implemented:

- creator plus one independent operator using a combined safety/privacy review,
  instead of requiring three distinct people;
- a separate pseudonymous 1,826-day awareness ledger while raw interaction data
  remains bounded to 365 days; and
- a digest-pinned internal model executed by the existing worker image/role as
  the preferred AI path, with Foundry serverless optional and no Foundry
  managed-compute or always-on-GPU requirement.

The source curation workbench, named disposition/five-year graph,
campaign-specific micro-training, and simplified Azure discovery wizard are
also target behavior rather than current capability. Do not infer them from the
implemented source administration, generation contract, generic training, or
three-stage deployment connector.

## Deployable topology

```text
                         Microsoft Entra
                                |
                                | OIDC code + PKCE, roles
                                v
Operator browser ------> Operator API + console
                              |      |  \
                  business DB|      |   \ reviewed queue intent
                              |      |    v
                              |   PostgreSQL <---- migration job
                              |      ^   |              (one-shot)
                              |      |   | transactional outbox
                              |      |   v
                              |      | DB-owned audit dispatcher
                              |      |
                              v      v
                         Managed Redis <------ Multi-role worker
                                               |    |       |
                                               |    |       +--> AI/source/webhook providers
                                               |    +----------> Graph directory/reported mailbox
                                               +---------------> SMTP or ACS Email

ACS Event Grid --Entra app role--> Operator receipt endpoint --minimized/HMAC--> Redis

Recipients ------------> Tracking + training API ----> least-privilege PostgreSQL
       opens/clicks and opaque training bearers
```

The default managed deployment contains:

1. `kp-operator-api`: private control plane, web console, OIDC, configuration/readiness, campaigns, recipients, training administration, reporting, audit inspection, and safety controls.
2. `kp-tracking-api`: narrow public ingestion and training renderer. It does not serve the operator console or receive operator/audit secrets.
3. `kp-worker supervise`: fair supervised polling for configured roles. Delivery can be placed in a second worker deployment when explicit isolation or scale justifies it.

The worker executable currently supports `ingestion`, `generation`, `delivery`, `retention`, `mailbox`, `reminder`, `alert`, `directory`, and `audit-anchor`. Azure enables provider-dependent roles only when the corresponding provider is configured. Preflight failure is fenced before readiness, each role closes owned database context, reminder transports are single-use and closed deterministically, and retention work is bounded/idempotent on a cadence bucket. Invalid delivery batch settings fail explicitly; stale supervisor/helper paths were removed. Local `scripts/supervisor.py` starts the original eight operational roles separately for development observability; references to “eight Azure workers” are historical.

The migration container job is not a continuously running deployable. It owns schema/role setup and is intentionally more privileged than runtime applications.

## Engineering and qualification topology

The Azure topology above is unchanged. Development/build/local-live
qualification uses a controller/worker split:

```text
controller workspace
  /Users/edierks/projects/codex-test/phishing-awareness-platform
            |
            | SSH; explicit socket/context only
            v
192.168.1.140 (native arm64)
  canonical source: /Users/edierks/Projects/kingphisher-phoenix
  target project Colima profile: kingphisher
  target source mount: read-only
  external state/socket root: /Volumes/DockerExternal/KingPhisher-Phoenix

192.168.1.140 Docker Desktop
  shared internal engine; unrelated workloads; not a project fallback
```

The current external engine's VM disks, cache, Docker client metadata, and socket
are all beneath the exact reviewed 1 TB external volume. Mount UUID, writability,
free space, unsymlinked path ancestry, native ARM64/VZ profile, disabled
Rosetta/binfmt/Kubernetes, read-only source mount, Keychain-backed Docker
credentials, and canonical `.git` source passed preflight. The global remote
context remains `desktop-linux`; the exact external socket is current, and the
final preflight reported approximately 744,006,440 KiB free. The
inactive `kp-external-mac` context is created and returns
`colima-kingphisher|aarch64|/var/lib/docker`; its exact endpoint is
`ssh://edierks@192.168.1.140/Volumes/DockerExternal/KingPhisher-Phoenix/colima/kingphisher/docker.sock`,
and the default remains `desktop-linux`.
Absence/drift blocks
instead of creating an internal default profile or using Docker Desktop.
The legacy Docker contexts named `DockerExternal` and `kp-remote-mac` omit the
reviewed socket path and can select shared Docker Desktop; never use them for
project work. The external volume named `DockerExternal` is the storage target,
not a Docker context.

The seven internal Docker Desktop project containers are stopped/preserved;
unrelated containers remain running. One legacy encrypted snapshot
is preserved, but the identity needed to decrypt it is absent; it is
unrecoverable and does not satisfy `EXT-002`. Both project stacks must never bind
the same host ports simultaneously. The external USB Journaled-HFS+ volume is unencrypted, has no
SMART telemetry, and physically reserves its Colima disks; it is engineering
capacity for synthetic or explicitly approved test data, not production
hosting. Azure storage/security/availability gates remain independent. Native
ARM64 evidence from `.140` is not native AMD64 release evidence.

Recovery identity authority remains in the controller Keychain at public
recipient `age1p9t25wm9uvcaafjv3hjmgsj092mgydrr9uzndjnmcq9psupfl94qm8h2w2`;
headless SSH cannot unlock the remote Keychain. `checkpoint-remote.sh` uses an
exact temporary identity transfer; controller `stage-remote.sh` makes a second
bounded transfer so `stage-checkpoint.sh` can validate one archive
and no-clobber publishes the reserved `migration-checkpoint/` payload, and only
then may external-engine-scoped `restore-state.sh` consume it. These paths have
produced snapshot `20260829T013332Z-tsX1WQ`, archive SHA-256
`e4fb16a735d0c9d3b6aa04381c4c9d7e24269006203c551f50abf671cc3637ff`,
which passed staging and external restore. External installation and
`verify_install.sh` passed. Final local hermetic now passes; external
PostgreSQL/Redis/E2E, image, browser, and cloud gates remain NO-GO.

## Implementation map

The application directories own HTTP/UI/process composition. Reusable policy and infrastructure behavior stays in packages:

| Component | Responsibility |
|---|---|
| `domain-models` | enums, request-independent state rules, RoE canonicalization |
| `database` | ORM, migrations, sessions, audience/training/program services, aggregate reporting, transactional outbox and audit facade |
| `contracts` | bounded generation/event contracts and Redis queue lifecycle |
| `auditing` | canonical records, hashes, and head-signature primitives |
| `authorization` | roles and capabilities |
| `domain-verification` | DNS proof and required-record policy |
| `sanitization` / `safety-validation` | egress/content normalization and deterministic lure gates |
| `templating` / `campaign-patterns` | sandboxed rendering and reusable lure definitions |
| `source-adapters` | bounded threat-source provider clients |
| `telemetry` | redaction, distributed rate limits, and the bounded worker metric primitive |
| `test-fixtures` | reusable test support only |

Applications should not import other applications. Split oversized feature modules inside their existing deployable; do not create another service merely to shorten a file.

Campaign publication uses one durable review and two explicit delivery phases.
The review hash binds the campaign configuration, signed RoE, frozen audience,
canonical template content, exact approved lesson, and locked server-designated
test accounts. Scheduling queues only that canary cohort. Full-audience
publication is a separate GUI action and is permitted only while server-derived
provider/config evidence remains current and the worker's pre-provider fence
still matches the review. ACS promotion requires authenticated delivered
receipts; SMTP-like development/provider paths prove acceptance only. A failed,
expired, missing, or drifting canary permanently blocks that review.

The content-library routes are the first bounded extraction from the oversized operator router. Four uncalled/unexported helpers were removed in Wave 13 (net 35 production lines), and Wave 21 removed the unused source-adapter clone implementation/exports (net 87 lines; 36 focused plus 5 downstream tests). These cleanups do not close the broader modularization debt in `routers.py`, `console.py`, `app.js`, and `jobs.py`.

The exact Alembic code head is `0032_source_explicit_curation`. Revision `0030` persists a safe default privacy notice while enforcing one current row; `0031` adds the confirmed-interaction/PII-free 1,826-day awareness ledger; and `0032` quarantines legacy automatically active source evidence for explicit operator review while adding migrated retention-policy bounds/default uniqueness. The latest complete external warning-strict, skip-rejecting PostgreSQL profile remains the historical 86-test result at exact head `0029`; no external `0032` qualification is claimed. ORM metadata still needs to mirror `0032`'s retention constraints before the paused checkpoint can be committed.

## Trust zones and authorities

| Zone | Inbound exposure | Identity / database authority | Sensitive material | Important restrictions |
|---|---|---|---|---|
| Operator | Authenticated HTTPS; administrator control plane | Entra user principal; `kp_operator` DB role | operator configuration, recipient PII access, policy keys by reference | exact issuer/audience/role checks; origin/CSRF controls; privileged operations fail on unhealthy audit; edge restriction remains a live gap |
| Tracking/training | Public HTTPS | no operator user identity; `kp_tracking` DB role | keyed token verifiers needed for event/training lookup | opaque bearer only; no operator/audit/recipient-decryption authority; distributed rate limits |
| Worker | No public ingress | worker deployment identity plus a DB role per enabled role | only role-required secrets and provider configuration | each supervised role uses its own DSN; delivery rechecks all policy gates |
| Provider identity | Outbound Graph only | separate directory or mailbox managed identity | Graph access token obtained at runtime | attached to the worker deployment but independently consented/scoped |
| ACS sender identity | Outbound ACS Email only | worker managed identity selected by explicit ACS client ID | ACS access token obtained at runtime | no implicit choice when multiple user-assigned identities exist; live send remains unqualified |
| Migration | One-shot control plane | migration managed identity and database migration role | schema/admin setup and audit root | never injected into runtime applications |
| PostgreSQL audit | Database internal | `audit_owner` is `NOLOGIN`; SECURITY DEFINER dispatcher | database-side audit root | runtime roles stage intent but cannot update/delete/truncate audit evidence |

Azure Key Vault access is assigned per identity and per secret. Runtime applications receive distinct least-privilege database URLs; they do not receive the PostgreSQL administrator DSN. The public tracking identity is specifically separated from recipient decryption and audit authority.

The console receives its allowlisted roles and capabilities from the authenticated server session. It rejects incomplete, unknown, or stale authority before exposing navigation or actions. An exact contract keeps the browser capability vocabulary aligned with the backend, and an explicit manifest reviews all 113 operator routes: 103 capability-protected and 10 dedicated/public. Non-Azure views avoid calls the principal cannot make; Help is available to aggregate-read roles, while template safe preview accepts either author or reviewer authority without allowing a reviewer to clone or an author to decide. This is a usability and defense-in-depth boundary only: every API mutation still enforces its capability independently, and no browser-live proof is claimed.

The console also discovers the authentication mode from the server before login. If discovery fails or returns an unknown mode, login fails closed; the browser never assumes the disposable development-password path.

Training-resource actions are finer-grained than view navigation. The API derives minimized `can_submit` and `can_review` booleans from role, creator identity, and resource state on every list, preview, and mutation response. The browser renders an action only when the corresponding flag is exactly `true` and the state permits that action; missing or malformed flags fail closed.

## Data flows

### Campaign and audience

An operator creates campaign content from an approved pattern/template and configures an audience using groups, departments/status filters, explicit inclusions/exclusions, and an optional deterministic sample. Preview records the proposed selection. Preparation freezes exact recipient rows plus configuration and manifest digests. Directory membership changes invalidate affected frozen manifests; they never silently expand a campaign. Legacy campaigns are marked as requiring configuration rather than defaulting to every active recipient. Recipient exclusions may be global or campaign-scoped, may expire, and are revoked by timestamping the retained audited record rather than deleting it; only active, unexpired, unrevoked exclusions affect preparation.

Scheduling and delivery independently enforce state, approvals, signed Rules of Engagement, verified/allowed target domains, the frozen manifest, current emergency-stop state, recipient cap, and deterministic rendered-content validation.

### Content generation

One strict generation contract crosses queue publication, worker assembly, AI provider I/O, template persistence/review, and delivery. Outbound context has bounded strings, lists, maps, and a 64 KiB aggregate serialized limit; the worker revalidates it before opening an HTTP stream. Provider JSON is streamed with duplicate/malformed declared-length rejection and cumulative decoded-byte limits before UTF-8/JSON/schema parsing. Unknown fields and generated subject/body values beyond database/preview limits fail with stable content-free errors.

The queued idempotency key is stored with the generated draft. A same-key retry returns the existing result; the worker rechecks after the pattern lock, and a unique-race loser rolls back its draft/audit effect and converges on the winner. This prevents a second provider call/draft during the tested retry and race paths; it is local contract evidence, not a claim about every external AI provider.

Managed configuration requires an approved non-local HTTPS gateway exposing both
`/propose` and `/setup-assist`. Pattern approval atomically records an approved
pattern and a durable generation request; the API reports that request boundary,
not asynchronous queue/provider completion. Live AI-provider execution remains
unqualified.

### Finite campaign programs

The Program Planner is a bounded materializer, not a cron service. From one reviewed, future scheduled campaign it atomically creates a fixed 2–12 occurrence timeline using one allowlisted elapsed-day cadence. The first occurrence is the existing source; every later occurrence is a separate draft with an unfrozen audience and without copied approvals, RoE binding, assignments, tracking/training tokens, or event evidence. Duplicate requests for the same reviewed source configuration return the existing program; source drift fails closed.

Pause/resume is versioned and audited. A shared database lock makes pause order safely against scheduling: a paused program blocks future schedule attempts, but does not recall or cancel work already scheduled or queued. Adaptive difficulty, new-hire/cohort enrollment, remedial rules, and an open-ended scheduler are not implemented.

### Delivery and provider results

The operator transaction stages an idempotent queue intent. The worker atomically claims each assignment with a durable attempt identifier before provider contact. SMTP assigns a deterministic message ID; ACS records the provider operation ID and selects its managed identity by explicit client ID. A crash after ambiguous provider contact becomes `INDETERMINATE` rather than an automatic blind resend.

Provider acceptance is not represented as final delivery. Terraform creates a system topic/subscription filtered to ACS email-delivery reports. The operator endpoint accepts a bounded batch only after Entra verifies the expected tenant, audience, Microsoft Event Grid caller, and dedicated application role; it rejects unexpected topic/subscription/schema values. Before enqueueing, it drops mailbox and free-form diagnostic fields, hashes bounded status detail, and HMAC-binds the minimized event. The delivery worker verifies that internal signature, deduplicates the external event, applies delivered/bounced/blocked-style outcomes, and updates suppression evidence. Here `DELIVERED` means that ACS reports handoff to the recipient mail system; it does not prove inbox placement, display, or reading. This pipeline is implemented locally but has not been proven against a live Event Grid subscription. Quota, ramp, sender, custom-domain, and fresh verification evidence are readiness gates for managed ACS delivery.

### Tracking and training

Each recipient URL contains a random opaque bearer. The database stores an HMAC verifier scoped to tracking or to a specific training purpose; possession of a database value is not sufficient to reconstruct the URL bearer. Opens/clicks are deduplicated at storage. The public API minimizes request metadata and does not log raw bearers.

Generated content receives only a required training placeholder, not the configured awareness destination. Recipient-specific delivery resolves that placeholder to the same opaque tracking-click URL used for event evidence. A valid click creates or reuses the exact training assignment and redirects to a separate assignment- and purpose-bound open bearer. The lesson form uses a distinct completion bearer; open cannot complete and completion cannot open. Reminders re-derive the assignment's open/completion verifiers and send only the open link when both match durable state. Approved legacy content containing the old static awareness URL fails delivery closed. Completion remains idempotent, assignment due time is one fixed 72-hour policy, and campaign reporting includes training states; the unused reminder-delay configuration was retired rather than pretending it was effective.

The training-resource library stores bounded plain text. A creator may submit only their own draft; a different reviewer may approve/reject a pending resource or supersede an approved resource under a row lock. Supersession prevents future selection without rewriting campaign assignments already bound to the prior version. Preview renders content as text only.

A loopback-only local canary used an explicit seeded `example.com` account and the real delivery/tracking/training route. A canonical approved template reached Mailpit once across duplicate processing, open/click events deduplicated, the assignment was reused, and separate purpose-bound lesson/completion bearers enforced an assessed knowledge-check failure/remediation/pass/replay lifecycle. The reporting funnel and audit correlation matched the single flow, followed by canary-only cleanup. This proves local orchestration, not DNS, external provider transport, inbox placement, human reading, or Microsoft 365 ingestion.

The public edge caps request targets and both declared and streamed bodies before route work, rejects duplicate/malformed content lengths, and trusts `X-Forwarded-For` only from an allowlisted direct peer. No-store, no-referrer, framing, content-type, robot, permissions, and HSTS policy is applied to normal responses, redirects, early limit failures, and translated errors. Known conflicts/not-found/database failures have fixed public responses; unexpected failures log only bounded exception type, method, and route template.

### Directory synchronization

The Microsoft Graph provider supports bounded paging, group selection, full/delta results, removal records, same-origin cursor validation, and bounded `429` retry. Directory changes first become a short-lived preview. An authorized operator applies or discards it in the GUI/API; incomplete or rejected snapshots cannot deactivate recipients. Stable tenant-keyed identifiers prevent group movement from creating a new recipient identity.

Preview fetches do not hold a database lock across Graph I/O. Instead, the worker commits a durable latest-request key and configuration fingerprint before the fetch, then locks/rechecks them before publishing success or error state. If a newer request or configuration has won, the older attempt returns `superseded`; its success cannot overwrite the newer payload and its failure cannot clear or retry over it.

### Threat-source lifecycle

An authorized operator can create one of the implemented source types and use audited GUI/API actions to acknowledge/inspect/revoke its current terms, enable it, disable it, or request ingestion. A complete current acknowledgement is required for enable and manual ingest. Revocation disables the source. Queue intent remains transactional and repeatable without treating an earlier request reference as a durable status object. Disable/revocation cannot abort provider I/O already executing. Before and after fetch, however, the worker verifies the exact source/terms version and re-reads it under `FOR UPDATE`; expiry, revocation, replacement, or disable records the stop and discards fetched material without source-item or pattern writes. Provider parsing/fetching retains bounded egress/content-safety controls, and no database lock is held across network I/O.

### Reported-phishing ingestion

The Microsoft 365 mailbox provider performs bounded delta polling under a leased, generation-checked cursor. Messages and receipts are deduplicated. MIME/original-message parsing treats message content and headers as untrusted evidence. The preferred correlation is an exact encrypted `rpt1` mapping created at delivery; ambiguous candidates are not promoted to confirmed campaign reports. The old Mailpit token-hash header is accepted only on the explicit local Mailpit path.

### Analytics and correction boundary

The reporting projection exposes PII-free single-campaign funnels and bounded longitudinal Executive Trends through JSON, formula-safe CSV, and the GUI. Every rate includes its numerator, denominator, denominator name, and nullable value. Aggregate reporting is available without named rows; named campaign outcomes require `view_named:results`, and bulk download requires `export_bulk:results`. Global recipient management and campaign named results use deterministic server-side pagination envelopes with a maximum of 500 rows, exact total/offset/limit, and truncation state. Other user-facing collections also apply deterministic database limit/offset bounds, and the browser follows pages only to its explicit collection ceiling. Scheduling reads at most 101 covering RoE candidates and fails closed when more than 100 match, before signature work. Trend windows select terminal campaigns by schedule start; they do not pretend to reconstruct historical transport states. Portfolio totals sum campaign-assignment exposures rather than averaging campaign percentages. Provider acceptance means handoff, ACS delivery means destination-MTA handoff rather than inbox placement/read, and training completion is not represented as causal efficacy.

### Provider control-plane responses

OIDC discovery, token, and JWKS documents; setup-assistant and generation responses; and GitHub workflow metadata/status/activity use small, purpose-specific limits. Each reader rejects duplicate or malformed `Content-Length`, pre-rejects declared oversize, caps cumulative decoded bytes when length is absent/compressed/chunked, and validates UTF-8, JSON, and schema before use. Stable errors omit provider bodies, tokens, and low-level exceptions. GitHub workflow dispatch is streamed/status-only so hostile success or error bodies are never eagerly buffered.

Application request validation follows the same minimization rule. Campaign/source/pattern/privacy/correction/approval/exclusion/rationale values and returned collections are normalized and bounded server-side. Campaign and pattern mutation/action flags are derived by the server; the browser must fail closed when they are absent or malformed. Operator and tracking validation responses expose only capped structural locations/counts and truncation state, never the rejected input value or unbounded validator context.

Privacy request and current-notice reads are independent browser operations. A
notice failure produces a bounded warning but does not make request listing or
mutation unavailable. The database default/current invariant is owned by
migration `0030`, not by UI fallback state.

The legacy public `/v1/corrections` endpoint is retired and always returns HTTP 410 without parsing or writing its body. The obsolete compatibility secret has been removed from runtime settings, local examples, and Terraform/Key Vault provisioning. Current reports preserve observed evidence and state explicitly that scanner/bot corrections are not subtracted. A normalized, separately proposed and approved correction workflow with observed/excluded/adjusted reporting is deferred.

### Audit and queue outbox

Business mutations stage audit and queue intent in the same PostgreSQL transaction. After commit, reconciliation dispatches queue work idempotently and invokes a database-owned function to serialize canonical audit events into the hash chain. Completion retains the native UUID database type. Final local acceptance exposed and fixed an audit-store owner-fallback revocation defect, reconciled 36 stranded idempotent queue intents, and left the audit chain green. Runtime roles cannot write audit rows directly or access the audit signing root.

If queue publication fails, the durable outbox row stores only the fixed `queue_dispatch_failed` code while retry counters/status progress normally. Bounded diagnostics may identify the outbox phase and SQLSTATE class plus a safe reference; statements, parameters, provider/driver exception text, and database detail are neither logged nor persisted.

Audit health includes chain verification and overdue/failed outbox intent. An unhealthy audit boundary removes readiness and blocks privileged API operations while leaving the minimum authentication/recovery/inspection surface available.

Periodic verification retains only an aggregate status and bounded problem count for readiness and inspection. Raw verification problems are not retained in scheduler state, returned by health endpoints, or written to logs.

Residual trust: the source audit chain head and signing root remain within the PostgreSQL administrative boundary. A create-only worker now verifies a stable head and publishes a minimal witness into a separate, versioned Azure Blob container with locked WORM retention. Its database role is column-scoped and cannot read the signing secret or outbox payload, mutate evidence, or invoke dispatch. This is locally permission-tested/static evidence only; production claims of independent immutability still require live Azure storage/RBAC evidence plus tested monitoring and recovery.

### Queue, retry, and dead letters

Redis keys for each topic share a cluster hash tag. Lua scripts atomically publish-once, promote delayed work, claim, reject, recover stale processing entries, and replay an explicitly selected dead-letter item. Consumers still require durable idempotency at the business/provider boundary; the queue alone cannot make an external mail send exactly once.

The console/API exposes bounded, authorized dead-letter inspection and replay. Logs contain job identifiers and failure categories, not job payloads containing recipient/provider data.

### Telemetry and health

Structured logging applies centralized redaction and size bounds. Local supervisor logs rotate/compress, and Azure has bounded logging infrastructure. The operator/tracking write-only metric registries were removed; those APIs retain dependency/security state through bounded health and logs. Workers emit bounded queue, role, job, and provider aggregates through structured snapshots. Neither API publishes a public `/metrics` endpoint, and their public OpenAPI, Swagger, and ReDoc routes are disabled. Unexpected production failures log bounded event/type metadata and safe operational references, never exception messages or tracebacks. Reviewed operator configuration/template/audience, authentication/RBAC, and analytics evidence-window/trend boundaries also convert failures to stable allowlisted public messages instead of reflecting arbitrary exception text. Worker jobs bind a safe correlation context, but end-to-end distributed tracing, authenticated metrics export, Azure collection/alerts, and live operational dashboards are not yet qualified. Logs and worker metric labels must not contain raw mailboxes, MIME bodies, correlation headers, token bearers, client IPs, credentials, provider cursor URLs, exception messages, or tracebacks.

`/livez` answers only whether the API process is alive. `/readyz` tests the dependencies and security state needed to receive traffic; database, Redis where required, or audit-integrity failures return an unhealthy result. The legacy `/healthz` compatibility response must not be used as the managed or local qualification readiness probe.

The test topology mirrors these boundaries. `make test` is hermetic. PostgreSQL, Redis, local E2E, and Azure-live profiles are explicit opt-ins and every profile rejects skips. PostgreSQL integration jobs use Redis DB14 and flush only DB14 before and after their profile; the Redis queue contract uses DB15; neither may touch application DB0. The historical pre-Wave-30 result was 1,994/87/2/8, the superseded intermediate external result was 2,230/86/2/8, and the now pre-remediation local/external snapshot was 2,329 hermetic/97 deselected, 86 PostgreSQL/2,340 deselected at head `0029` using DB14, 2 Redis/2,424 deselected using DB15, and 8 E2Es plus audit/install and clean 03Z logs. The pre-Wave-36 local hermetic `make test` passed 2,469 tests/97 deselected with 0 failures in 158.15 seconds. The final local Wave 36 hermetic suite at checked-in head `0030` passed 2,501 tests/97 deselected with 0 failures in 183.40 seconds. Ruff/format, mypy, and security results remain bounded to their separately recorded scopes. PostgreSQL, Redis, and E2E external reruns at `0030`, exact-final images, browser/WCAG, Azure/provider, recovery, and witness gates remain open.

The test environment uses the official Starlette `TestClient` through a test-only `httpx2` compatibility dependency; production HTTP clients continue to use the normal runtime `httpx` dependency. Owned API/tracking pools and SQLite test engines close deterministically, outbox timestamps use explicit SQLAlchemy datetime typing, and PostgreSQL fixture cleanup covers schemas, tables, roles, and engines. The canonical plan records exact hermetic/PostgreSQL/Redis/E2E counts and the targeted local bootstrap/audit repairs. A backup snapshot alone is not full restore evidence.

## Configuration and deployment

The reviewed deployment repository is `ELDSRQ/kingphisher-phoenix`.

The integration boundary is provider-aware: the GUI exposes explicit SMTP/ACS
and Mailpit/Microsoft 365 choices; active fields alone are required, tested,
saved, or supplied to setup assistance, while inactive saved values are
preserved. ACS uses an exact HTTPS Azure Communication Services origin and is
non-sending reachability-only; Microsoft 365 uses one quoted/bounded Graph delta
probe. Provider/destination changes validate before atomic credential rebinding.
Privacy export is POST-only, privacy list/export data is no-store, and cookie
mutations require same-origin CSRF metadata. OIDC endpoints are issuer-origin
bound and reached through single-resolution IP-pinned TLS without redirects,
environment proxies, or HTTP/2, preventing cross-origin navigation or secret
transmission.

Local mode reads generated secrets and connector settings from `.env` and may use the local console credential, mock providers, Mailpit, and memory-backed limits. That mode is disposable and loopback-bound.

The one-click local deployment is a fail-closed control sequence. Except for the already-running PID fast path, it requires 8 GiB of available disk by default before dependency synchronization, bootstraps the preserved environment, proves Docker access, and runs a read-only `prestart` inventory before Compose can create anything. A clean host may have no project volumes; an existing host must have the complete expected named-volume identity. Partial or mismatched state blocks. Before `uv sync` or any `.env` write, existing recovery keys, mirrored service keys, and preserved credentials must be complete and internally consistent; uninspectable state is treated as preserved state. Stateful base images are then required to be digest-pinned, to contain exactly one manifest for the selected platform, and to pass hardened ephemeral account-file, entrypoint, binary, and version probes without project-volume attachment. Only after those controls pass may Compose start missing services with `--no-recreate`. Migration, audit bootstrap, and seed run from the frozen environment and precede the read-only `ready` phase, which requires healthy PostgreSQL/Redis and the current migration head before application processes start. The already-running fast path also requires `/readyz`, so a stale or unrelated PID cannot suppress recovery. Both reports state that no mutation or automatic cleanup was authorized. Earlier controller observations at about 5.9 and 5.6 GiB remain dated proof that the normal capacity gates blocked; the external Colima execution capacity and preservation-first cutover/restore are now proven.

Local Compose services and the mock Python base use immutable manifest digests. The mock runtime's full 17-package dependency closure is pinned and hash-verified. Normal bootstrap, development, and console launch consume the frozen workspace lock. Dependency audit fails closed on export/audit failure and covers 58 external production packages; native CycloneDX 1.5 SBOM export contains 59 total components/58 external PURLs. The latest completed all-five native ARM64 snapshot passed hardening and 0 HIGH / 0 CRITICAL / 0 secret scans, but Wave 29/30 source edits make those interim images stale. The preservation-first external-worker cutover, restore, installation, and installation verification passed; exact-final rebuild/rescan, native AMD64, and registry evidence remain open until executed.

Release verification uses a dedicated, validated verification-image namespace,
refuses every pre-existing target tag instead of moving an earlier evidence
reference, validates all timeout controls before creating a build context, and
removes only uniquely named containers or networks whose creation it recorded.
Exact-final ARM64 status is evidence-conditional: retained no-clobber
`qualification.json` plus scan evidence must prove the exact non-emulated
Docker server platform, explicit `--platform`, all-five
OS/architecture/image-ID metadata, unchanged source/context manifests, the
expected source-manifest digest, exact Trivy executable/hash/cache, retained empty config/ignore/secret policy files,
ambient-`TRIVY_*` rejection, fresh database/check-bundle metadata, an immutable
verified cache, and verified labeled-disposable cleanup. The Azure workloads stage
scans exact immutable ACR `repository@sha256` images with pinned Trivy before
SBOM/attestation/deploy and retains scan JSON/checksums. These controls do not
by themselves establish a pass.
Supervisor PID publication is atomic, partial child generations are stopped,
and restart fails closed while retaining PID evidence if any prior child exit
cannot be confirmed. Launcher publication is staged, byte-identical reruns do
not accumulate backups, and a failed publication restores the prior bundle.

Managed mode receives non-secret settings as Container Apps environment values and secrets through Key Vault references. It refuses console attempts to edit an ephemeral `.env`, restart local processes, use loopback providers, use development authentication, or start with omitted mandatory policy/provider configuration. Operator, tracking, and worker settings hide input values and suppress nested parser/provider exception chains. Each worker role validates only its own dependencies; managed roles reject local, credential-bearing, query-bearing, or fragment-bearing provider URLs and legacy pasted provider credentials, while development keeps explicit local mock defaults. Tracking receives exact `TRACKING_API_TRUSTED_PROXIES` CIDRs derived from the Container Apps infrastructure subnet plus loopback. It accepts forwarding only from a trusted direct peer, resolves a bounded canonical `X-Forwarded-For` chain right-to-left, and runs with Uvicorn proxy rewriting disabled so client-IP rate limiting does not collapse to the ingress peer.

The Azure workflow, Terraform, API, and GUI use three exact stages. `foundation_bootstrap` plans and applies the complete `deploy_workloads=false` foundation—including ACR, private-network, data, ACS/email/domain, and DNS resources—without Terraform targets. It initiates exactly four verification types while explicitly forbidding association/sender changes. `foundation_finalize` requires fresh authenticated Domain/SPF/DKIM/DKIM2 Verified state, allows only the association/sender changes, and proves those exact resources after apply. `workloads` repeats the exact live checks before immutable runtime/provider wiring, then requires exactly one active Healthy/Provisioned worker revision, two consecutive simultaneous ready observations for every enabled role in that revision, and a final same-revision health recheck. The API rejects operator-entered readiness assertions; the GUI resumes the owner/environment plan, advances only through a new predecessor/evidence-bound review, displays the validated bounded stage artifact, and exports the same exact one-label HTTPS `*.communication.azure.com:443` shape enforced by API/Terraform/preflight. Every plan rejects deletion/replacement, and missing or mismatched evidence cannot advance. The connector/workflow binding is SHA-256 `6868067ef5d58c799bc4a07dd832d4852d38dee73e6ff1af9a58c701ce85a4d3`.

Azure `private` mode also has a topology prerequisite: its Terraform runner must already have routed VNet access. The same hosted job cannot create the VNet and then become private to it. A separately provisioned private runner is the preferred first-deployment path. `starter` is only a bounded empty non-production foundation option; it exposes the data planes, is refused for production, and must be replaced by `private` before recipient data or campaign workloads are introduced.

The workflow/ref/environment content is digest-bound and rechecked before dispatch. The exact connector digest is refreshed only after a workflow/security review closes; a mismatch fails closed. The workflow explicitly targets `linux/amd64`, captures/re-resolves immutable ACR digests, binds SBOM/provenance subjects, rejects credentials/tokens in reviewed configuration, disables persisted checkout credentials, and removes ephemeral registry credentials. Connector validation covers protected-environment metadata/reviewers, exact workflow/ref/content, new run identity/status, and owner-bound Redis environment/operation leases. Each reviewed operation retains bounded append-only hash-chained checkpoints and a recovery contract requiring evidence and in-place reconciliation. An interrupted or indeterminate dispatch is refreshed against its opaque request, reviewed revision, correlation ID, and linked GitHub run; it is never blindly reissued or treated as cleanup authorization. Provider-backed local validation passes. The 2026-08-29 live GitHub re-audit proves valid `ELDSRQ` authentication with `repo`/`workflow` scopes; a public, enabled repository with default `main`; Actions enabled; the Azure workflow active; and no billing-disabled run signal. It also proves zero environments, variables, secrets, rulesets, and workflow runs, unprotected `main`, disabled secret scanning and push protection, and remote `main` still at old-tree SHA `1403d944a40214714b6cbfcf5cbabc4fa7225eb9`. The sandbox could not resolve `management.azure.com`, so current Azure management-plane state remains unverified. No workflow dispatch/run, remote-backend, or Azure operation occurred.

The operator application emits an HSTS header and exposes fail-closed readiness contracts locally. That is not evidence of what a browser receives through an Azure custom host or edge. WAF/edge policy, custom-domain and certificate completion, live HSTS observation, rollback, and restore remain unqualified.

## Security invariants and known residuals

- OIDC uses discovery metadata, exact issuer and audience checks, HTTPS outside loopback, Entra stable `oid`, top-level app roles, state/nonce, and PKCE. Unknown roles fail closed.
- Real OIDC requires separated security/privacy approvals by different principals; relaxed single-admin behavior is confined to disposable development auth.
- Signed RoE v2 binds the normalized authorization including domains, window, party, signer, and terms. Legacy authorization cannot be silently reused.
- Roles are immutable typed snapshots. Wildcard/malformed capabilities and unknown roles cannot escalate; UUID self-approval checks and non-identifying denials fail closed. RoE domains are strict canonical ASCII/A-label values with unambiguous suffix checks; Unicode/IP/single-label ambiguity is rejected. RoE v2 permits at most 100 domains, requires a key of at least 256 bits, signs bounded canonical fields, and requires aware ordered UTC windows. Shared campaign size and campaign/program/training temporal invariants apply across API and worker consumers.
- The emergency stop is a persistent singleton database policy. Global and campaign-scoped stop transitions order against delivery using shared/exclusive database locks and block future scheduling/delivery across restarts until an authorized, reasoned release. Wave 24 point-in-time evidence passed 52 focused worker lifecycle/security tests in 1.30 seconds and 15 isolated PostgreSQL tests in 3.07 seconds, including a 250 ms shared-versus-exclusive lock-contention proof. A separate isolated migrated-PostgreSQL scoped-stop persistence test passed 1 in 2.88 seconds at `0027` and dropped its disposable database. Application and worker runtime safety checks use explicit exceptions rather than optimization-removable `assert` guards.
- Sensitive database fields use application-layer AES-256-GCM and recipient lookup uses a separate keyed mailbox digest. New ciphertext carries an authenticated format version and non-secret key identifier; each process writes only with its active key and can read with at most four configured prior decrypt-only keys, including the legacy unversioned format. This is direct secret-store-supplied encryption, not envelope encryption. Managed prior-key input is metadata-bound legacy/recovery support only: the first foundation fixes the active ID, later dispatches cannot change it, and active rotation is blocked. The Terraform-generated active KEK remains in protected state/history; `prevent_destroy` prevents replacement and makes teardown an explicit reviewed exception. Pre-stage/prove/promote across revisions, a database decrypt canary, bulk re-encryption, safe prior-key retirement, row/column-specific AAD, and a true envelope-key hierarchy remain design debt.
- Fetching and rendered HTML controls prevent external/IP/protocol-relative/CSS/form exfiltration paths before mail leaves the system.
- Direct Azure edge/WAF/custom-domain controls and live attack evidence remain incomplete.
- Exact-final-tree ARM64, AMD64, registry publication/attestation and rollback qualification; protected GitHub environment/configuration, branch protection and final-source sync; remote Terraform backend and disposable-Azure stage execution; live external-audit-witness proof; browser/WCAG qualification; backup/restore/recovery and encryption-rotation canaries; live Entra/Graph/ACS/Event Grid/Outlook/DNS/inbox evidence; end-to-end trace/metric collection; and alert proof remain production and RSA Conference blockers. No KnowBe4 parity or production readiness is claimed.

## Evidence levels

Every architecture assertion should be qualified as one of:

- **Implemented/static** — present in code, migrations, Terraform, or tests.
- **Local live** — exercised against disposable local PostgreSQL/Redis/APIs/providers.
- **Cloud/provider live** — exercised in the intended Azure/Entra/Graph/ACS/Outlook environment.

Static validation is not cloud evidence. The current product has substantial implemented/static and local-live evidence, but insufficient cloud/provider-live evidence. Production and RSA Conference use therefore remain **NO-GO**.
