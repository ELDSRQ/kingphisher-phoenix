# Engineering handoff

This is a navigation and invariants document, not a second status tracker. Read [the integrated build plan](WAVE-BUILD-PLAN.md) for the current decision, exact gate evidence, findings, and backlog. Read [the architecture description](architecture/README.md) before changing a trust boundary. Azure operating steps remain in [Azure deployment](AZURE_DEPLOYMENT.md).

## Product contract

Kingphisher-Phoenix is intended to be a simple, single-tenant phishing-simulation
and awareness platform for one 125-person organization operated by two IT
staff. Routine deployment, connector setup, campaign operation, recovery, and
reporting should be GUI-driven. A bounded one-time bootstrap may remain
external, but scripts and Terraform are not substitutes for a finished operator
workflow.

AI may explain settings, produce a reviewed deployment plan, map integration inputs, or draft campaign content. AI must never save secrets, apply infrastructure, grant consent, approve a campaign, choose an audience, bypass policy, or send mail. Deterministic code is the authority.

The supported AI architecture is internal-model-first. Benchmark two or three
small permissively licensed instruction models against a fixed sanitized set,
prioritizing schema validity, evidence fidelity, safe refusal/content checks,
and prompt-injection resistance before latency, memory, and cost. Digest-pin
weights, runtime, license, prompt, and evaluation. The first deployment target
is a pinned `llama.cpp` role/job in the existing worker image on CPU; use
scale-to-zero serverless GPU only when measurement requires it. Foundry
serverless/token inference remains an optional measured fallback. Foundry
managed compute and always-on GPUs are out of scope. The model has no tools or
network, cannot approve or launch, and deterministic fallback must remain.

Deferred functionality is retained and supported but not expanded. Do not
delete potentially valuable features because they are outside the current
priority sequence; retiring functionality or data requires a separate reviewed
decision.

The release decision is **NO-GO for production and RSA Conference use** until the build plan’s cloud/provider-live gates pass. Never turn local/static evidence into a production claim.

### Wave 38 paused implementation boundary

- `ORG-001` is complete locally with creator plus one independent
  dual-capability approver. Security and privacy remain separately recorded
  facets, and every RoE/audience/canary/provider/stop/review gate remains.
- `THR-001A` and `DOCSIM-001` are complete locally with evidence-fidelity and
  recipient-bound ICS behavior; their focused closure passed 150 tests.
- `IMP-001` and `THR-001B` are complete locally. Guided CSV preview/apply is
  digest-bound and serialized; daily ingestion quarantines by default; the
  bounded Threat Campaigns workbench requires explicit audited activation to
  create/retain one draft pattern basis; source governance and provenance are
  rechecked through approval and generation.
- `OUT-001`/`RET-005`/`INT-001` retention integration is complete locally at
  Alembic head `0032_source_explicit_curation`: confirmed interaction,
  current writer locking, terminal-only project-before-purge, a PII-free
  1,826-day ledger, stable pseudonym configuration, grants, and a 365-day raw
  maximum are wired. Privacy/RBAC, named-history API, reporting/graph, and export
  consumers remain open.
- The retained P1 is closed: `RetentionPolicy.__table_args__` mirrors migration
  `0032`'s retention constraints with metadata/direct-database tests. The
  current-head gate also fixed the migration revision-id overflow
  (`0032_source_item_explicit_curation` → `0032_source_explicit_curation`) so
  fresh databases can reach head.
- The checkpoint is committed (`d25313d`) and pushed; `origin/main` is `c9ea716`
  (plus ANA-010 increments `aa67c17` and `c9ea716`). Current-head hermetic
  2,620/103, external PostgreSQL 92, and external Redis 2 pass; E2E, image,
  browser, and cloud gates remain open.
- Privacy/RBAC, named-history API, and remaining ANA-010 consumers (basic
  repeat history) are the next build work; use the copy-ready prompt in
  `RESUME-HERE.md`.

## Architecture at a glance

The managed default is three deployables: operator API/console, public tracking/training API, and one supervised multi-role worker. Delivery may be isolated only when scale or security justifies a second worker deployment. The migration job is one-shot and privileged; it is not a fourth continuously running product service.

The worker supports nine roles inside one executable: ingestion, generation, delivery, retention, mailbox, reminder, alert, directory, and audit-anchor. Local development starts the original eight operational roles separately; managed deployment supervises the configured set in one worker. Do not describe the local process layout as separate Azure workers.

Engineering qualification is split across two hosts. The controller owns the
workspace at `/Users/edierks/projects/codex-test/phishing-awareness-platform`.
The target native ARM64 worker is `edierks@192.168.1.140`, with canonical source
`/Users/edierks/Projects/kingphisher-phoenix` mounted read-only in the
project-only `kingphisher` Colima VM. Its VM, cache, client metadata, and
socket is fixed under `/Volumes/DockerExternal/KingPhisher-Phoenix`.
External preflight/restore passed; the final exact preflight reported
approximately 744,006,440 KiB free. The inactive `kp-external-mac` context is
created with endpoint
`ssh://edierks@192.168.1.140/Volumes/DockerExternal/KingPhisher-Phoenix/colima/kingphisher/docker.sock`
and reports `colima-kingphisher|aarch64|/var/lib/docker`, while the
default remains `desktop-linux`; the seven internal Docker Desktop project
containers are stopped/preserved and unrelated containers remain running. The
remote global context must remain `desktop-linux`; unrelated Docker Desktop
workloads are never fallback or cleanup targets. The external volume UUID,
writable host mount, capacity, unsymlinked roots, reviewed profile, read-only VM
source mount, Keychain-backed credential policy, and canonical source must pass
before every external project Docker operation. Loopback application URLs are
loopback on `.140`.
The legacy Docker contexts named `DockerExternal` and `kp-remote-mac` omit the
reviewed socket path and can select shared Docker Desktop; never use them for
project operations. The external volume named `DockerExternal` is storage, not
a Docker context.

The external USB/HFS+ worker is development and qualification infrastructure,
not Azure production. It is unencrypted and has no SMART telemetry; use only
synthetic or explicitly approved test data and retain encrypted recovery
copies. Rosetta/binfmt are disabled. Native AMD64 remains independently gated.

Recovery identity authority stays in the controller Keychain at public
recipient `age1p9t25wm9uvcaafjv3hjmgsj092mgydrr9uzndjnmcq9psupfl94qm8h2w2`.
Headless SSH cannot unlock the remote Keychain. `checkpoint-remote.sh` therefore
transfers only a temporary mode-0600 identity and cleans it up;
Controller `stage-remote.sh` then makes a second bounded transfer so remote
`stage-checkpoint.sh` can validate one exact archive and no-clobber publish
its reserved `migration-checkpoint/` payload before `restore-state.sh`. These
paths produced validated/staged snapshot `20260829T013332Z-tsX1WQ`, archive
SHA-256
`e4fb16a735d0c9d3b6aa04381c4c9d7e24269006203c551f50abf671cc3637ff`,
and a proven external restore. External installation and `verify_install.sh`
passed. Final local hermetic now passes separately; this restore/install result
is not external PostgreSQL/Redis/E2E, image, browser, or cloud evidence.

Repository boundaries:

```text
apps/operator-api/     private control plane and SPA host
apps/operator-ui/      browser console
apps/tracking-api/     public tracking/training boundary
apps/workers/          supervised roles and provider adapters
packages/              domain, storage, queue, policy, security, and telemetry
infrastructure/        containers and Azure Terraform
scripts/               development/release/qualification tools
```

Applications depend on packages and should not import other applications. Favor feature modules within the three deployables over new services.

## Non-negotiable invariants

### Identity and authority

- Managed mode uses Entra OIDC discovery, code + PKCE, exact issuer/audience, stable `oid`, and top-level app roles. The local shared credential/JWT path is disposable development compatibility only.
- Single-tenant mode is explicit. Do not add a tenant ID column and call the product multi-tenant; isolation would have to cover auth, all data, queues, keys, providers, cache keys, logs, and tests.
- Operator, tracking, worker, migration, directory-provider, and mailbox-provider identities are separated in Azure. Runtime applications must not receive the administrator database URL.
- Each supervised worker role uses its role-specific database URL. Key Vault access remains per identity and per secret.
- External-worker mount or identity drift must fail closed without internal
  Colima/Docker Desktop fallback. Preserve the stopped internal project
  rollback stack, external profile, encrypted snapshots, and all named
  volumes. The legacy encrypted snapshot is
  unrecoverable because its identity is absent and cannot satisfy `EXT-002`.
  Never change
  the global context or mutate unrelated `.140` Docker resources.
- The browser trusts only server-derived, allowlisted roles and capabilities. Invalid, missing, unknown, or stale session authority must clear the session and fail closed; navigation visibility is not API authorization.
- Per-resource training authority is also server-derived. The GUI may use capabilities to expose the library/create view, but submit/review/supersede controls require strict `can_submit`/`can_review` booleans returned for that principal, resource, and state. Missing or malformed flags remove actions.

### Campaign safety

- A campaign must use a configured, previewed, frozen audience. Never restore “all active recipients” as a fallback.
- Directory membership changes may invalidate a manifest but must never expand it silently.
- Scheduling and delivery both recheck approvals, signed RoE v2, verified/allowed domains, frozen manifest, persistent emergency stop, recipient cap, and rendered-content safety.
- Provider acceptance is not final delivery. Ambiguous post-provider crashes become `INDETERMINATE`; do not blindly resend them.
- Generated content must carry the training placeholder until recipient-specific delivery. Delivery resolves it to the recipient's tracking-click bearer; the click issues the assignment's distinct open bearer, and completion uses a separate purpose. Reject static awareness URLs and cross-purpose reuse.
- Generation request and response models are the canonical queue/provider/storage boundary. Preserve field/list/aggregate input limits, streamed declared/decoded provider limits, subject/body storage limits, unknown-field rejection, and the durable queue idempotency key. Retries and same-key races must converge without a second provider call, draft, or audit effect.
- Source enable, manual ingest, and worker writes require the source's current complete terms acknowledgement. Preserve both pre-fetch and post-fetch terms/version fences; revocation disables the source but does not pretend to cancel network I/O already in progress.
- Outside loopback development auth, security/privacy approvals remain separate
  facets. One independent operator holding both capabilities may complete both;
  the campaign creator may complete neither. Do not restore self-approval or
  weaken any downstream safety recheck.
- Roles must be immutable typed snapshots. Reject wildcard/malformed capabilities and unknown roles without escalation. Self-approval compares canonical UUID principals; denial messages must not identify a principal. RoE v2 accepts at most 100 strict canonical ASCII/A-label domains, rejects Unicode/IP/single-label ambiguity, requires at least a 256-bit signing key, signs all bounded canonical fields, and requires aware ordered UTC windows with fail-closed comparisons. Preserve shared `Campaign` size 1–10,000 and campaign/program/training temporal invariants at every API/worker consumer.

### Bearers, privacy, and content

- Tracking and training URLs carry random opaque bearers. Store only purpose-scoped keyed verifiers. A stored “token hash” must never itself be a bearer.
- Do not log raw URLs/bearers, mailboxes, MIME bodies, report correlation headers, provider cursors, client IPs, secrets, connection strings, exception messages, or tracebacks. Production unexpected failures use bounded event/type metadata and safe non-secret references only; do not reintroduce `logger.exception`, `.exception`, or `exc_info=True` in applications, packages, or scripts.
- Recipient PII remains authenticated-encrypted; mailbox matching remains salted/digested. New ciphertext uses the authenticated `kpct.1.<key-id>.<payload>` format. Each process writes with one active key and can read with at most four prior decrypt-only keys plus bounded legacy-unversioned values. This is direct AES-GCM, not envelope encryption. In managed Azure, prior keys are metadata-bound legacy/recovery inputs only. The first foundation fixes the active key ID, later dispatches cannot change it, active rotation is deliberately blocked, and `prevent_destroy` protects the Terraform-generated active key while complicating teardown. The active KEK remains in protected Terraform state/history. Safe pre-stage/prove/promote, a decrypt canary, bulk re-encryption, and proven prior-key retirement remain debt.
- All recipient-specific rendered HTML passes deterministic validation. Outbound content/provider fetching stays globally routable, HTTPS-allowlisted, DNS-revalidated, streamed, and bounded.
- The public tracking edge rejects ambiguous/oversized bodies and request targets before route work, trusts forwarding only when the direct peer belongs to a validated `TRACKING_API_TRUSTED_PROXIES` CIDR, walks the bounded canonical `X-Forwarded-For` chain right-to-left, stamps privacy/security headers on every response, and never reflects internal exception detail. Managed Azure derives the exact proxy set from the Container Apps infrastructure subnet plus loopback, and Uvicorn proxy rewriting stays disabled.
- API validation is authoritative. Campaign/source/privacy/correction/approval/exclusion/mailbox/domain/timezone/rationale fields remain normalized and bounded server-side, while operator/tracking validation output exposes only capped structural locations/counts and stable messages—not rejected values.
- OIDC discovery/token/JWKS, setup assistance, AI generation, and GitHub metadata/status/activity readers must stream and cap decoded bytes before UTF-8/JSON/schema handling. Reject duplicate/malformed lengths and never include provider bodies, tokens, or low-level errors in logs or responses. GitHub dispatch must classify status without reading its body.
- Pydantic settings must hide input values and secret parsers must suppress low-level exception chains. Managed worker roles validate only their role dependencies and reject local, credential-bearing, query-bearing, or fragment-bearing provider URLs; disposable local defaults belong only to development mode.

### Audit, queue, and health

- Business mutation, audit intent, and queue intent share a database transaction. Runtime roles stage intent; only the database-owned dispatcher writes audit evidence. Outbox completion preserves native UUID binding, and reconciliation emits bounded phase/SQLSTATE-class metadata without statement, parameter, or driver detail.
- Runtime roles must not update/delete/truncate audit evidence or receive the audit root.
- Preserve the explicit residual: PostgreSQL administration still owns the source audit root/head. A create-only worker and locked Azure Blob witness are implemented and locally permission-tested, but independent immutability remains unqualified until the separate Azure boundary and monitoring/recovery behavior are proven live.
- Redis transitions remain atomic and cluster-slot compatible. Queue retry is at-least-once; business/provider idempotency is still required.
- Queue-dispatch failure state stores only the fixed code `queue_dispatch_failed`; never persist raw exception text in the outbox or another durable retry record.
- Dead-letter inspection/replay is bounded, authorized, audited, and payload-minimizing.
- `/livez` is process liveness. `/readyz` is dependency/security readiness. Managed probes and local installation verification must not use the legacy always-readable health endpoint. Keep the local readiness preflight ahead of expensive gates: free disk, bounded Docker/Compose response, required service health, then tests with live-E2E skip rejection.
- Periodic audit verification may retain only aggregate status and a bounded problem count. Never retain raw verification problems in scheduler state or expose them through logs/health responses.
- Operator and tracking must not publish public `/metrics`, OpenAPI, Swagger, or ReDoc routes, and their former write-only metric registries must not be restored. Preserve dependency/security health and bounded structured logs. Worker snapshots may retain bounded metric labels for queue, job, and provider aggregates; never turn recipient, mailbox, bearer, cursor, MIME, URL, or provider-correlation data into a label.

### Recovery-safe local deployment

- The local Compose identity is immutable recovery state: project
  `phishing-awareness-platform`, PostgreSQL volume
  `phishing-awareness-platform_postgres_data`, and Redis volume
  `phishing-awareness-platform_redis_data`. A different project name or volume
  name is drift, not a clean deployment opportunity.
- Before generating any critical local credential, bootstrap inspects preserved
  PostgreSQL/Redis volume labels. If `.env` is missing/incomplete and preserved
  state exists—or Docker inventory cannot be proven—fail closed and restore the
  matching values from protected recovery material. Never generate replacement
  keys/passwords over state whose identity or decrypt/audit credentials are
  unknown.
- Except for the already-running PID fast path, one-click startup requires the
  positive whole-GiB headroom setting (8 GiB by default), then read-only
  `prestart`, base-image qualification, Compose start, migrations/audit
  bootstrap/seed, and read-only `ready`. `prestart` allows a genuinely clean
  host or the complete fixed volume set; partial state blocks before Compose can
  create a missing volume. `ready` adds service health and exact migration-head
  evidence.
- Preflight reads dotenv as data, not shell, and minimizes each subprocess
  environment: Docker/volume inspection gets no dotenv secrets, Compose gets
  only `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `AUDIT_WRITER_PASSWORD`, and
  `MAILPIT_API_PASSWORD`, and migration inspection gets only `DATABASE_URL`.
  Loader/path injection variables and `DOCKER_*`/`LD_*`/`DYLD_*` dotenv values
  are never forwarded.
- Base-image qualification accepts an offline cached image only when its local
  platform and repository digest exactly match the reviewed index, then probes
  it with `--pull=never`. Otherwise it resolves the reviewed remote index and
  exact platform manifest. Hardened probes attach no project volume and require
  non-empty account/entrypoint files and working service binaries; Redis must
  run as `999:999` and write a disposable `/data` tmpfs.
- Preflight evidence explicitly records no mutation and forbids automatic
  cleanup. Preserve caches, images, containers, volumes, databases, `.env`, and
  recovery evidence. An uncertain local or Azure operation is checkpointed and
  reconciled against the same identity/request; never prune, reset, recreate,
  rename, or blindly redispatch it.

## Implemented integration state

Microsoft Graph directory support includes selected groups, bounded full/delta reads, removals, retry, stable recipient identities, and a durable preview/apply/discard flow. A rejected or incomplete preview cannot deactivate recipients.

Directory preview is latest-request-wins around provider I/O. Each request durably claims the integration row before the network fetch, then rechecks its request key and configuration afterward. An older success or failure returns `superseded` and must not overwrite, clear, audit as current, or trigger retry over a newer preview.

Threat-source management supports audited, authorized, repeatable terms acknowledgement/inspection/revocation plus enable, disable, and manual-ingest requests through the API and GUI for the implemented adapters. Enable/ingest fails without current complete terms. Disable or terms revocation cannot abort provider I/O already in progress, but the worker must re-read and lock both source and terms after fetch; if either changed, it records that outcome and discards fetched material without source-item or pattern writes. An ingestion `job_id` is only a request reference; do not present it as a status resource.

Microsoft 365 reported-message support includes bounded delta polling, a leased generation-checked cursor, replay/dedup protection, MIME parsing, and exact encrypted delivery correlation. Treat parsed content as untrusted evidence. Mailpit’s legacy token header is local-only.

ACS Email support includes a custom-domain path, optional Azure DNS records or exact manual records, sender/domain readiness evidence, quotas/ramp inputs, provider operation IDs, an explicit managed-identity client ID, and an Entra-authenticated Event Grid receipt pipeline. The public endpoint minimizes and HMAC-binds accepted events before Redis; the worker verifies, deduplicates, updates transport state, and maintains suppressions. Terraform and Entra bootstrap wire the topic, subscription, dedicated app role, and narrowly shared receipt key. The flow is not live-qualified. Generic SMTP and Mailpit remain supported paths.

Training includes an approved lesson renderer, separate open/completion bearers, assessed knowledge-check remediation/pass behavior, idempotent completion, due/reminder state, reporting, and the governed text-resource library from migration `0026`. Migration `0028` binds every campaign to one exact approved lesson, and tracking revalidates that immutable binding. Authors submit their own drafts; a different reviewer may approve/reject pending lessons or supersede approved ones under row locking. List, preview, and mutation responses recompute minimized `can_submit`/`can_review` flags without exposing creator/reviewer identity. Migration `0029` adds one durable launch review over configuration, RoE, frozen audience, template, lesson, and server-designated test accounts; scheduling queues only that canary, while full publication requires current provider-derived evidence. Migration `0030_default_privacy_notice` persists a safe default and enforces one current notice; `0031_awareness_ledger` adds the confirmed-interaction/PII-free 1,826-day ledger foundation; current head `0032_source_explicit_curation` requires explicit re-review of legacy automatically active threat evidence and adds migrated retention-policy invariants. Privacy/RBAC, named-history API, reporting, graph, and export consumers remain open. The current loopback `example.com` Mailpit durable-gate lifecycle passed within the latest external 8-test E2E profile at exact head `0029`; that historical result does not qualify current head `0032`. No local test proves inbox/provider behavior. Browser/mobile/WCAG live qualification is still pending.

Campaign Programs are deliberately finite rather than scheduler-heavy. An authorized operator can use the GUI to create 2–12 independently reviewed occurrences on an allowlisted elapsed-day cadence, inspect exact UTC times, and pause or resume future scheduling. Creation is duplicate-safe and never copies approvals, RoE binding, frozen manifests, assignments, tokens, or evidence. Pause does not recall work that is already scheduled or queued. Adaptive difficulty, new-hire/cohort enrollment, and remedial automation remain backlog.

Analytics include a denominator-explicit single-campaign funnel and bounded longitudinal Executive Trends JSON/CSV/GUI. Trend selection uses terminal campaigns' schedule-start timestamps; portfolios sum assignment exposures rather than averaging campaign rates. Provider acceptance and MTA handoff are not inbox/read evidence, and training completion is not a causal efficacy claim. Cohorts, repeated-risk analysis, efficacy evaluation, scheduled reports, and normalized scanner/bot corrections remain backlog.

Global recipient management and campaign named outcomes return explicit server-side pagination envelopes (maximum 500); the browser validates them and never fetches an unbounded recipient list. Named outcomes still require `view_named:results`, while aggregate reporting never receives named rows and CSV export requires `export_bulk:results`. Migration `0027` adds durable global/campaign recipient exclusions with expiry and explicit append-only revocation history. Alert subscriptions are owner-listed/disabled; external HTTPS destinations require the configured hostname allowlist.

The legacy tracking `/v1/corrections` endpoint is intentionally retired as HTTP 410/no-write, and its obsolete shared secret is absent from runtime settings and Terraform/Key Vault. Do not restore either the credential or its append behavior. A future correction feature must normalize immutable evidence, require separate proposal and approval, and show observed, excluded, and adjusted outcomes rather than silently rewriting history.

Reviewed operator configuration/template/audience, authentication/RBAC, and analytics evidence-window/trend boundaries return stable allowlisted errors. Never reflect arbitrary `ValueError`, provider, driver, token, URL, or configuration exception text into an HTTP response.

The complete operator surface has an explicit 113-route authorization manifest: 103 capability-protected plus 10 dedicated/public routes. Browser and backend capability inventories must match exactly. Non-Azure navigation and actions are capability-gated, Help uses aggregate-read authority, and template safe preview is available to template reviewers without granting authoring or cloning. These are static contracts, not browser-live proof.

User-facing collection routes apply deterministic database pagination and bounded offsets; the browser follows pages only up to its explicit collection ceiling. Scheduling refuses more than 100 covering RoE candidates before signature work. Scoped campaign stop and delivery order through a shared/exclusive database lock rather than a process-local assumption. Application and worker runtime guards use explicit failures rather than optimization-removable `assert` statements.

Keep the simplified local control surface intentional: source seeding is `make seed`, not an installed `kp-seed`; ignored reminder, Mailpit-TLS, and queue-prefix settings are retired; and training due time is one fixed 72-hour policy. Settings may request a local restart, but remote full-stack stop routing, capability, and marker handling are absent from the browser, supervisor, and launcher. A host signal stops the launcher; full shutdown belongs to OS/launcher/terminal recovery. `make sign` must fail closed unless `IMAGE` is immutable and `COSIGN_KEY` plus `cosign` are available. No external signature has yet been witnessed.

These statements mean implemented and locally tested. No live Azure/Entra/Graph/ACS/Outlook qualification should be inferred.

The browser must obtain an exact `dev` or `oidc` authentication mode from the server before login. Discovery failure or an unknown value must stop login; never restore an implicit development-auth fallback.

Operator HSTS and production deployment-readiness checks are local application contracts only. The current build has not observed those headers through a production custom host/edge, provisioned a qualifying WAF boundary, or completed live rollback/restore evidence.

The reviewed Azure path has three exact stages: `foundation_bootstrap`, `foundation_finalize`, and `workloads`. Bootstrap plans and applies the complete `deploy_workloads=false` foundation—including ACR, private-network, data, ACS/email/domain, and DNS resources—without Terraform targets. It initiates exactly Domain/SPF/DKIM/DKIM2 verification while explicitly forbidding association/sender changes; every stage refuses delete/replacement plans. Finalize requires fresh authenticated all-four Verified readback, permits only association/sender changes, and proves both after apply. Workloads repeats exact live readiness before deployment. The API/GUI reject the seven obsolete operator readiness fields, restore the owner's latest environment plan, create a new digest-bound plan for each allowed advance, and validate/display the bounded `kp.acs-stage-result.v1` artifact. GUI Terraform export, API validation, Terraform, and preflight share the exact one-label HTTPS `*.communication.azure.com:443` contract. Workloads requires exactly one active Healthy/Provisioned worker revision, every enabled role ready in two consecutive simultaneous current-revision Log Analytics observations, and a final health check of that same revision before the environment checkpoint passes. Missing or mismatched evidence becomes `evidence_unverified` and cannot advance. The connector is pinned to workflow SHA-256 `6868067ef5d58c799bc4a07dd832d4852d38dee73e6ff1af9a58c701ce85a4d3`. Protected bootstrap and external provider verification remain human-administered; no stage has been live-qualified.

The release workflow explicitly builds `linux/amd64`, captures and re-resolves immutable ACR digests, binds SBOM/provenance evidence to each digest, rejects reviewed configuration containing credential/token material, disables persisted checkout credentials, and removes ephemeral registry credentials. Preserve those controls. The connector validates protected-environment metadata/reviewers, exact workflow/ref/content, newly dispatched run identity/status, and owner-bound Redis leases. The recovered Terraform provider tree passes provider-backed local initialization and validation. Read-only GitHub access to `ELDSRQ/kingphisher-phoenix` is now valid, but no workflow dispatch/run occurred, no remote backend exists, and none of the three Azure stages has run.

Exact-final ARM64 status is evidence-conditional: a pass requires retained,
no-clobber `qualification.json` and scan evidence proving the exact Docker
server platform without emulation, explicit `--platform`, all-five
OS/architecture/image-ID metadata, unchanged source/context manifests, Trivy
0.74.0, the expected source-manifest digest, exact Trivy executable/hash/cache, retained empty config/ignore/secret policy files,
ambient-`TRIVY_*` rejection, fresh database/check-bundle metadata, an immutable
verified cache, and cleanup limited to verified labeled disposable resources. Azure
workloads scan each exact immutable ACR `repository@sha256` image with pinned
Trivy before SBOM/attestation/deploy and retain scan JSON with checksums. Do not
infer a pass from the presence of these controls.

The preserved `final-v2` qualification failed closed before image build because
BSD filesystem-mode and evidence-path/source-context defects violated the
verifier contract. Its evidence remains preserved. The repaired `final-v3`
attempt is conditional until no-clobber `qualification.json`, exact-engine
metadata, and all five verifier-produced Trivy JSON/checksum artifacts validate.

The GUI now makes SMTP/ACS and Mailpit/Microsoft 365 providers explicit and
passes only active non-secret fields to setup assistance. Inactive saved values
remain preserved; provider/destination changes validate before atomic credential
rebinding. ACS is exact-origin, non-sending reachability-only; Microsoft 365 uses
one quoted/bounded Graph delta probe and fails closed on bearer or redirect
errors. Privacy export is authenticated `POST`, privacy list/export data is
`private, no-store`, and cookie mutations require same-origin CSRF metadata.
The console loads privacy requests and the current notice independently, so a
notice read failure warns the operator without disabling request operations.
OIDC endpoints are issuer-origin bound and use single-resolution, IP-pinned TLS
transport without redirects, environment proxies, or HTTP/2; cross-origin
authorization and secret-bearing token/JWKS requests fail before transmission.

The existing approved non-local HTTPS gateway implementing `/propose` and
`/setup-assist` remains a supported optional adapter; local, credential-bearing,
query-bearing, or fragment-bearing endpoints fail validation. It is not the
supported default AI deployment path. Pattern approval commits a durable
generation request and returns only that fact—it does not claim queue or
provider completion. The pinned internal-model worker path and live inference
qualification remain open.

The historical 2026-08-28 read-only Azure audit confirmed the selected subscription/tenant, Owner authority, `eastus2`, and required provider readiness including `Microsoft.Communication`; it also found no Terraform backend, foundation group, platform Entra applications, or application resources. The 2026-08-29 sandboxed re-audit could prove only an enabled cached account because DNS could not resolve `management.azure.com`, so current Azure management-plane state remains unverified. The live GitHub re-audit proves valid `ELDSRQ` authentication with `repo`/`workflow` scopes; a public, enabled repository with default `main`; Actions enabled; and the Azure workflow active, with no billing-disabled run signal. It also proves zero environments, variables, secrets, rulesets, and workflow runs, unprotected `main`, disabled secret scanning and push protection, and remote `main` at old-tree SHA `1403d944a40214714b6cbfcf5cbabc4fa7225eb9` at re-audit time; the checkpoint push has since advanced remote `main` to `c9ea716`. No workflow dispatch/run or Azure apply occurred. Azure script/preflight repairs passed 56 tests with 1 pre-existing live skip; this is prerequisite/static evidence only.

## Working method

1. Inspect `git status` and preserve unrelated/user changes.
2. Read the relevant model, migration, route, provider, UI, and test together before editing.
3. Keep migrations immutable once landed; add a new forward migration.
4. Add a regression test at the same boundary as the defect. Prefer a real PostgreSQL/Redis contract when concurrency, grants, locks, or Lua semantics matter.
5. Label evidence accurately: local/static, local-live, or cloud/provider-live.
6. Update only the canonical build plan for status/test counts. Do not copy volatile counts into handoffs.

Capacity gates are purpose-specific and fail closed. Earlier controller
inspection at about 5.9 and 5.6 GiB proved the 8 GiB deployment and 10 GiB
release-image floors stopped before unsafe work; those figures are historical,
not the current worker plan. External build/local-live capacity, its Colima
socket, and the preservation-first cutover/restore are proven. Exact-final
images remain open until rebuilt and rescanned there. Never trade recovery
evidence or cached exact images for a temporary pass.

Common gates are defined by the Makefile and release scripts. `make test` is hermetic; PostgreSQL, Redis, local E2E, and Azure-live evidence belongs only to its explicit profile. Every invoked profile rejects skips. Operational readiness must preflight disk, Docker/Compose, and service health before running hermetic, PostgreSQL, Redis, audit, install, and E2E gates, and it must not print connection URLs. Also run focused tests, Ruff/format, strict mypy, JavaScript/Actionlint, `git diff --check`, fresh-migration contracts, Terraform formatting/validation, security scans, and image verification in proportion to the change. A skipped or deselected integration is not release evidence.

The historical pre-Wave-30 result was 1,994 hermetic, 87 PostgreSQL, 2 Redis, and 8 E2E tests; the superseded intermediate external result was 2,230/86/2/8; and the 2,329 hermetic/97 deselected, 86 PostgreSQL/2,340 deselected using Redis DB14, 2 Redis/2,424 deselected using DB15, and 8-E2E operational snapshot is now pre-remediation evidence. PostgreSQL testing flushes only DB14, Redis queue testing uses DB15, and neither may touch application DB0. Its 03Z logs were clean and its audit acceptance fixed owner-fallback revocation and 36 stranded queue intents. The pre-Wave-36 local hermetic `make test` passed 2,469 tests/97 deselected with 0 failures in 158.15 seconds. The final local Wave 36 hermetic suite at historical head `0030` passed 2,501 tests/97 deselected with 0 failures in 183.40 seconds. Ruff/format, mypy, and security results remain bounded to their separately recorded scopes. Current-head `0032` PostgreSQL/Redis/E2E external profiles, exact-image evidence, browser/WCAG, full recovery, remote Terraform/Azure execution, and cloud/provider/human gates remain open.

Normal bootstrap/development/console launch must keep using the frozen `uv.lock`. Local Compose and mock base images remain immutable manifest digests, and the mock dependency closure remains fully pinned and hash-verified. `make security-scan` must fail closed if frozen export or audit fails and audits the hash-verified 58-package external production workspace closure. `make sbom` exports CycloneDX 1.5 with 59 total components/58 external PURLs. Starlette tests use the official `TestClient` through the test-only `httpx2` compatibility dependency; do not replace production `httpx` with it.

## Near-term priorities

Use the build plan’s goal-aligned dependency order:

1. Close the one ORM retention-metadata P1, run the full local and current-head
   PostgreSQL gates, reconcile evidence, then commit and push the preserved
   checkpoint. Continue privacy/RBAC/API/reporting/graph consumers of the
   `0032` outcome/retention/interaction foundation.
2. Complete the minimum product loop: benchmark/select the pinned internal
   model, implement `AI-010` in the existing worker role/job, then deliver
   campaign-specific micro-training and named five-year disposition/trends.
3. Make Azure/mail deployment simple through the GUI after the interfaces
   stabilize, while preserving current provider adapters and the reviewed
   three-stage fail-closed deployment/recovery controls.
4. Qualify the exact stable product with current-head external profiles,
   exact-final ARM64, native AMD64/registry/attestation, real-browser/WCAG,
   disposable Azure/provider, recovery/rotation, audit witness, and human
   acceptance evidence.
5. Simplify navigation/modules only after core stability; retain and support
   deferred useful behavior without expanding it.

Wave 21's latest completed snapshot rebuilt all five native ARM64 images; applicable checks, 30 focused contracts, and Trivy at 0 HIGH / 0 CRITICAL vulnerabilities and 0 secrets passed. Later source edits through Wave 38 make those interim images stale. External-worker capacity is now the execution path, but no exact-final rebuild/rescan has yet been claimed. AMD64, registry publication/attestation, and live Azure evidence remain open.

The earlier operational-readiness interruption remains historical. Docker recovered, installation verification is green after restart, and all 8 live local E2Es pass. The backup and targeted audit repair were local reconciliation, not a restore pass. Static accessibility-shell contracts pass; full browser/WCAG and assistive-technology evidence remains open. Mailpit and Terraform now pass their focused local lanes, but those do not prove external delivery or Azure deployment. Graph/Microsoft 365/ACS-event/reported-MIME, server-derived flag/privacy, connector, outbox, and worker repairs also have focused point-in-time evidence in the canonical plan; the overlapping counts are not a final broad-suite result.

For RSA use, require a written RSA-controlled RoE and exact RSA-controlled population. Conference attendance is not authorization.
