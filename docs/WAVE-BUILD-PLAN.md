# Phishing Awareness Platform — Integrated Build Plan

**Audit date:** 2026-08-29<br>
**Baseline:** `main` at `1403d94`; current `origin/main` is `c9ea716` (checkpoint `d25313d` + ANA-010 increments `aa67c17`, `c9ea716`)<br>
**Decision:** **NO-GO for production or an RSA Conference campaign.** Core safety and workflow defects have been repaired locally, but the build has not passed the live Azure, Entra, Microsoft Graph/Outlook, ACS/Event Grid, browser-accessibility, recovery, or external audit-witness gates. Do not treat local/static evidence as operational qualification.

This is the canonical architecture, security, product, and delivery plan for `ELDSRQ/kingphisher-phoenix`. Older handoff, remediation, and test-count claims are historical until reconciled with this document.

Wave 36's conflict-controlled execution details and current acceptance evidence
are in [the production-readiness task matrix](PRODUCTION-READINESS-TASK-MATRIX.md).

## Current engineering topology

The controller retains the workspace at
`/Users/edierks/projects/codex-test/phishing-awareness-platform`. The target
native ARM64 worker is `192.168.1.140`, with canonical source
`/Users/edierks/Projects/kingphisher-phoenix` mounted read-only inside the
project-only `kingphisher` Colima profile. Its VM/cache/client state and socket
are rooted under `/Volumes/DockerExternal/KingPhisher-Phoenix`.
External preflight/restore passed; final exact preflight reported approximately
744,006,440 KiB free. The inactive `kp-external-mac` context is
created with endpoint
`ssh://edierks@192.168.1.140/Volumes/DockerExternal/KingPhisher-Phoenix/colima/kingphisher/docker.sock`
and reports `colima-kingphisher|aarch64|/var/lib/docker`. The remote global context remains
`desktop-linux`; the seven internal Docker Desktop project containers are
stopped/preserved and unrelated workloads remain running and are never selected as
fallback, or mutated. The legacy encrypted snapshot is preserved but
unrecoverable because its identity is absent, so it does not satisfy `EXT-002`.
Rosetta/binfmt are disabled; native AMD64 remains separate. The USB/HFS+ worker
is unencrypted/no-SMART engineering infrastructure, not Azure production
hosting.
The legacy Docker contexts `DockerExternal` and `kp-remote-mac` omit the
reviewed socket and can select shared Docker Desktop; never use them for this
project. The external volume named `DockerExternal` remains the storage target.

The controller recovery identity is verified at public recipient
`age1p9t25wm9uvcaafjv3hjmgsj092mgydrr9uzndjnmcq9psupfl94qm8h2w2`.
Headless SSH cannot unlock the remote Keychain, so `checkpoint-remote.sh`
performs only an exact temporary identity transfer/cleanup. A successful apply
must then pass controller `stage-remote.sh`, which invokes remote
`stage-checkpoint.sh` with a second bounded transfer to validate one direct-child archive
and no-clobber publishes its reserved `migration-checkpoint/` payload before
external-engine-scoped `restore-state.sh`. Snapshot
`20260829T013332Z-tsX1WQ`, archive SHA-256
`e4fb16a735d0c9d3b6aa04381c4c9d7e24269006203c551f50abf671cc3637ff`,
passed this chain and external restore. External installation and
`verify_install.sh` passed. Final local hermetic now passes; external
PostgreSQL/Redis/E2E, image, browser, and cloud gates remain open.

## Product direction

The target is a simple, single-tenant, GUI-operated awareness platform with commercially credible simulation and training. Normal installation, upgrades, Azure integration, mail integration, campaign operation, recovery, and evidence export must be possible from the GUI. A one-time, explicitly documented bootstrap action is acceptable; routine shell, Terraform, GitHub workflow, or secret-file work is not.

AI may propose deployment settings, integration mappings, and campaign content, but a human must review every state-changing plan. Deterministic code—not AI—must enforce authorization, recipient scope, safety, approvals, RoE, and delivery controls.

Favor three deployables:

1. Operator API and GUI (control plane).
2. Public tracking and training API.
3. One multi-role worker, with delivery separable only when scale or isolation proves necessary.

Keep feature modules inside those deployables. Do not solve the current complexity by adding services.

## Goal-aligned priority policy (2026-08-29)

This section is authoritative for **new work**. Older priority labels and the
historical wave sequence below record how the current build was produced; they
must not be used to justify more scope. The product is for one 125-person
organization operated by two IT staff. A feature earns priority only when it
helps those operators safely curate a current threat, prepare and approve a
simulation, deliver it to an explicitly authorized audience, train the user,
measure defensible outcomes, or deploy and recover that workflow through the
GUI.

KnowBe4 is a functional reference, not a requirement to reproduce its breadth.
The target remains a single-tenant modular monolith with the three deployables
above. Production/security qualification is not optional work and cannot be
deprioritized as “infrastructure.”

### Priority order

| Order | IDs | Required outcome | Why it is in scope |
|---:|---|---|---|
| 0 — decide before feature code | `ORG-001`, `OUT-001`, `RET-005`, `MAIL-005`, `AI-005` | Adopt the two-person approval model; canonical outcome taxonomy; five-year ledger/privacy policy; honest provider support matrix; and internal-model-first AI architecture | These decisions change database, authorization, UI, deployment, and test contracts. Building around the current assumptions would create rework. |
| 1 — repair the existing operator loop | `THR-001A`, `IMP-001`, `INT-001`, `DOCSIM-001` | Preserve source excerpt, observation time, claimed actor and sector through generation; correct the broken ICS promise; add guided CSV mapping/preview/merge/deactivate; distinguish observed scanner-triggerable events from confirmed human interaction | These are current defects, false promises, or missing required paths—not competitive embellishments. |
| 2 — deliver the minimum complete product | `THR-001B`, `AI-010`, `TRN-010`, `ANA-010` | One Threat Campaigns queue; bounded scheduled ingestion; internal AI-assisted safe draft; campaign-specific micro-lesson/question; named campaign disposition; pseudonymous five-year ledger and click/no-click trend graph | This is the shortest complete path from current threat to measurable awareness improvement. |
| 3 — make deployment genuinely simple | `DEP-010`, `MAIL-001`, `M365-001`, `M365-002` | Browser Azure sign-in and discovery, strong defaults, Advanced-only internals, GUI progress/retry/rollback/recovery, and first-class ACS plus advanced SMTP integration | A two-person team should not have to understand Terraform, GitHub workflow internals, Azure resource IDs, or raw secret files for the normal path. |
| 4 — qualify the exact product | `QA-030`, `PROD-030` | Current-head PostgreSQL/Redis/E2E, exact AMD64 images/registry, disposable Azure, Entra/Graph/Outlook/ACS, browser/WCAG, recovery, audit witness, and human operator acceptance | Local/static checks cannot establish production or RSA campaign readiness. Final image/cloud evidence follows behavior changes so it is not made stale immediately. |
| 5 — simplify after the core is stable | `UX-010`, `ARC-001` | Consolidate navigation to Home/Threats, Campaigns, People/Training, Reports, Settings/Deployment; split oversized modules inside existing deployables; remove demonstrably dead source metadata paths | This reduces operator and maintenance cost without adding product surface. Refactors must preserve stable APIs and follow core behavior. |

`ORG-001` should replace the current three-distinct-person requirement with a
creator plus one independent approver. The independent approver completes one
combined security/privacy checklist. Signed RoE, frozen audience, canary,
provider evidence, emergency stop, and immutable review evidence remain
mandatory. This reduces staffing friction without allowing self-approval.

`OUT-001` should define the supported campaign outcomes as accepted/delivered,
reported, observed open, observed click, confirmed interaction, training
started/completed/passed, and **no observed activity at campaign close**.
Mailbox deletion is not reliably observable and must not be offered or inferred.

`RET-005` should retain minimized raw delivery/tracking evidence for no more
than the current 365-day window while maintaining a separate pseudonymous
1,826-day awareness ledger. Named drill-down is capability-protected and
audited; exports, privacy notice, legal basis, deletion/rectification behavior,
and key recovery must be decided before the migration is written.

`MAIL-005` should state the actual support boundary: Azure Communication
Services is the recommended managed sender; SMTP is an advanced compatible
sender; Microsoft Graph supports directory synchronization and reported-mail
ingestion. Graph `Mail.Send`, generic “any mail platform,” and deletion
telemetry are not current capabilities.

### Internal-model-first AI decision

`AI-005` removes Azure OpenAI/Foundry as a mandatory dependency. “Managed AI”
means a lifecycle-controlled inference path, not a particular Azure product.
The lowest-complexity candidate is the existing worker image executing a pinned
`llama.cpp` runtime as a bounded, event-driven generation role/job. This reuses
the durable generation request and does not add an always-on service. Model
weights, runtime, license text, prompt version, and evaluation result must be
versioned and digest-pinned; production may not auto-pull or auto-update them.

Before selecting a model, benchmark two or three small permissively licensed
instruction models on a fixed, sanitized evaluation set. The acceptance order
is: valid schema-constrained JSON; evidence fidelity; safe refusal and content
validation; prompt-injection resistance; then latency, memory, and cost. The
model receives only bounded reviewed evidence, has no tools or outbound network,
cannot approve or launch, and remains subordinate to deterministic validation
and human review.

Deployment order for inference is:

1. CPU-only Azure Container Apps consumption/job if the selected quantized
   model meets the measured operator latency target.
2. Scale-to-zero Azure Container Apps serverless GPU only if the CPU benchmark
   fails and quota, region, cold start, and total cost are acceptable.
3. Foundry serverless/token inference as an optional, explicitly selected
   fallback only when measured quality or total cost is better.

Foundry managed compute, an always-on GPU, and a general multi-provider AI
framework are out of scope for this organization. The `.140` Apple Silicon
worker may run the same pinned model for development and qualification, but it
must not become a production Azure dependency. Deployment discovery and safe
defaults remain deterministic so setup still works when AI is unavailable;
optional pre-deployment AI may run only on operator-approved internal hardware.

### Explicitly deferred or rejected

- Adaptive/open-ended programs, new-hire automation, difficulty engines, large
  template/course libraries, LMS features, gamification, and localization.
- Advanced cohorts, causal training-efficacy claims, scheduled report delivery,
  and a general corrections workflow. Basic per-user history, repeat count,
  campaign disposition, and the five-year click/no-click graph remain in scope.
- QR, reply tracking, credential-entry simulation, executable or macro-bearing
  attachments, and pixel-perfect replication. A later safe document-preview
  link may record access, never execute or collect credentials.
- Additional mail transports, Graph `Mail.Send`, and provider-neutral promises.
  Add a provider only after a real customer need and an end-to-end qualification
  plan exist.
- Autonomous APT attribution, broad threat-intelligence correlation, or an
  automated campaign selector. Operators curate source-backed actor/TTP/sector
  metadata and explicitly choose every simulation basis.
- More microservices, replacement of Redis before the current topology is live
  qualified, more GitHub orchestration, or expansion of desktop/launcher
  packaging. Hide existing engineering internals behind the GUI instead.
- Foundry managed compute, dedicated always-on GPU capacity, model fine-tuning,
  autonomous agents, tool-using models, and a broad model-provider abstraction.

Deferred work must be marked `DEFERRED` in future task matrices and must not
consume an implementation slot unless the operator explicitly changes product
scope. Rejected behavior must be removed from product claims even if no code
change is otherwise needed.

## Current build status

| Area | Status | Evidence-based assessment |
|---|---|---|
| Local code quality | Current-head hermetic, PostgreSQL, and Redis gates pass; E2E, image, and release gates open | At checked-in head `0032_source_explicit_curation`, `make test` passed 2,620/103 deselected with 0 failures in 180.45 seconds; `make lint` and strict mypy (131 source files) pass. The historical Wave 36 result was 2,501/97 at head `0030`; Ruff/format and strict mypy remain bounded to their separately recorded scopes. E2E, browser, and exact-image gates remain separate. |
| Full test gate | Current-head hermetic, PostgreSQL, and Redis profiles pass; E2E and release gates open | Current-head `0032` results (2026-08-29, controller via the reviewed external-worker tunnel): hermetic 2,620/103 deselected with 0 failures; PostgreSQL 92 passed (including fresh-install/historical migration and retention concurrency coverage); Redis 2 passed on DB15. The historical final local Wave 36 result was 2,501/97 at `0030`. E2E, exact-final ARM64/AMD64, browser/WCAG, and cloud/provider gates remain pending. |
| Security gate | Current source/workflow checks pass; exact-final image evidence open | Bandit passed; Semgrep ran 4 rules across 125 targets with 0 findings; Trivy repository scans found 0 HIGH/CRITICAL vulnerabilities, secrets, or misconfigurations; pip-audit found no known vulnerabilities; Actionlint and Zizmor passed. Historical Wave 21 CI evidence remains bound to exact workflow SHA-256 `03686ddd51aa301ff829e3c6a78ed5d3322fc63277e20cdbeeb7c42a1de3baaa`. Exact-final status depends on retained qualification/scan evidence; AMD64 and registry publication/attestation remain unwitnessed. |
| Terraform | Local/provider validation passes; cloud absent | Current Terraform formatting and validation pass. The recovered provider/resource tree also passed 43 point-in-time lane tests and provider-backed `terraform init -backend=false`. This is local/static evidence only: no remote backend, Azure plan/apply, state/recovery exercise, or provider-live qualification exists. |
| Fresh installation | Current-head `0032` migration gate passed on the external worker's PostgreSQL; exact-image evidence open | Revision 0001 remains frozen and the checked-in code head advances linearly to `0032_source_explicit_curation`. The current-head fresh-install/historical migration gate (including the retention concurrency and outcome-writer-versus-retention lanes) passed within the 92-test PostgreSQL profile against the external worker's live PostgreSQL on 2026-08-29. Snapshot restore at `0029` plus external install/verification remain historical; exact-final ARM64, AMD64, registry, and deployment evidence remain open. |
| Azure deployment | Three-stage workflow/Terraform/API/GUI contract implemented; live deployment absent | `foundation_bootstrap` applies the complete `deploy_workloads=false` ACR/private-network/data/ACS/DNS foundation without Terraform targets, initiates four verification types, and forbids sender/association changes; `foundation_finalize` requires fresh all-four Verified state, allows only association/sender changes, and proves both post-apply; `workloads` revalidates exact resources and immutable images, then requires exactly one active Healthy/Provisioned worker revision, two consecutive simultaneous current-revision ready observations for every enabled worker role, and a same-revision final health recheck. Every stage refuses deletion/replacement. Manual ACS claims are rejected. The GUI resumes/advances new digest-bound plans, displays validated bounded artifact evidence, and exports the same exact ACS endpoint contract enforced by API/Terraform/preflight. The connector is pinned to workflow SHA-256 `6868067ef5d58c799bc4a07dd832d4852d38dee73e6ff1af9a58c701ce85a4d3`. GitHub authentication/repository/Actions/workflow are valid with no billing-disabled run signal, but environments/variables/secrets/rulesets/runs and branch protection are absent, secret scanning/push protection are disabled, and remote `main` was at old-tree SHA `1403d944a40214714b6cbfcf5cbabc4fa7225eb9` at re-audit time; the checkpoint push has since advanced remote `main` to `c9ea716`. Current Azure management-plane state is unverified because sandbox DNS blocked the re-audit; no workflow dispatch/run or Azure apply occurred. |
| Mail platform | Current local durable-gate Mailpit lifecycle passed; provider runs pending | ACS send, pacing, authenticated/minimized delivery receipts, suppression, Graph directory delta sync, and Outlook report-message ingestion are wired. The current loopback `example.com` durable-gate canary passed within the external 8-test E2E profile at exact head `0029`, proving approved-template send, retry suppression, recipient-bound tracking/training, and correlated report/audit state with exact cleanup. SMTP acceptance by Mailpit is not inbox placement; real tenant consent, DNS/domain, quota, delivery, paging, receipts, and correlation remain. |
| Campaign workflow | Core and durable canary gate implemented locally | Exact previewed/frozen audiences, approval/RoE invalidation, idempotent delivery claims, generation queue-key idempotency, persistent emergency stop, purpose-bound training links/quiz/remediation, exact campaign-training binding, safe preview, and auditable exclusions have tests. One immutable launch review binds configuration, RoE, audience, template, lesson, and locked test accounts; `/schedule` queues only the canary and `/publish` requires current provider-derived evidence. Browser/load/live-provider and migrated-PostgreSQL two-phase evidence remain. |
| GUI-only operation | Partial | Campaign, integration, reporting, recipients/exclusions, training-resource governance, queue, sources, and the reviewed three-stage Azure dispatch/evidence lifecycle are GUI-driven. Protected connector/credential bootstrap, external DNS/provider consent/verification, rollback/recovery, edge completion, and live qualification still require external administration; these remaining normal-path shell/admin handoffs prevent a 100% GUI production claim. |
| Goal alignment | Partial | Two-person approval, threat-evidence fidelity, guided CSV import, explicit Threat Campaigns curation, confirmed interaction, truthful ICS behavior, the locked 1,826-day pseudonymous ledger/365-day raw-retention foundation, and its five-year click/no-click trend graph are complete locally. Named-history/privacy/RBAC consumers, campaign-specific micro-training, internal-model execution, simplified GUI deployment, and live operational proof remain. Commercial breadth outside the explicit priority policy is deferred. |
| Recovery-safe local deployment | External-worker cutover/restore and final local profiles passed | Wave 29 freezes Compose/volume identities and fails closed around preserved state. Snapshot `20260829T013332Z-tsX1WQ` passed decryption, PostgreSQL/Redis validation, staging, and clean external restore; 39 tables and Redis DB0 766→766/DB15 12→12 were proven. Final exact preflight reported approximately 744,006,440 KiB free. The internal project is stopped/preserved and unrelated containers remain running. Image/browser/cloud qualification remains open. |

### Recorded integrated and lane test evidence

- Pre-remediation local/external integrated acceptance reached exact head `0029`: hermetic 2,329/97 deselected; PostgreSQL 86/2,340 using Redis DB14; Redis 2/2,424 using DB15; audit/install; and 8 E2Es, with clean 03Z logs. The pre-Wave-36 local hermetic `make test` passed 2,469 tests/97 deselected with 0 failures in 158.15 seconds. At historical head `0030_default_privacy_notice`, the final local Wave 36 hermetic suite passed 2,501/97 deselected with 0 failures in 183.40 seconds. **Current-head `0032` evidence (2026-08-29, after the Wave 38 checkpoint landed as `d25313d`):** hermetic 2,620/103 deselected with 0 failures in 180.45 seconds; external PostgreSQL 92 passed (fresh-install/historical migration, retention concurrency, outcome-writer-versus-retention, grants); external Redis 2 passed on DB15. E2E, exact-final ARM64/AMD64, browser, and cloud/provider evidence at `0032` remains pending.
- Wave 36 implemented/static closures add the `0030` persisted default and single-current privacy invariant, independent privacy-request UI degradation, mandatory approved managed AI contract with durable generation requests, exact GUI/API/Terraform/preflight ACS endpoint parity, bounded Container Apps trusted-proxy/XFF handling, and a current-revision two-observation worker-role health gate. Live Azure telemetry/ingress, AI provider, external migrations/profiles, and final images remain open.
- Provider-aware GUI remediation adds explicit SMTP/ACS and Mailpit/Microsoft 365 selects, active-only non-secret AI/setup context, exact-origin warning-only ACS reachability, one quoted/bounded Graph delta probe, and validation-before-atomic credential rebinding. Privacy export is POST-only with no-store/list and same-origin CSRF enforcement. OIDC is issuer-origin bound and uses DNS-pinned TLS transport without redirects/proxy inheritance/HTTP2. These are focused/static controls, not provider/browser-live evidence.
- The superseded intermediate external result was 2,230 hermetic/97 deselected, 86 PostgreSQL/2,241 deselected, 2 Redis/2,325 deselected, and 8 E2Es; it is historical rather than current release evidence.
- Historical Wave 29 integrated acceptance passed 1,994 hermetic/87 PostgreSQL/2 Redis/8 E2E tests. That controller snapshot proved the capacity gates stopped safely; it is retained as historical evidence, not the current result.
- Historical pre-Wave 11 broad quality gate: Ruff check/format across 264 Python files, Actionlint, console JavaScript syntax, and strict mypy across 121 source files passed. The Wave 18 closing gate superseded that scope at the time: Ruff check/format covered 292 Python files, strict mypy covered 123 source files, Node syntax passed, all 13 shell checks passed, and Terraform formatting/validation plus Actionlint passed. The current-tree rerun is recorded immediately above.
- Historical pre-Wave 11 non-Azure-live pytest result: 1,240 selected, 1,232 passed, 8 environment-gated skips, 0 failures. Test profiles have since changed, so this is retained as historical evidence rather than a current-tree release count.
- Interim Wave 15 hermetic snapshot during concurrent integration: 1,245 passed, 85 deselected, 0 skipped, with one third-party warning. A later warning-strict intermediate run passed 1,261 with 85 deselected but excluded concurrently changing deployment/readiness tests. Neither is the final integrated count.
- Final Wave 17 warning-strict hermetic gate: `.venv/bin/python -m pytest -o addopts='' -q -m "not postgres and not redis and not e2e and not azure_live" -p tests.no_skips_plugin -W error` passed 1,379 tests with 85 deselected, 0 skipped, and 0 warnings in 59.05 seconds. This is historical after Wave 18 changes; the first bullet in this section is the current integrated result.
- Wave 18 integrated warning-strict hermetic snapshot: `.venv/bin/python -m pytest -o addopts='' -q -m "not postgres and not redis and not e2e and not azure_live" -p tests.no_skips_plugin -W error` passed 1,622 tests with 91 deselected, 0 skipped, and 0 warnings in 67.68 seconds. Fresh-cache `uv lock --check` resolved 90 packages in 4 ms, and `git diff --check` was clean. The closing focused bundle passed 104 tests. Later source changes make this historical, and it does not execute or qualify PostgreSQL, Redis, E2E, Azure-live, browser, exact images, provider, recovery/rotation, or witness gates.
- Final focused logging regression suite after the traceback hardening: 37 passed; 21 production exception/traceback sites were replaced, and no `logger.exception`, `.exception`, or `exc_info=True` call remains in production applications, packages, or scripts.
- Historical Wave 19 PostgreSQL profile with skip rejection and warnings as errors: 83 passed, 1,634 deselected, 0 skipped, and 0 warnings. The isolated fresh base/historical-to-current-head gate passed 1 test and confirmed head `0027`; qualification repairs also closed leaked schema/table/role/engine cleanup paths. Earlier `0025`→`0026` preservation/write-bound/least-privilege evidence remains valid. The later pre-Wave-30 87-test result is recorded above as historical.
- Wave 19 expanded Redis atomic-queue contract with skip rejection: 2 passed and 1,713 deselected. This supersedes the earlier one-test Redis evidence.
- Audit-anchor least-privilege acceptance against a migrated local PostgreSQL database with skip rejection: 1 passed, including secret/outbox/business/DML/dispatch denials.
- Current source/workflow-security evidence: Bandit reported no findings; Semgrep reported 0 findings for 4 rules across 125 targets; Trivy repository scans reported 0 HIGH / 0 CRITICAL vulnerabilities, 0 secrets, and 0 misconfigurations; and `pip-audit` reported no known vulnerabilities. Actionlint and Zizmor are green. CycloneDX 1.5 previously emitted 59 components/58 external PURLs. These are source/dependency results, not exact-final image evidence.
- Exact-final ARM64 status is evidence-conditional. A pass requires retained
  no-clobber `qualification.json` plus scan evidence proving the exact Docker
  server platform without emulation, explicit `--platform`, OS/architecture/image-ID
  metadata for all five images, unchanged source/context manifests, Trivy
  0.74.0, the expected source-manifest digest, exact Trivy executable/hash/cache, retained empty config/ignore/secret policy files,
  ambient-`TRIVY_*` rejection, fresh database/check-bundle metadata, an
  immutable verified cache, and cleanup limited to verified labeled disposable resources. Azure
  workloads scan each exact immutable ACR `repository@sha256` image with pinned
  Trivy before SBOM/attestation/deploy and retain scan JSON/checksums. The
  controls are implemented; this plan does not infer a pass.
  The planned authoritative ARM64 evidence root is
  `/Volumes/DockerExternal/KingPhisher-Phoenix/qualification-evidence/arm64-release-20260829-wave35-final-v3`
  (`verifier/` beneath it), using unique prefix
  `kingphisher/verify-arm64-20260829-w35-final-v3`; only validated contents at
  that identity determine the gate.
  The preserved `final-v2` attempt failed closed before build because BSD
  filesystem-mode and evidence-path/source-context defects violated the
  verifier contract. Its evidence remains preserved. The repaired `final-v3`
  result remains conditional until no-clobber qualification and exact five-image
  Trivy JSON/checksum evidence validate.
- Wave 16 local supply-chain evidence is focused and must not be summed into a full-suite count: an interim 52-test local supply-chain/mock/container/release/launcher subset passed before the final fail-closed audit regression was added. The later behavioral contract proves that `pip-audit` cannot run after a failed export, and the corrected online dependency gate passed with zero findings. Local Compose and mock-service base images are pinned by tag plus immutable manifest digest; the mock Python runtime has a fully pinned, hash-verified 17-package closure; bootstrap, development, and console launch use the frozen workspace lock; and native `uv` CycloneDX 1.5 export emits 59 total components, including 58 external package PURLs.
- The recovered Terraform provider/resource tree passed 43 point-in-time lane tests, provider-backed `terraform init -backend=false`, and `terraform validate -no-color`. This replaces the stale active-work claim but remains local/static evidence; there was no remote-backend initialization, Azure plan/apply, state recovery, or cloud/provider-live exercise.
- Wave 21's latest completed native ARM64 rebuild covered operator, tracking, worker, migration, and mock services. All five passed applicable startup/entrypoint/migration checks and 0 HIGH / 0 CRITICAL / 0 secret scans; 30 focused image/packaging contracts also passed. Wave 29/30 source edits make those interim image IDs and sizes stale. The old controller capacity block is historical; exact-final work is pending on the external worker. A cold AMD64 cross-build previously timed out; no multi-architecture or registry publication/attestation evidence is claimed.
- The former Debian image findings (18 HIGH, 3 CRITICAL across OS and embedded packaging metadata) were removed by switching to pinned minimal Chainguard Python 3.14/Wolfi builder/runtime digests; runtimes contain no `pip`, `setuptools`, `msgpack`, package manager, or build tooling.
- Waves 11–13 focused evidence is component-scoped, not a new full suite: 15 outbox/migration contracts; 11 ingestion-fence tests plus the worker suite with 5 pre-existing environment skips; 45 operator content/sending/error-boundary tests, including 20 live-PostgreSQL no-skip tests; 4 readiness-harness tests; 85 auth/RBAC no-skip tests; 56 retired-secret no-skip tests plus Terraform validation; 107 dead-code regression tests; and 26 analytics no-skip tests. Central integration reruns also passed 9 outbox/ingestion tests, 21 non-database operator boundary tests, the 85 auth/RBAC tests, the 56 retired-secret tests, the 26 analytics tests, and the 4 readiness tests.
- Wave 14–15 commands are focused and may overlap; do not sum them into a suite total. Evidence: 87 initial deployment-orchestration tests and 115 broader two-phase Azure GUI/workflow/Terraform tests; after complete workflow hardening, 34 focused orchestration tests plus Actionlint and a 0-finding Zizmor offline/auditor run; an initial 281-pass worker configuration/supervisor/directory command with 5 environment skips followed by a worker non-PostgreSQL command that exited 0 with no skips; 49 public-tracking-boundary tests; 46 training-link-binding tests; 148 settings-secret-boundary tests; 20 combined launcher/readiness tests; and 5 readiness-harness tests.
- The seven running-stack tests remain isolated under the `e2e` marker and skip-rejecting. After local bootstrap/audit backup, targeted reset, migration/seed, token-key, PID/log, mock Graph, and fixture repairs, `verify-install` was green and the strict E2E command passed 7 tests with 0 skips and 0 warnings in 3.37 seconds. This is local-live evidence, not a full restore exercise or browser/WCAG proof.
- Focused Wave 16–18 contracts prove that operator and tracking do not publish OpenAPI, Swagger, ReDoc, or HTTP metrics routes and no longer retain write-only internal metric registries; the internal audit scheduler retains only aggregate status and bounded problem count; browser authentication-mode discovery fails closed; and the official Starlette `TestClient` works through the test-only `httpx2` compatibility dependency. SQLite ownership/outbox timestamp warnings and newly added PostgreSQL fixture cleanup are covered locally. Public tracking rejects duplicate as well as malformed `Content-Length` and returns capped non-reflective validation detail. At the Wave 18 point-in-time close, the explicit authorization inventory covered 111 operator routes; the current Wave 24 inventory covers 113—103 capability-protected plus 10 dedicated/public—after removal of the abandoned remote stop route. Browser/backend capability sets match exactly, and per-resource training actions use strict server flags. These are local/static claims, not browser or live-provider evidence.
- Wave 21 hardened the shared authorization and RoE boundary: roles are immutable typed snapshots; wildcard/malformed capabilities and unknown roles cannot escalate; self-approval compares canonical UUID principals and denial text is non-identifying; domains use strict canonical ASCII/A-label and suffix validation and reject Unicode/IP/single-label ambiguity; RoE v2 allows at most 100 domains, requires a key with at least 256 bits, signs bounded canonical fields, and requires aware ordered UTC windows with fail-closed comparisons. Shared `Campaign` size 1–10,000 plus campaign/program/training temporal invariants are enforced at their consumer boundary. The owned and operator/worker consumer-inclusive suite passed 374 tests; Ruff/mypy, Bandit/Semgrep at 0 findings, and offline build/import passed for both packages.
- Wave 21 CI hardening explicitly targets `linux/amd64`, captures and re-resolves immutable ACR digests, binds SBOM/provenance subjects to those digests, rejects credential/token material in reviewed deployment configuration, avoids persisted checkout credentials, and removes ephemeral registry credentials. The focused bundle passed 23 tests plus Actionlint and Zizmor; workflow/code/test SHA-256 is `03686ddd51aa301ff829e3c6a78ed5d3322fc63277e20cdbeeb7c42a1de3baaa`.
- The unused source-adapter clone implementation and exports were removed for a net reduction of 87 lines. Its focused regression suite passed 36 tests, and a downstream package/import gate passed 5 tests.
- The earlier operational-readiness interruption remains historical environmental evidence. Docker subsequently recovered, the local installation verifier is green after restart, and the recorded live local E2E profile passes 8 tests. Controller observations at about 5.9 and 5.6 GiB proved the capacity gates blocked safely; they are not the current worker plan. The targeted audit repair is not full backup/restore or production recovery evidence. Static accessibility-shell contracts now pass; full browser/WCAG and assistive-technology evidence remains open.
- Waves 22–23 point-in-time lane evidence is focused, overlapping, and must not be summed or treated as a current broad-suite result: Mailpit/training passed 123 focused tests plus one isolated local-live canary in 2.03 seconds; outbox passed 29 hermetic, 5 logging, and 1 isolated PostgreSQL test; Graph/Microsoft 365/ACS-event/reported-MIME provider hardening passed 92 owned plus 119 adjacent tests; the worker snapshot at that provider boundary passed 343 with 5 PostgreSQL-only skips; Terraform recovery passed 43 tests plus provider-backed `terraform init -backend=false` and `terraform validate -no-color`; server-derived campaign/pattern flags and privacy bounds passed 10 hermetic, 29 PostgreSQL, and 103 route/boundary tests; GitHub connector hardening passed 92 focused plus 96 including route authorization; and the final worker dead-path/wiring lane passed 355 hermetic tests with 5 PostgreSQL tests deselected.
- Wave 24 bounded user-facing database pagination and browser page collection, capped covering-RoE scheduling at 100 candidates with fail-closed overflow, replaced application/worker runtime `assert` guards with explicit failures, and added shared/exclusive campaign locking so scoped stop orders against delivery. Point-in-time worker evidence passed 52 focused lifecycle/security tests in 1.30 seconds and 15 isolated PostgreSQL tests in 3.07 seconds, including a 250 ms lock-contention proof. An exploratory PostgreSQL ACS pacing check printed `acs_pacing_upsert_and_durable_fence=ok` after reserving 3 and then 0 sends in the same window. These overlapping results are not a broad final-tree suite.
- Wave 24 dead-path cleanup removed the broken installed `kp-seed` wrapper while retaining source-checkout `make seed`; retired ignored reminder, Mailpit-TLS, and queue-prefix settings while keeping the fixed 72-hour training due policy; and removed the remote full-stack stop route. `make sign` now fails closed unless `IMAGE` is an immutable digest reference, `COSIGN_KEY` is set, and `cosign` is installed. No external signature, registry, or attestation evidence is claimed.
- Historical Wave 25 integrated hermetic evidence: the exact warning-strict, no-skip non-PostgreSQL/non-Redis/non-E2E/non-Azure profile passed 1,899 tests with 98 deselected. Process-stop capability and marker handling are fully retired from the browser application, local supervisor, and launcher; restart remains, and an OS signal stops the launcher. Its focused regression lane passed 39 tests. A separate isolated migrated-PostgreSQL scoped-kill persistence test passed 1 in 2.88 seconds at migration head `0027`, after which the disposable database was dropped. The later pre-Wave-36 result is recorded above.
- The loopback-only Mailpit canary used an explicit seeded `example.com` recipient and the real delivery path. It rendered a canonical approved template, delivered exactly once despite a retry, deduplicated open/click observations, reused one assignment, issued separate purpose-bound training bearers, rejected an incorrect/missing knowledge check, completed the correct quiz idempotently, and correlated one-count funnel/audit evidence before canary-only cleanup. No external mail, network, Azure, Graph, or provider call occurred.
- Wave 22's outbox repair preserved native UUID binding for completion, added bounded phase/SQLSTATE-class diagnostics without statement or parameter content, and reconciled 29 stale local queue intents at that snapshot. Final local acceptance later exposed and fixed an audit-store owner-fallback revocation defect, reconciled 36 stranded idempotent queue intents, and ended with a green audit chain. This is local-live reconciliation evidence, not backup/restore or external-witness qualification.

### Latest completed native ARM64 image snapshot

These IDs passed at the recorded snapshot. Wave 29/30 source edits make them stale. The dated controller capacity block is superseded by the external-worker architecture, but an exact-final-tree rebuild/rescan is still pending.

| Image | Local image ID | Docker size (bytes) | Scan |
|---|---|---:|---|
| operator API | `sha256:dea69ee89cd61252e71aa3839344b049959db1693ac11451d31e51d5a16476c3` | 54,676,396 | 0 HIGH / 0 CRITICAL / 0 secrets |
| tracking API | `sha256:c17453f2ac7b76b8d056ca89cbcc553a7e95091a0fc9b23ab705b7629ddb3be0` | 51,473,076 | 0 HIGH / 0 CRITICAL / 0 secrets |
| worker | `sha256:0ff23be9a060134def7f137961ef552c120dedca59b7b3c7f0425548803a5641` | 46,674,346 | 0 HIGH / 0 CRITICAL / 0 secrets |
| migration | `sha256:ee1b95e5d386337864a307d3b697ded4e9706f93dbd734075eb300886324396e` | 43,585,560 | 0 HIGH / 0 CRITICAL / 0 secrets |
| mock services | `sha256:a11f1cae779d014cd9bd80cecb8522e5c6717c36b6f5f62acdb3ec89fba27dfb` | 32,741,533 | 0 HIGH / 0 CRITICAL / 0 secrets |

## Findings

### Baseline P0 findings and current disposition

1. **Fresh migration failure — remediated and externally qualified at head `0032`.** The current-head external PostgreSQL profile passed 92 tests on 2026-08-29, including the fresh-install/historical migration gate to `0032_source_explicit_curation`, the retention concurrency and outcome-writer-versus-retention lanes, and grants coverage. The PostgreSQL profile isolates queue effects on Redis DB14 and flushes only DB14 before/after. Exact-final ARM64, AMD64, registry, and live deployment proof remain pending.
2. **Missing operator runtime dependency — remediated locally.** Package closure and release-image import/startup verification pass.
3. **Entra verifier incompatibility — remediated locally; live proof pending.** Metadata discovery, audience, `oid`, roles, nonce/state/PKCE, and fail-closed role mapping are covered locally; three-account tenant evidence is absent.
4. **Missing mandatory authorization keys — remediated locally; live proof pending.** Independent RoE, domain, audit, tracking, and receipt keys are provisioned/scoped in configuration and Terraform.
5. **Collapsed Azure identities/database authority — remediated statically; live proof pending.** Workloads now have separate identities, secret references, and role DSNs; a deployed negative-permission test remains required.
6. **Mutable/non-authoritative audit — partially remediated.** Security-definer append, isolated roles, transactional outbox, reconciliation, audit health gates, and a create-only locked-Blob witness are implemented locally. Live storage/RBAC proof plus alert/recovery exercises remain release blockers.
7. **Incomplete RoE signature — remediated locally.** Versioned canonical signatures bind the complete authorization, and legacy artifacts fail closed.
8. **Duplicate external delivery — remediated locally.** Atomic claims, leases, provider correlation, indeterminate-state handling, and crash/concurrency tests exist; real provider idempotency behavior still requires canaries.
9. **Disconnected training — remediated locally.** Token-bound lessons, quiz/pass, due/reminder/escalation, immutable progress, and completion wiring exist; mobile/WCAG browser qualification remains.
10. **Unsafe all-recipient targeting — remediated locally.** Explicit group/filter/include/exclude/sample definitions produce a masked preview and frozen manifest; legacy campaigns cannot silently expand.
11. **Demo-grade ACS delivery — remediated locally; live proof pending.** Custom-domain readiness, sender constraints, pacing, authenticated Event Grid delivery state, suppression, and staged activation are wired. Real DNS/quota/inbox/bounce behavior is unqualified.
12. **Fake Microsoft 365 integration — remediated locally; live proof pending.** Managed Graph directory reconciliation and durable Outlook report ingestion/correlation are implemented. Real consent, paging, replay, and mailbox canaries remain.

### Current unresolved release blockers

- No disposable-Azure `foundation_bootstrap`, `foundation_finalize`, or
  `workloads` stage, live Entra role-separation exercise, or negative
  workload-permission proof has passed. The exact three-stage path is
  static/local contract evidence only.
- The historical 2026-08-28 Azure audit found no Terraform backend, foundation resource group, platform Entra application, or application workload. Current management-plane state is unverified because the 2026-08-29 sandbox could not resolve `management.azure.com`. The live GitHub re-audit proves valid `ELDSRQ` authentication with `repo`/`workflow` scopes; a public, enabled repository with default `main`; Actions enabled; the Azure workflow active; and no billing-disabled run signal. It also proves zero environments, variables, secrets, rulesets, and workflow runs, unprotected `main`, disabled secret scanning and push protection, and remote `main` at old-tree SHA `1403d944a40214714b6cbfcf5cbabc4fa7225eb9` at re-audit time; the checkpoint push has since advanced remote `main` to `c9ea716`. No workflow dispatch/run or Azure plan/apply occurred.
- No real ACS custom-domain/quota/Event Grid or Microsoft Graph/Outlook end-to-end canary has passed.
- The loopback-only Mailpit delivery/training canary passed and cleaned up its canary-only state. SMTP acceptance into Mailpit does not prove real DNS, provider transport, inbox placement, human reading, or external reporting behavior.
- GUI deployment, upgrade, rollback, DNS/certificate completion, and recovery are incomplete.
- No complete browser-driven GUI, mobile, keyboard, or WCAG qualification exists.
- Canary designation is explicit, locked against frozen/nonterminal campaigns, and GUI-wired; browser qualification remains absent.
- The audit witness is implemented and locally permission-tested but has no live Azure storage/RBAC or recovery/alert exercise.
- Azure Monitor collection/alerts and request-to-worker distributed tracing are not qualified.
- The finite Program Planner and Executive Trends are implemented locally. Their current 12-campaign/366-day bounds do not satisfy the required five-year ledger/graph, named disposition, confirmed-interaction distinction, or basic repeat history. Adaptive/new-hire/remedial automation, advanced cohorts, causal efficacy claims, scheduled reports, a general corrections workflow, and broad content-library depth are explicitly deferred and are not release blockers.
- An exact-final-tree ARM64 rerun, AMD64/multi-architecture build, registry publication/attestation, rollback evidence, full backup/restore, recovery and encryption-rotation canaries, and externally witnessed evidence remain absent. The build is not claimed to match KnowBe4 or to be production-ready.

### Recent local closures requiring live/browser qualification

- The console now derives roles/capabilities from server session responses and fails closed for invalid or stale authority before showing navigation or enabling actions; browser qualification remains absent.
- Test ownership is now explicit: hermetic, PostgreSQL, Redis, local E2E, and Azure-live commands have disjoint opt-in boundaries and reject every skip. Operational readiness runs the applicable local profiles only after bounded environmental preflight and does not echo connection URLs.
- Source management now provides authorized, audited, repeatable terms acknowledgement/inspection/revocation plus enable/disable/manual-ingest operations in the API and GUI. Enable/ingest and worker execution require current complete terms. Disable or revocation cannot abort provider I/O already executing, but the worker re-reads and locks source/terms state after fetch; when either fence changes, fetched material is discarded without `SourceItem` or pattern writes. The returned `job_id` remains a request reference rather than a status resource.
- Directory preview uses a durable latest-request token around provider I/O. An older success or failure becomes `superseded` and cannot overwrite, clear, or retry over a newer preview/configuration.
- Generated and approved lure content retains a mandatory placeholder until delivery resolves it to that recipient's opaque tracking click bearer. The click creates or reuses the exact training assignment and redirects with a separate purpose-bound open bearer; reminders derive the same assignment-bound open credential, and legacy static awareness URLs fail delivery closed.
- The public tracking boundary now rejects ambiguous/oversized bodies and oversized request targets before route work, attaches hardening/privacy headers to early errors and redirects, and translates internal/database failures without reflecting their details. Managed Azure supplies exact bounded `TRACKING_API_TRUSTED_PROXIES` CIDRs from the Container Apps infrastructure subnet plus loopback; forwarding is accepted only from a trusted direct peer, canonical `X-Forwarded-For` hops are walked right-to-left, and Uvicorn proxy rewriting is disabled.
- Duplicate `Content-Length` is rejected even when repeated values agree, closing the request-smuggling ambiguity rather than relying on ASGI header normalization.
- Operator, tracking, and worker settings suppress input values and low-level exception chains. Managed worker roles validate only their required provider configuration, reject local/credential-bearing or parameterized provider URLs and legacy pasted credentials, and preserve disposable local defaults only in development mode.
- The reviewed Azure workflow/Terraform/API/GUI path now requires `foundation_bootstrap`, live-verified/post-apply-proven `foundation_finalize`, then `workloads`. Operator-entered ACS statuses are rejected; GUI export/API/Terraform/preflight share the exact ACS endpoint contract; and only validated run-bound artifact evidence can advance. `workloads` requires exactly one active Healthy/Provisioned worker revision, every enabled role ready in two consecutive simultaneous observations, and a same-revision final check. Every live/provider gate remains open; no live run is claimed.
- Queue-dispatch failures persist the fixed code `queue_dispatch_failed` in durable outbox state, not raw exception text; retry state and bounded type/reference logging remain intact.
- Operator configuration, template preview, audience, authentication/authorization, evidence-window, and trend failures now expose stable allowlisted public messages rather than reflecting arbitrary backend exception text.
- The retired corrections credential has been removed from runtime settings, local examples, and Terraform/Key Vault provisioning. The compatibility route itself remains an unconditional HTTP 410/no-write boundary.
- The local readiness gate now fails before expensive tests on insufficient disk, an unresponsive Docker engine, invalid Compose configuration, or unhealthy required services; installation verification follows the actual local supervisor child topology and checks `/readyz` rather than legacy `/healthz`.
- Operator authorization is explicitly inventoried across all 113 routes: 103 capability-protected plus 10 dedicated/public. The browser capability set must exactly match the backend; non-Azure navigation/actions avoid unauthorized calls and stale controls, Help uses `view_aggregate:results`, and safe template preview accepts either author or reviewer authority without granting clone/decision privileges across lanes.
- SQLite lifecycle/outbox warnings are remediated: application-owned tracking pools and test engines close deterministically, and outbox timestamp binds use explicit SQLAlchemy datetime typing instead of deprecated implicit SQLite adapters.
- Generation now has one strict contract from queued context through bounded provider JSON, stored review fields, and recipient delivery. Field/list/aggregate limits and output/storage limits are canonical, and a durable queue idempotency key plus row locking/race recovery prevents duplicate provider calls and drafts.
- Managed deployments require an approved non-local HTTPS AI gateway with `/propose` and `/setup-assist`. Pattern approval durably records a generation request without reporting asynchronous queue/provider completion. Live AI generation remains open.
- OIDC discovery/token/JWKS, setup assistance, AI generation, and GitHub metadata/status/activity responses are streamed and capped before UTF-8/JSON/schema validation. Duplicate/malformed lengths and oversized decoded content fail closed; GitHub dispatch status is classified without reading hostile response bodies.
- Campaign/source/privacy/correction/approval/exclusion/rationale validation is enforced and normalized on the API. Operator/tracking validation responses cap structural locations/counts and omit rejected values/provider detail.
- Checked-in migration `0030_default_privacy_notice` reconciles historical duplicate-current rows, persists a safe default only when absent, and enforces one current notice. The privacy console loads request operations independently so a notice failure warns without disabling them; external `0030` qualification remains open.
- The governed training-resource library, response-derived row actions, paginated recipient management/named outcomes, aggregate/named/export reporting separation, alert subscription lifecycle/hostname allowlist, and append-only recipient-exclusion GUI are locally wired and regression-covered.
- Wave 29 makes local deployment preservation-first. Compose project
  `phishing-awareness-platform` and volumes
  `phishing-awareness-platform_postgres_data`/
  `phishing-awareness-platform_redis_data` are frozen recovery identities.
  Missing/incomplete `.env` plus existing or uninspectable preserved state
  refuses credential generation. Preflight parses dotenv as inert data and
  supplies only command-required keys; `prestart` precedes any Compose start and
  `ready` follows migration/audit bootstrap/seed.
- ANA-010 increment 1: the five-year pseudonymous awareness ledger gained its
  first graph consumer — `ledger_trend` in reporting (bounded monthly
  click/no-click series with explicit delivered denominators and a distinct
  no-click bucket over the 1,826-day PII-free retention), `GET
  /analytics/ledger/trend` JSON + CSV behind `view_aggregate`/`export_bulk`, and
  a GUI panel in Executive trends. Route-authorization inventory and UI-contract
  tests updated; live/browser qualification remains open.
- ANA-010 increment 2: the named per-recipient campaign surface now projects
  explicit close disposition. `confirmed_interaction` (deliberate training-page
  action, never relabeling observed open/click) and `close_disposition`
  (`activity_at_close`/`no_activity_at_close` for terminal campaigns, `null`
  while open) are exposed on `/campaigns/{id}/recipients`, rendered as
  capability-gated GUI columns, and pinned by route/pagination/UI-contract
  tests.
- ANA-010 increment 3: basic repeat history landed. `ledger_repeat_distribution`
  reads only the PII-free ledger and buckets distinct tenant-keyed pseudonyms by
  exposures (and by exposures with retained human activity) into bounded
  `1..5+` buckets with explicit denominators; `GET /analytics/ledger/repeats`
  JSON + CSV sit behind `view_aggregate`/`export_bulk`, and Executive trends
  gained a bounded Repeat exposure history panel (window capped at 1,826 days,
  capability-gated CSV). No recipient identifiers or pseudonyms are ever
  returned.
- ANA-010 increment 4: named per-recipient pseudonymous drill-down landed.
  `ledger_recipient_history` resolves one recipient id to its tenant-keyed
  pseudonym (server-side, never returned) and reads only the PII-free ledger,
  bounded to 500 chronological entries with explicit exposure/delivered/
  engaged/no-activity/repeat summaries; `GET
  /analytics/ledger/recipients/{id}/history` JSON + CSV sit behind
  `view_named`/`export_bulk`, 404 on unknown recipients, and the operator API
  now shares the governed ledger pseudonym key with the retention worker (same
  synthetic local default in development; managed mode never falls back).
  Route-authorization inventory (115 routes) and tests updated. ANA-010 is
  complete locally; GUI drill-down wiring and key rotation/recovery remain
  governed follow-up.
- AI-010 bake-off foundation landed (`scripts/ai-bakeoff/`): a fixed,
  sanitized, versioned evaluation set (fictional actors/sectors, no PII, no
  real domains, SHA-256 digest recorded per report) scored deterministically
  against the exact `GenerationResponse` contract in the acceptance order
  (schema validity, evidence fidelity, safe refusal, injection resistance,
  then latency/usage), with a bounded runner for a loopback-bound llama.cpp
  chat endpoint (2 MiB response cap, no downloads, no tools, no outbound
  network beyond the supplied endpoint, report JSON is the selection
  evidence). Scorer/set validation are hermetic-tested offline; no model has
  been downloaded or selected.
- TRN-010 campaign-specific micro-training landed: `training_resources` gain
  an optional all-or-nothing knowledge check (question + 2–5 bounded distinct
  options + correct-answer index; migration `0033` with CHECK constraints), the
  digest pins the check when present while legacy lessons keep the content-only
  digest so existing bindings stay valid, the deterministic builder
  (`kp_database.training_builder`) composes a bounded evidence-bound question
  whose correct answer is always independent verification, `POST
  /campaigns/{id}/training-draft` returns a read-only lesson + check draft from
  the campaign's approved template/pattern (capability-gated, fails closed
  without an approved template), the tracking page renders the bound question
  and options with the generic quiz as fallback and validates the submitted
  option server-side (the answer index is never rendered), and the GUI gains
  authoring/preview/review surfaces. Current-head hermetic 2,675 / PostgreSQL 92
  / fresh-migration 1 / Redis 2 pass; live/browser gates remain open.
- AI-010 generation-worker pinning landed: the generation role now requires
  `KP_WORKER_AI_MODEL_ID` in managed mode (optional in development), refuses
  any response whose self-reported `model_id` does not match the pin with a
  constant-time compare (fail closed before the proposal can be persisted or
  reviewed), and exposes cost/status metrics (`kp_worker_ai_response_bytes_total`
  with ai/generate labels, `kp_worker_ai_model_pinned` gauge, and
  `kp_worker_ai_model_mismatch_total`). Model benchmark/selection against the
  bake-off set and the actual pinned llama.cpp image/endpoint deployment remain
  external to this increment. Current-head hermetic 2,681 / PostgreSQL 92 /
  Redis 2 pass; live/browser gates remain open.
- Wave 38 checkpoint `d25313d` closed the retention P1 (ORM `RetentionPolicy`
  now mirrors migration `0032`'s 1–365-day check and partial unique
  single-default index with metadata and direct-database tests), repaired the
  migration gate that no fresh database could reach head (revision id renamed
  `0032_source_item_explicit_curation` → `0032_source_explicit_curation` to fit
  Alembic's `VARCHAR(32)` version column; constraint name aligned to the
  codebase's short-name convention; upgrade/downgrade round-trip proven on live
  PostgreSQL), and fixed three preserved-worktree test defects the full gates
  exposed. Committed and pushed; current-head hermetic 2,620 / PostgreSQL 92 /
  Redis 2 pass; E2E, image, browser, and cloud gates remain open.
- Stateful base-image qualification accepts an exact reviewed local
  digest/platform cache with `--pull=never`, otherwise resolves the exact remote
  index/platform digest. Hardened probes attach no project volume; Redis runs as
  `999:999` and must write disposable `/data`. Deployment/recovery evidence
  forbids automatic cleanup and an interrupted or uncertain operation is
  reconciled from the same checkpoint/request rather than blindly retried.

### Baseline P1 findings and current disposition

- **Redis queue transition windows — remediated locally.** Lua-atomic lifecycle, recovery, idempotent publication, bounded DLQ inspection/replay, and live Redis contracts pass.
- **Replayable tracking credential storage — remediated locally.** URL bearers are random and only purpose-scoped keyed verifiers are stored; legacy credentials are revoked.
- **HTML exfiltration bypasses — remediated locally.** Parsed allowlist validation covers literal, protocol-relative, IP, CSS, form, and remote-resource cases.
- **Buffered/unreliable SSRF enforcement — remediated locally.** Fetching streams bounded bodies and uses global-address classification, DNS pinning/revalidation, and IPv4/IPv6 edge-case tests.
- **Missing CSRF enforcement — remediated locally.** Cookie mutations enforce trusted Origin/Fetch-Metadata policy and have adversarial coverage.
- **Per-process abuse controls — remediated locally.** Managed replicas use shared Redis limits and login throttling; failures deny work.
- **False-positive health — remediated locally/static; live managed proof pending.** `/livez` is process-only and `/readyz` checks required database, Redis, provider, and audit state. The local readiness/installation harness consumes `/readyz`; managed `workloads` additionally requires exactly one active Healthy/Provisioned worker revision, two simultaneous ready observations for every enabled role, and a same-revision recheck. Azure execution remains unwitnessed.
- **Nondeterministic test ownership — remediated locally.** Hermetic, PostgreSQL, Redis, E2E, and Azure-live profiles are explicit and skip-rejecting; operational readiness invokes them in dependency order after bounded preflight. PostgreSQL jobs use Redis DB14 with DB14-only before/after cleanup; the Redis queue contract uses DB15; application DB0 is never a test cleanup target. Final local hermetic passed; PostgreSQL/Redis/E2E external reruns and Azure-live remain pending.
- **Production localhost/configuration fallbacks — remediated locally.** Managed worker roles reject missing role dependencies, local or structurally unsafe provider URLs, pasted legacy credentials, and missing dedicated identities/keys without requiring unrelated provider settings.
- **Non-durable kill switch — remediated locally.** Persistent emergency-stop policy blocks scheduling and delivery across replicas/restarts and uses reviewed release.
- **Incomplete directory deprovisioning — remediated locally.** Delta reconciliation applies selected-group/guest/service/disabled policy and deactivates missing users.
- **Implicit RoE/stale assignments — remediated locally.** Explicit signed authorization and preparation invalidation prevent silent scope expansion; retryable assignment states are handled.
- **Misleading managed runtime controls — remediated locally.** Unsupported local PID controls are hidden/refused and the default worker topology is consolidated.
- **Missing database invariants — partially remediated.** Migration 0024 adds seven preflighted composite relationship/check groups without rewriting history; ambiguous retention/lifecycle links remain intentionally unconstrained.
- **Malformed UUIDs becoming 500s — remediated locally.** External route/body/query UUIDs are typed and return deterministic 4xx responses; 18 boundary families have regression tests.
- **Unsafe legacy tracking correction ingestion — retired locally.** `/v1/corrections` is a stable HTTP 410 no-write endpoint regardless of bearer or body, and the obsolete shared secret is no longer accepted or provisioned by application/Terraform configuration. A normalized, dual-reviewed correction workflow and adjusted analytics are deferred; current reports explicitly do not subtract scanner/bot corrections.
- **Durable exception-text persistence — remediated locally.** Queue outbox failures store a fixed operational code rather than provider/driver exception text, preserving retries without turning durable state into a secret-bearing error sink.
- **Public exception reflection — remediated at reviewed boundaries.** Operator key/configuration, template, audience, authentication/authorization, evidence-window, and trend paths translate backend failures to stable allowlisted messages. Continue applying this rule to new boundaries.
- **Secret-bearing settings diagnostics — remediated locally.** Operator, tracking, and worker settings hide input values and suppress nested parser/provider exception chains; public deployment/tracking failures expose only stable messages.
- **Public tracking request ambiguity — remediated locally.** Duplicate/malformed content lengths, streamed or declared oversized bodies, oversized request targets, untrusted forwarding headers, and early-error security headers have explicit fail-closed contracts.
- **Static or cross-purpose training links — remediated locally.** AI drafts retain a placeholder, delivery binds the lure link to the recipient's tracking bearer, clicks issue an assignment-bound open bearer, completion has a distinct purpose, and reminders verify the stored assignment-bound credentials. Static legacy training destinations fail delivery closed.
- **Concurrent directory preview overwrite — remediated locally.** A durable latest-request fence makes stale success and failure results harmless without holding a database lock during Graph I/O.
- **One-phase Azure deployment dead end — partially remediated locally.** GUI/workflow/Terraform now separate foundation discovery from verified workload deployment. Protected connector bootstrap, real DNS/provider verification, rollback/recovery, edge completion, and both live phases remain open.
- **Application-owned connection pools leaked across shutdown — remediated locally.** Operator/tracking lifespans dispose owned SQLAlchemy pools and close owned Redis/HTTP clients; repeated-lifespan tests return connections to zero.
- **Direct public ingress/edge controls — unresolved.** The application-level operator HSTS contract is locally tested, but WAF/front-door policy, verified custom domains/certificates, HSTS observation through the intended edge, and live abuse/tamper diagnostics remain.
- **Missing release evidence — partially remediated locally/CI.** Pinned scans, SBOM/provenance attestations, immutable actions/images, exact digest deployment, and image verification are implemented. The latest all-five native ARM64 snapshot passed hardened verification and 0 HIGH / 0 CRITICAL / 0 secret scans, but Wave 29 source edits make those interim images stale. At about 5.6 GiB free, the 10 GiB release-image gate blocks before temporary-directory creation or Docker. AMD64 cross-build, live registry attestation verification, and cloud deployment remain open.
- **Destructive or identity-drifting recovery — remediated with live restore proof.** Fixed identities and fail-closed checkpoint/staging controls culminated in validated snapshot `20260829T013332Z-tsX1WQ`, clean external restore, historical migration head `0029`, durable seed, and ready preflight. The checked-in chain is now `0030` and has not been externally restored/qualified. The internal seven project containers are stopped/preserved; image/browser/cloud qualification remains open.

### P2 — maintainability and commercial capability gaps

- Core behavior is concentrated in `routers.py`, `console.py`, `app.js`, and `jobs.py`; split by feature inside the existing deployables after behavior is stabilized. Wave 13 removed four verified-dead helpers (35 lines) while preserving behavior, but this does not close the broader modularization debt.
- The old eight-worker Azure topology is resolved by the supervised multi-role worker default; local development still starts separate role processes for observability.
- Application Insights/OTel infrastructure, API health/log correlation, and bounded worker metric snapshots exist. The operator/tracking write-only registries were removed; authenticated cross-process metrics/traces, Azure collection, alerts, and live dashboards remain unqualified.
- Documentation truth has been reconciled around one canonical status plan; future waves must keep evidence labels and counts current.
- Reporting now includes a denominator-explicit single-campaign funnel and bounded longitudinal Executive Trends JSON/CSV/GUI. The required named disposition, five-year pseudonymous ledger, click/no-click graph, confirmed-interaction distinction, and basic repeat history remain priority work. Cohort comparison, causal training-efficacy claims, scheduled reports, and a general correction workflow are deferred.
- QR, reply tracking, credential-entry simulation, localization, adaptive/open-ended recurrence, and difficulty automation are deferred. Safe tracked document preview is the only attachment-related candidate after the core outcome loop is complete; executable, macro-bearing, or credential-collecting simulation is rejected.
- Training has an approved lesson/quiz/pass/due/reminder/escalation loop plus a governed bounded text-resource lifecycle. A short campaign-specific lesson/question derived from approved evidence remains priority work. Broad library depth, LMS behavior, gamification, localization, and richer assignment automation are deferred.
- Recipient encryption is direct application-layer AES-GCM, not envelope encryption. New ciphertext uses a versioned, key-ID-bound format; runtime configuration accepts one active key plus at most four prior decrypt-only keys and can read bounded legacy-unversioned values. Managed prior keys are metadata-bound legacy/recovery inputs only. The first foundation fixes the active ID, active rotation is deliberately blocked, and `prevent_destroy` protects the Terraform-generated active key while complicating teardown. The active KEK remains in protected Terraform state/history. Pre-stage/prove/promote, a database decrypt canary, bulk re-encryption, safe prior-key retirement, and row/column AAD remain debt.

### Strengths to preserve

- Public tracking and operator control-plane separation.
- Package boundaries generally avoid cross-application imports.
- Deterministic safety validation is repeated after recipient-specific rendering.
- Delivery rechecks campaign state, approved manifest, current independent approval, RoE, allowlist, and recipient-domain coverage. The current separate security/privacy approval implementation remains fail-closed until `ORG-001` replaces it with the two-person combined checklist.
- Independent review of security/privacy criteria and OIDC state/nonce/PKCE handling; `ORG-001` preserves independence while combining the criteria for a two-person team.
- PII authenticated encryption, mailbox equality digest, and storage-enforced open/click deduplication.
- Tracking minimizes IP/user-agent data, uses no cookies, and sets no-referrer.
- DNS-pinned/revalidated outbound fetching is a sound base once URL parsing, classification, and streaming are fixed.
- Provider interfaces provide useful seams for ACS/SMTP, directory, AI, alerts, and report ingestion.

## RSA Conference operating decision

Do not target conference attendees, exhibitors, or unrelated external domains. Conference participation is not authorization. Any future pilot must be limited to a written, RSA-controlled RoE and RSA-controlled domains/populations.

Before an internal RSA staff pilot, the GUI must prove: Entra role separation; exact frozen target cohort; current directory reconciliation; verified sending domain and quota; delivery-event feedback; Outlook report ingestion; working lesson/assessment; persistent kill switch; canary inbox placement; audit integrity; alerts; and tested recovery. Any failed check blocks launch.

## Conflict-aware task matrix

`Owner` names the component owner, not a person. A conflict group may have only one active implementation task per wave. Acceptance evidence must be committed with the task; a passing unit test alone does not qualify Azure or a mail provider.

| ID | Outcome | Owner / inputs | Acceptance | Depends on | Conflict group | Priority | Status |
|---|---|---|---|---|---|---:|---|
| ORG-001 | Two-person-safe approval | Authorization/domain/API/GUI/delivery | Creator cannot self-approve; one other authorized operator completes combined safety/privacy checklist; RoE, audience, canary, stop, provider evidence, and immutable review remain mandatory | — | AUTH/CAMPAIGN | P0 | **Complete locally:** creator plus one independent dual-capability approver; existing safety gates retained |
| OUT-001 | Honest canonical outcomes | Domain/database/reporting/tracking | Scanner-triggerable observed events are separate from confirmed human interaction; no-activity-at-close is explicit; deletion is neither claimed nor inferred | — | DOMAIN/ANALYTICS | P0 | **Implemented locally:** confirmed interaction and terminal close/no-activity projection wired; reporting consumers remain under ANA-010 |
| RET-005 | Five-year minimized awareness ledger | Retention/privacy/database/reporting | Raw evidence remains bounded to 365 days; pseudonymous 1,826-day projection supports per-user authorized history and trend graph; notice/legal/RBAC/export/recovery rules are tested | OUT-001 | DB/PRIVACY/ANALYTICS | P0 | **Complete locally:** locked terminal-only projection/purge, key/grants/policy bounds at head `0032`; ORM metadata mirrors the migrated invariants; five-year click/no-click graph, repeat-exposure distribution, and named per-user pseudonymous history (capability-gated, shared governed key) landed. Key rotation/recovery and GUI drill-down wiring remain governed follow-up |
| MAIL-005 | Honest mail support matrix | Docs/setup/provider GUI | ACS is recommended managed send; SMTP is advanced send; Graph is directory/report ingestion; unsupported Graph send/deletion/“any provider” claims absent | — | MAILER/DOCS | P0 | Decision proposed; existing implementation already supports ACS/SMTP and Graph directory/report paths |
| AI-005 | Select the internal-model architecture | Worker/generation/deployment/docs | Fixed bake-off selects a digest-pinned, licensed model/runtime by schema validity, evidence fidelity, safety, injection resistance, latency/memory, and cost; deterministic non-AI setup remains complete | — | AI/ARCHITECTURE | P0 | Bake-off harness landed (`scripts/ai-bakeoff/`): fixed sanitized versioned evaluation set (digest-recorded), deterministic scorer against the exact generation contract, bounded runner for a loopback llama.cpp endpoint (no downloads, no tools, no outbound network), README selection contract. Actual candidate model benchmarks and selection remain |
| THR-001A | Repair threat-to-draft fidelity | Source adapters/ingestion/pattern/generation | Excerpt, `as_of`, actor, sector, TTP, source/citation, confidence, and freshness survive ingestion and enter only bounded reviewed generation evidence | AI-005 | SOURCE/GENERATION | P0 | **Complete locally:** bounded reviewed fidelity and untrusted-data treatment persist through generation |
| IMP-001 | Guided CSV people import | Recipient API/GUI/database | Header mapping, bounded file/row errors, masked preview, merge/deactivate choices, duplicate handling, and final count are GUI-driven and audited | CAM-001 | PEOPLE/UI/DB | P0 | **Complete locally:** arbitrary header mode, mapping/preview/digest/apply, merge/deactivate, audit, and serialized writes |
| INT-001 | Confirmed human interaction | Tracking/training/database/reporting | Observed open/click remain immutable; a deliberate training-page or question action records a separate confirmed event; reports never relabel one as the other | OUT-001 | TRACKING/DB/ANALYTICS | P0 | **Complete locally at event/ledger boundary:** deliberate quiz action is distinct and locked; ANA-010 consumers remain |
| DOCSIM-001 | Truthful safe document simulation | Template/generation/tracking/docs | ICS no longer claims a nonexistent tracked URL; later document simulation uses a safe tracked preview/link only and never macros, executables, or credential collection | OUT-001 | CONTENT/TRACKING | P0 | **Complete locally:** recipient-bound safe tracked ICS behavior; broader document variants remain deferred |
| THR-001B | One Threat Campaigns workbench | Source API/GUI/worker | Bounded daily ingest/status plus review queue showing citation/date/freshness/actor/TTP/sector/confidence; operator explicitly selects every simulation basis | THR-001A | SOURCE/UI/WORKER | P1 | **Complete locally:** bounded GUI/API, daily governed ingest, default quarantine, explicit activation, provenance/terms rechecks, and legacy re-review migration |
| AI-010 | Internal inference execution | Existing worker image, durable generation requests, setup UI | Pinned model runs without tools/network, emits schema-constrained proposals, scales to zero where hosted, exposes cost/status, and never approves/launches; `.140` is dev/qualification only | AI-005, THR-001A | AI/WORKER/DEPLOYMENT | P1 | Bake-off foundation landed (`scripts/ai-bakeoff/`); the generation worker now enforces a pinned model identity (`KP_WORKER_AI_MODEL_ID`, constant-time compare against the self-reported `model_id`, fail-closed on mismatch — required in managed mode, optional in development), and exposes cost/status metrics (`kp_worker_ai_response_bytes_total`, `kp_worker_ai_model_pinned`, `kp_worker_ai_model_mismatch_total`). Actual model benchmark/selection, the pinned `llama.cpp` image/endpoint deployment, and live qualification remain |
| TRN-010 | Campaign-specific micro-training | Training/content/generation/API/GUI | Approved evidence yields one concise lesson and question bound to the campaign and human-reviewed; generic fallback remains | THR-001B, AI-010, TRN-001 | TRAINING/CONTENT | P1 | **Complete locally:** optional all-or-nothing campaign-bound knowledge check on `training_resources` (question + bounded options + correct-answer index, migration `0033`), deterministic evidence builder (`kp_database.training_builder`), operator `POST /campaigns/{id}/training-draft` (read-only, capability-gated, requires an approved template), digest pins the check when present (legacy lessons keep the content-only digest), tracking page renders the bound question/options with generic quiz fallback and validates the answer server-side (never renders the answer index), GUI authoring/preview/review surfaces. Live/browser qualification remains |
| ANA-010 | Five-year disposition and trend UX | Reporting/database/GUI/export | Named capability-protected per-recipient campaign status, explicit close disposition, five-year click/no-click graph, report/training rates, basic repeat history, CSV/PDF-equivalent export | RET-005, INT-001 | ANALYTICS/DB/UI | P1 | **Complete locally:** five-year pseudonymous ledger click/no-click graph (`ledger_trend` + `/analytics/ledger/trend` JSON/CSV + GUI); named per-recipient disposition (`confirmed_interaction` + explicit `close_disposition` on `/campaigns/{id}/recipients`); basic repeat history (`ledger_repeat_distribution` + `/analytics/ledger/repeats` JSON/CSV + GUI panel, bounded 1..5+ buckets, explicit denominators); and named per-recipient pseudonymous drill-down (`ledger_recipient_history` + `/analytics/ledger/recipients/{id}/history` JSON/CSV behind `view_named`/`export_bulk`, operator API shares the governed ledger pseudonym key with the retention worker; the pseudonym is never returned). Live/browser qualification remains open |
| DEP-010 | Two-person GUI deployment path | Deployment API/GUI/Azure discovery/recovery | Browser login discovers tenant/subscription/regions/DNS/groups; strong defaults reduce normal inputs; Advanced hides resource IDs/GitHub/Terraform; progress/retry/rollback/recovery and cost are visible | AI-005, MAIL-005, GOV-002 | DEPLOY-UX/AZURE | P1 | Existing staged workflow is secure but too infrastructure-heavy and not live qualified |
| UX-010 | Five-area operator navigation | Operator UI/API navigation contracts | Home/Threats, Campaigns, People/Training, Reports, and Settings/Deployment expose the complete core loop without removing capability gates or deep links | Stable Alignment Waves A–D | UI | P2 | Deferred until core behavior is stable; current 17-item navigation is operationally dense |
| REL-001 | Reproducible install and operator image | Database migrations, `azure_migrate.py`, operator package manifest, container tests | Empty DB base→head and historical upgrade→head pass; grants reference real tables; operator image imports/starts from package-scoped install | — | DB-FOUNDATION | P0 | Exact checked-in code head `0032_source_explicit_curation`; current-head external PostgreSQL profile passed 92 tests on 2026-08-29 (fresh-install/historical migration and grants lanes included). Exact-final ARM64, AMD64, registry, and live deployment remain pending |
| IAM-001 | Entra login/RBAC works | Auth module, OIDC console, Entra bootstrap, auth fixtures | Discovery `jwks_uri`; `oid`; top-level `roles`; correct API scope/audience; three-account Azure E2E; unknown roles fail closed | — | AUTH | P0 | Immutable typed roles, malformed/wildcard/unknown fail-closed handling, canonical principals, and non-identifying denials pass consumer-inclusive local gates; Azure E2E pending |
| IAM-002 | Workload and data least privilege | Terraform identities/vault policy, DB roles, app configs | Separate workload identities and per-secret access; no runtime admin DSN; tracking cannot read PII/audit secrets or mutate privileged/audit data | REL-001 | IAM-DB | P0 | Implemented locally; live RBAC proof pending |
| GOV-001 | Cryptographically complete RoE | Domain model, models/migration, API, delivery checks | Versioned canonical signature binds terms, party, normalized unique domains, window, signer/time; mutation/replay tests fail; legacy RoEs expire or re-sign | REL-001, IAM-002 | ROE | P0 | Bounded canonical v2 signatures, ≥256-bit key, ≤100 strict domains, aware ordered UTC windows, and consumer invariants pass 374-test shared gate; live proof pending |
| GOV-002 | Azure provisions every mandatory gate | Terraform/Key Vault/env/preflight | Independent RoE/domain keys; production mode rejects missing provider config; live challenge→verify→sign→schedule→delivery-gate passes | IAM-001, IAM-002, GOV-001 | AZURE-CONFIG | P0 | Exact `foundation_bootstrap` → `foundation_finalize` → `workloads` wiring and managed role-specific configuration boundaries implemented; live gates pending |
| AUD-001 | Tamper-resistant, authoritative audit | Audit schema/store, append function or isolated sink, external anchor, outbox | Runtime cannot UPDATE/DELETE/TRUNCATE/ALTER or access signing root; mutation/outbox/audit reconcile atomically; integrity failure blocks privileged operations and alerts | IAM-002 | IAM-DB | P0 | DB/outbox and create-only locked-Blob witness complete locally; final acceptance fixed the audit-store owner-fallback revocation defect, reconciled 36 stranded idempotent queue intents, and left the audit chain green. Live witness/alerts/recovery pending |
| DEL-001 | No concurrent duplicate send | Assignment schema, delivery job, provider result ledger | Atomic claim/lease; provider ID and accepted/delivered/bounced/blocked states; five-worker and crash-injection tests expose indeterminate sends without blind resend | REL-001 | DELIVERY | P0 | Implemented locally |
| CAM-001 | Exact scalable campaign audience | Group/audience models, campaign service/API/GUI | Static groups, directory groups, filters, individuals, exclusions, sample; masked frozen manifest; 10k preparation target; concurrent scheduling idempotent | REL-001 | CAMPAIGN-DB | P0 | Implemented locally; live DB/browser gate pending |
| TRN-001 | Complete training/remediation loop | Training schema, operator/tracking API+GUI, reminder worker | Token-bound approved lesson; quiz/pass; due date/reminder/escalation; idempotent completion; mobile/WCAG E2E | REL-001 | TRAINING | P0 | Purpose/assignment-bound lure, open, completion, and reminder links implemented; accessibility/browser gate pending |
| M365-001 | Safe Graph directory integration | Graph provider, sync job, setup GUI, Entra consent | Managed identity/client credential; selected groups; delta sync; guest/service/disabled policy; missing users deactivated; audited dry-run diff | IAM-001, CAM-001 | DIRECTORY | P0 | Durable provider/job/GUI plus latest-request-wins preview fence implemented; live Graph proof pending |
| MAIL-001 | Production ACS mail integration | Terraform, ACS provider/event receiver, delivery model/GUI | Verified custom domain and DNS status; quota/ramp estimate; pacing; display/persona constraints explicit; Event Grid delivery/bounce/block and suppression handling | GOV-002, DEL-001 | MAILER | P0 | Local/static implementation complete; live ACS/Event Grid proof pending |
| M365-002 | Outlook report-phish ingestion | Microsoft 365 provider, mailbox job, setup/readiness GUI | Built-in Report-to-mailbox path; MIME/original correlation; cursor/watermark/paging; dedup/replay; canary appears in campaign | IAM-001 | REPORT-INGEST | P0 | Durable provider/job/GUI implemented; live Outlook proof pending |
| QUE-001 | Honest at-least-once work queue | Contracts queue + Redis integration tests | Streams consumer groups or Lua-atomic transitions; crash/property tests show no silent loss; authorized DLQ inspect/replay in GUI | DEL-001 | QUEUE | P1 | Atomic lifecycle and authorized DLQ GUI implemented locally |
| WEB-001 | Tracking/content security boundaries | Token model, tracking API, HTML validator/sanitizer | Opaque URL token with stored keyed verifier; current tokens migrated/revoked; parsed HTML allowlist blocks remote/protocol-relative/IP/CSS/form exfiltration | REL-001 | TRACKING-CONTENT | P1 | Implemented locally |
| EGR-001 | Bounded, globally routable provider egress | Fetcher and provider adapters | Streamed byte caps; `ip.is_global` policy; IPv4-mapped/CGNAT/IPv6/rebinding tests; provider response caps | — | EGRESS | P1 | Implemented locally |
| PLT-001 | Truthful multi-replica runtime controls | Health endpoints, Redis rate limits, managed controls, probes | Separate liveness/readiness; DB/Redis/audit failure removes readiness; limits hold across replicas; unsupported Azure controls hidden/refused | GOV-002 | PLATFORM | P1 | Role-specific managed configuration, runtime controls, strict readiness, restart verification, Redis database-15 isolation, and all 8 live local E2Es pass; edge/cloud-live proof remains pending |
| OPS-001 | Persistent emergency stop | System-state model, scheduler/delivery, API/GUI | Engaged stop blocks all future schedule/delivery across restarts; authorized two-step release; reason/evidence audited; concurrency E2E | REL-001 | OPERATIONS | P0 | Implemented locally |
| DEP-001 | GUI executes reviewed deployment | Deployment orchestration API/GUI, Azure workflow, internal AI adapter | GUI Azure sign-in/discovery/plan/apply/progress/retry/rollback; redacted logs; DNS/cert/identity/provider checks; strong defaults with internals under Advanced; no normal shell/GitHub workflow; AI optional and human-reviewed | GOV-002, MAIL-001, M365-001, AI-005 | DEPLOY-UX | P1 | Existing three-stage plan/apply/status/retry has immutable drift/fresh-evidence, exact ACS export/preflight parity, current-revision/two-observation worker-role health telemetry, trusted-proxy/XFF wiring, and bounded artifacts at workflow SHA-256 `6868067ef5d58c799bc4a07dd832d4852d38dee73e6ff1af9a58c701ce85a4d3`. It remains too GitHub/Terraform/identifier-heavy for the target team; discovery/default simplification, internal inference, live stages, rollback, protected bootstrap, and edge remain |
| TOP-001 | Simple default Azure topology | Worker runtime/supervision, Terraform | Operator + tracking + one worker by default; optional delivery isolation; fair polling, shutdown/recovery/load tests; cost/scaling visible | QUE-001, PLT-001 | TOPOLOGY | P1 | Implemented locally; Azure scale proof pending |
| APP-001 | Distributed web security and edge | CSRF/origin controls, WAF/edge, domains, HSTS, diagnostics | Cookie mutations resist cross/same-site abuse; direct default hosts restricted; custom certs automated; tamper/abuse alerts proven | IAM-001, PLT-001 | AUTH-EDGE | P1 | CSRF/distributed limits plus bounded public tracking and stable non-reflective operator/auth/analytics/deployment boundaries implemented locally; Azure edge/custom-host observation and alerts pending |
| TST-001 | Deterministic release evidence | CI, test profiles, scanner, migration/browser/provider fixtures | Unit tests never require live CLI/services; integration profile permits zero skips; security/IaC/container scans, coverage, SBOM, provenance, image verification required | REL-001, IAM-001, TRN-001 | TEST-INFRA | P0 | Current-head external evidence (2026-08-29): hermetic 2,620/103, 0 failures; PostgreSQL 92 passed with Redis DB14 isolation; Redis 2 passed on DB15. Historical final local Wave 36 hermetic at `0030`: 2,501/97, 0 failures in 183.40s. E2E, exact-final ARM64, AMD64/registry, browser/WCAG, live Azure/provider, recovery, and witness remain unqualified |
| UX-001 | Safe campaign authoring/readiness | Campaign API/GUI | Draft/clone; preview desktop/mobile/plain; test cohort; staggering; immutable approval manifest; one blocking readiness page incl. kill switch and backup | CAM-001, TRN-001, MAIL-001, M365-002, OPS-001 | CAMPAIGN-UX | P1 | Core readiness/preview, explicit test-account and exclusion GUI, paginated recipients, response-driven training governance, reporting, and alerts are complete locally; a 113-route authority inventory (103 protected plus 10 dedicated/public) and exact GUI capability contracts gate actions. Browser/live pending |
| ANA-001 | Accurate awareness outcomes | Delivery/tracking/reporting queries and GUI/export | Canonical transport/report/observed/confirmed/training/no-activity-at-close states; named capability-protected disposition; pseudonymous 1,826-day ledger; click/no-click graph; basic repeat history; explicit denominators | MAIL-001, M365-002, TRN-001, OUT-001, RET-005 | ANALYTICS | P0 | Single-campaign funnel and bounded longitudinal Executive Trends JSON/CSV/GUI complete locally; current 365-day/12-campaign bounds do not meet the requirement. Named disposition, confirmed interaction, five-year ledger/graph, and basic repeats remain. Causal efficacy, scheduled reports, advanced cohorts, and general corrections are deferred |
| AUT-001 | Recurring and adaptive programs | Scheduler/models/GUI | No new work without explicit scope change | CAM-001, TRN-001, DEL-001 | AUTOMATION | DEFERRED | Existing bounded 2–12 occurrence planner remains supported. Adaptive, new-hire/cohort, difficulty, and remedial automation are intentionally deferred |
| CNT-001 | Campaign-specific micro-training | Content models, authoring GUI, deterministic validator, internal AI role | Approved source evidence produces one bounded lure-specific lesson and knowledge check; independent human review; no LMS/localization/credential collection | WEB-001, TRN-001, UX-001, AI-010 | CONTENT | P1 | Search/filter, minimized preview, clone-as-draft, and generic lesson governance exist. Campaign-specific generation remains; broad variants, localization, course-catalog depth, gamification, and LMS behavior are deferred |
| OBS-001 | Minimum actionable operations telemetry | Telemetry package, APIs/workers, Azure Monitor | Queue age/DLQ, provider/send/readiness/audit state and alerts needed for safe launch/recovery; no PII/token leakage | TOP-001 | OBSERVABILITY | P1 | API health/log correlation, bounded worker snapshots, and strict managed readiness are implemented. Live Azure collection, required alerts, and recovery observation remain. General observability-platform expansion and tracing beyond release diagnosis are deferred |
| ARC-001 | Maintainable modular monolith | Feature splits in four god files; import rules | API snapshots unchanged; bounded feature modules; no new service; cross-app import guard | Stable P0 product APIs | REFACTOR | P2 | Content-library routes split; four earlier dead helpers removed 35 lines; unused clone adapter removal reduced another 87 lines with 36+5 tests. Broader `routers.py`, `console.py`, `app.js`, and `jobs.py` decomposition remains |
| DOC-001 | Documentation states verified truth | README, runbooks, architecture, ADRs, threat model, provider matrix | One status source; implemented/local/staging/production labels; data/trust flows; recovery and support matrix; stale claims removed | All P0 gates | DOCS | P1 | Wave 36 reconciliation records checked-in head `0030`, privacy/AI/ACS/proxy/worker-health contracts, historical `0029`/test evidence, and workflow digest `6868067ef5d58c799bc4a07dd832d4852d38dee73e6ff1af9a58c701ce85a4d3`; refresh after final tests/images, browser, and every cloud/provider-live gate |

### Wave 19–29 qualification matrix

These execution tasks refine the product matrix above; they do not create a second readiness decision.

| ID | Outcome | Owner files / target | Acceptance | Depends | Conflict group | Priority | Status |
|---|---|---|---|---|---|---:|---|
| W19-PG | Current database qualification | PostgreSQL test instance, migrations, fixture cleanup | Warning-strict no-skip PostgreSQL profile; fresh base/historical-to-head; exact head; no leaked test resources | REL-001 | DB | P0 | **Complete:** 83 passed/1,634 deselected; fresh migration 1 passed; head `0027`; cleanup leaks repaired |
| W19-REDIS | Current queue qualification | Redis test instance and queue contracts | Expanded Redis profile passes with skip rejection | QUE-001 | QUEUE | P0 | **Complete:** 2 passed/1,713 deselected, 0 skipped |
| W19-IMG | Exact current native images | Four application images plus mock services | Build, hardening/startup checks, Trivy 0 HIGH/CRITICAL/secrets | REL-001, TST-001 | IMAGE | P0 | **Partial:** four exact-current native ARM64 application images passed. Mock passed after its Debian repair but changed afterward and needs a rerun; AMD64 cold cross-build timed out; registry remains open |
| W20-AZ | Azure prerequisite audit and preflight hardening | Read-only subscription/tenant inspection; Azure scripts/tests | Identify authority/location/providers/resources without changing workload state; focused contracts pass | GOV-002, DEP-001 | AZURE | P0 | **Complete for prerequisite audit:** subscription/tenant, Owner, `eastus2`, and required providers including `Microsoft.Communication` ready; 56 focused tests pass with 1 pre-existing live skip. No backend/foundation/apps/resources. GitHub auth/repository/Actions/workflow now pass read-only inspection; protected configuration, final-source sync, dispatch, and Azure apply remain open |
| W20-EGR | Egress/content packaging repair | Source adapters and downstream content contracts | Focused and downstream suites pass | EGR-001, WEB-001 | EGRESS | P1 | **Complete:** 180 focused and 35 downstream tests passed |
| W20-E2E | Local recovery, stack, E2E, and browser qualification | Disposable local runtime and evidence only | Recovery completes; E2E/browser gates pass without skips; record exact evidence | W19-PG, W19-REDIS, W19-IMG | LOCAL-RUNTIME | P0 | **Partial:** `verify-install` green and 7 E2Es pass with 0 skips/warnings in 3.37s; targeted audit repair is not full restore evidence. Wave 30 static accessibility-shell contracts pass; real browser/WCAG/assistive-technology evidence remains open |
| W20-DOC | Evidence reconciliation | Canonical plan and navigation/runbook documents | Remove stale Docker/head claims; preserve evidence labels and NO-GO | Completed W19/W20 evidence | DOCS | P1 | **Complete:** Wave 19/20 evidence reconciled |
| W21-AUTH | Shared RoE/RBAC hardening | Authorization/domain models and API/worker consumers | Strict typed/canonical invariants; consumer-inclusive security/static/package gates pass | IAM-001, GOV-001 | AUTH | P0 | **Complete:** 374 tests plus Ruff/mypy, Bandit/Semgrep 0, offline build/import |
| W21-CI | Release workflow hardening | Azure workflow and release contracts | Explicit linux/amd64; immutable digest/attestation subjects; credential-safe execution; audited workflow binding | TST-001 | CI | P0 | **Complete:** 23 tests, Actionlint, Zizmor; SHA-256 `03686ddd51aa301ff829e3c6a78ed5d3322fc63277e20cdbeeb7c42a1de3baaa` |
| W21-DEAD | Remove abandoned clone adapter | Source-adapter clone module/exports | Dead path removed; owned and downstream tests pass | EGR-001 | EGRESS | P1 | **Complete:** net -87 lines; 36 focused plus 5 downstream passed |
| W21-IMG | Rebuild all five native ARM64 images | Application and mock images | Startup/hardening plus 0 HIGH/CRITICAL/secrets and focused image contracts | W21-AUTH, W21-CI | IMAGE | P0 | **Point-in-time pass:** five IDs/sizes recorded; scans pass and 30 focused pass. Later operator/runtime source edits require final-tree rerun; AMD64/registry open |
| W21-TF | Reconcile current Azure provider resources | Terraform provider schema/resources/tests | Integrated format/validate/contracts with no cloud inference | W20-AZ | TERRAFORM | P0 | **Point-in-time local/static pass:** 43 tests plus provider-backed `terraform init -backend=false` and `terraform validate -no-color`; no remote backend or Azure apply |
| W22-MAIL | Local delivery/training canary | Loopback Mailpit and explicit seeded `example.com` account | One canonical send; recipient-bound lifecycle; knowledge check; report/audit correlation; retry does not resend | MAIL-001, TRN-001 | LOCAL-MAIL | P0 | **Point-in-time local-live pass:** 123 focused plus 1 isolated canary in 2.03s; exact canary cleanup; no external/provider call |
| W22-OUTBOX | Outbox UUID and reconciliation repair | Database outbox completion/reconciliation | Native UUID binding; bounded diagnostics; stale local intents reconcile | QUE-001, AUD-001 | OUTBOX | P0 | **Point-in-time local pass:** 29 hermetic + 5 logging + 1 isolated PostgreSQL; 29 stale intents drained, final stale/failed/overdue 0 |
| W22-PROVIDERS | Provider seam hardening | Graph, Microsoft 365, ACS events, reported MIME | Bounded, authenticated, idempotent local contracts; explicit ACS managed-identity client ID | M365-001, M365-002, MAIL-001 | PROVIDERS | P0 | **Point-in-time local/static pass:** 92 owned + 119 adjacent; no live tenant/provider call |
| W22-FLAGS | Server-derived actions/privacy bounds | Campaign/pattern routes and privacy boundaries | GUI actions consume authoritative flags; request/result shapes bounded | CAM-001, IAM-001 | OPERATOR | P1 | **Point-in-time local pass:** 10 hermetic + 29 PostgreSQL + 103 route/boundary |
| W22-GH | Deployment connector hardening | GitHub connector and route authorization | Protected environment/workflow/ref/content and run identity/status validation; owner-bound Redis leases | DEP-001 | CONNECTOR | P0 | **Point-in-time local/static pass:** 92 focused + 96 including route auth. Current auth/repository/Actions/workflow inspection is valid; environments/variables/secrets/branch protection/final-source sync and dispatch remain open |
| W23-WORKER | Worker wiring/dead-path repair | Multi-role worker jobs/supervisor/reminders | Preflight/context cleanup; bounded reminders/retention; dead paths removed; deterministic shutdown | TOP-001, QUE-001 | WORKER | P0 | **Point-in-time local/static pass:** 355 hermetic / 5 PostgreSQL tests deselected |
| W24-DOC | Reconcile Waves 22–23 evidence | Canonical plan and navigation/runbook documents | Record completed local evidence and exact blockers without code/config changes | Completed Waves 22–23 tasks | DOCS | P1 | **Complete:** final images, browser/WCAG, GitHub/Azure/provider live, recovery/rotation, and witness gates remain open |
| W24-BOUNDS | Bound collections and authorization scans | Operator API/GUI collection routes and scheduling RoE selection | Deterministic database pagination; bounded browser traversal; fail closed before excessive RoE signature scans | CAM-001, GOV-001 | OPERATOR | P1 | **Point-in-time local/static complete:** user-facing collections bounded; covering-RoE candidate cap 100; current authorization manifest 113 = 103 protected + 10 dedicated/public |
| W24-LOCK | Order scoped stop and delivery | Campaign stop API and worker delivery locking | Shared/exclusive PostgreSQL campaign lock proves deterministic contention; lifecycle/security gates pass | OPS-001, DEL-001 | WORKER-DB | P0 | **Point-in-time local pass:** 52 focused in 1.30s; 15 isolated PostgreSQL in 3.07s including 250ms contention; scoped-kill persistence 1 isolated migrated-PostgreSQL pass in 2.88s at `0027`, disposable DB dropped; exploratory ACS pacing reserved 3 then 0 in one window |
| W24-SIMPLE | Remove blind alleys and false-success controls | Entrypoints, settings, local control and signing surfaces | No broken installed seeder, ignored setting, remote stop/marker, or successful no-op signing target | REL-001, TOP-001 | SIMPLICITY | P1 | **Complete locally:** source `make seed` retained; fixed 72h training due policy; GUI restart retained; process-stop capability/marker retired from browser, supervisor, and launcher; host signal stops launcher; 39 focused tests passed; `make sign` requires immutable IMAGE + COSIGN_KEY + cosign. No external signing evidence |
| W29-RECOVERY | Preserve local deployment identity and fail closed before mutation | Compose identity, `.env` bootstrap, deployment preflight, base-image qualification, launchers, recovery evidence | Fixed project/volume identities; no replacement credentials over preserved state; minimized command environments; `prestart`/`ready`; exact-cache offline probes including Redis UID/write; checkpoint/reconcile only; no automatic cleanup | REL-001, TST-001 | LOCAL-RECOVERY | P0 | **Complete for preservation/cutover restore:** the dated controller capacity gates blocked safely; Wave 30 then passed the fresh encrypted checkpoint, no-clobber staging, clean external restore, migration/seed, and installation verification. Exact-final images and production recovery evidence remain unwitnessed |

## Next implementation waves

The goal-aligned matrix is the dependency source of truth. Historical waves
below explain the current tree; they do not authorize unfinished commercial
parity work. Each new wave must integrate serially, pass its focused and central
gates, and recheck the merged tree before final-image evidence is produced.

### Alignment Wave A — settle contracts and repair false paths

Approve and encode `ORG-001`, `OUT-001`, `RET-005`, `MAIL-005`, and `AI-005`.
Then run `THR-001A`, `IMP-001`, `INT-001`, and `DOCSIM-001` under conflict
control. Current-head PostgreSQL/Redis/E2E qualification accompanies database
or event changes; no feature may silently widen raw-data retention.

Exit: a two-person workflow with no self-approval; honest outcome/provider
language; reviewed retention and internal-model decisions; complete source
evidence into generation; guided CSV import; confirmed interaction; and no
broken document-tracking claim.

### Alignment Wave B — complete the minimum operator product

Run `THR-001B`, `AI-010`, `TRN-010`, and `ANA-010`. Preserve the existing
three deployables by reusing the worker image/role for inference unless the
benchmark proves that impossible. Do not start adaptive programs, broad content
variants, scheduled reports, or LMS work.

Exit: an operator can curate a source-backed current threat, request a safe
internal-model draft, independently approve it, bind a relevant micro-lesson,
and view named disposition plus five-year awareness trend.

### Alignment Wave C — simplify deployment and integration

Run `DEP-010` and the necessary `DEP-001`/`MAIL-001`/`M365-001`/`M365-002`
live closures. Replace manual identifiers with Azure discovery, keep
deterministic defaults when AI is unavailable, put engineering detail under
Advanced, and keep ACS recommended/SMTP advanced.

Exit: a two-person team can complete the documented bootstrap and every normal
deployment, mail/directory/report integration, readiness, rollback, and recovery
step through the GUI without understanding GitHub Actions or Terraform.

### Alignment Wave D — exact production qualification

Run `QA-030` and `PROD-030` only against the final behavior and exact images.
Required evidence remains current-head database/queue/E2E, native release
architecture and registry attestations, disposable Azure, Entra role separation,
Graph/Outlook/ACS/Event Grid/DNS/inbox canaries, browser/WCAG/human acceptance,
audit witness, backup/restore, and recovery/rotation exercises.

Exit: a documented production/RSA `GO`; otherwise the decision remains NO-GO.

### Alignment Wave E — bounded simplification only

After the production loop is stable, consolidate navigation and split oversized
modules inside the current deployables. Remove dead source fields only after the
operator workflow has shown they are unnecessary. All explicitly deferred work
remains unscheduled.

### Execution ledger through Wave 22

- **Waves 0–4 foundation:** repaired fresh migrations/package closure, Entra semantics, authorization keys, workload/database boundaries, RoE v2, audit/outbox, idempotent delivery, training remediation, frozen audiences, token storage, content/egress controls, distributed runtime controls, and persistent emergency stop.
- **Wave 5:** delivered atomic queue/DLQ GUI, privacy-safe metrics/correlation, pinned supply-chain/SBOM/provenance evidence, and release-image verification.
- **Wave 6:** delivered consolidated worker topology, complete M365 directory/report ingestion, ACS custom-domain/readiness and authenticated minimized receipt ingestion, campaign readiness/preview, and documentation truth reconciliation.
- **Wave 7:** removed all release-image HIGH/CRITICAL findings, added database invariants through 0024, typed UUID boundaries, reviewed GUI workflow dispatch, accurate campaign analytics, explicit locked test-account backend, and deterministic application resource cleanup. The central local gate passed.
- **Wave 8:** completed test-account GUI, bounded reusable content libraries, immutable deployment workflow/ref/environment binding with last-moment drift checks, and a create-only audit-head witness in locked Azure Blob storage. Central code, local PostgreSQL/Redis, and source-security gates passed; the image refresh was deferred and later closed by the post-Wave 9 evidence gate.
- **Wave 9:** added migration 0025 and the GUI-driven finite Program Planner for 2–12 independently reviewed occurrences with allowlisted elapsed-day cadence, duplicate-safe materialization, and forward-only pause/resume. Added bounded longitudinal Executive Trends JSON/CSV/GUI with explicit weighted denominators and transport/training semantics; retired unsafe legacy tracking correction ingestion as a stable 410/no-write boundary while deferring normalized dual-reviewed corrections. Split content-library routes from the oversized operator router, added bounded unexpected-error logging, and made operator HSTS/edge/recovery readiness truthful as local contract evidence only.
- **Post-Wave 9 image snapshot:** fixed and regression-guarded a worker image verifier omission for the audit-anchor database password, then rebuilt all four isolated Chainguard/Wolfi images. Entrypoint/API/worker/database-migration smoke checks passed, and every image scanned at 0 HIGH / 0 CRITICAL vulnerabilities and 0 secrets. At that point the result proved the dependency/runtime base only; Wave 19 later superseded it for the four native ARM64 application images.
- **Wave 10:** made the console session, visible navigation, and actions capability-aware and fail closed on invalid/stale authority. Added repeatable, authorized, audited source enable/disable/manual-ingest backend and GUI operations, later strengthened by Wave 11's post-fetch disable fence. Preserved the retired correction endpoint as 410/no-write, and replaced 21 production traceback or exception-message logging sites across worker/outbox/supervisor and audit/scheduler/rate-limiter paths with bounded event/type metadata without changing retry, DLQ, or fail-closed behavior. The Wave 10 broad local suite passed 1,232 of 1,240 selected tests with 8 environment-gated skips and no failures, and the no-skip audit-anchor permission acceptance passed separately. Its focused logging regressions passed 37 tests with no production `logger.exception`, `.exception`, or `exc_info=True` remaining in applications, packages, or scripts. No live cloud, provider, browser, recovery, or witness capability is claimed.
- **Interrupted local readiness attempt after Wave 10:** the first database upgraded 0013→0025, then disk exhaustion caused an environmental cascade. Generated caches alone were removed and disk capacity recovered, but the shared Docker daemon remained unresponsive; seven running-stack E2Es therefore remained unqualified. Wave 12 repaired their contracts and the harness but did not execute them live. This interruption is not classified as a product failure.
- **Wave 11:** replaced durable queue-outbox exception strings with the fixed `queue_dispatch_failed` code while preserving retry transitions and bounded type/reference logs. Added a post-fetch `FOR UPDATE` source-state fence so a concurrent disable discards fetched material before source-item/pattern writes. Stabilized operator key/configuration, template, and audience error responses so arbitrary exception text is not reflected. Focused component suites passed (15 outbox/migration; 11 ingestion-fence plus the worker suite with 5 existing environment skips; 45 content/sending/boundary including 20 live-PostgreSQL no-skip), with a central 9-test outbox/ingestion integration rerun. This is not a new full-suite result.
- **Wave 12:** repaired the local qualification harness to fail fast on disk, bounded Docker/Compose responsiveness, and required service health; aligned install verification with the actual supervisor child map and truthful `/readyz`; and made the E2E target reject skips. Repaired all seven live-console E2Es for the current frozen-audience workflow, five-step ACS wizard, server-derived authority, and local web alerts without external `ntfy`; collection/static checks pass and hermetic selection excludes them, while the no-skip gate correctly rejects execution without explicit live credentials/lifecycle opt-in. The live stack was unavailable, so no E2E pass is claimed. Hardened authentication/RBAC error translation. Focused evidence: 4 readiness tests and 85 auth/RBAC no-skip tests.
- **Wave 13:** removed the obsolete corrections shared secret from runtime settings, examples, and Terraform/Key Vault while preserving the unconditional 410/no-write compatibility path; removed four uncalled/unexported production helpers—`monotonic_timestamp`, `build_email_body`, `parse_sending_domains`, and `SafetyValidatorError`—for a net 35-line reduction; and allowlisted analytics evidence-window/trend validation errors. Focused evidence: 56 retired-secret no-skip tests plus Terraform validation, 107 dead-code regression tests, and 26 analytics no-skip tests. Central reruns reproduced those 56 and 26-test results. This is not a commercial-parity or production-readiness claim.
- **Wave 14:** hardened local launcher failure/ownership boundaries and deterministic supply-chain evidence contracts; expanded stable, non-reflective deployment and configuration error handling; and reconciled documentation truth. These were focused/local closures only. They did not rebuild images or qualify a running stack, registry, dependency/vulnerability state, browser, Azure, providers, restore, or the external witness.
- **Wave 15:** separated hermetic, PostgreSQL, Redis, E2E, and Azure-live tests into explicit no-skip profiles and made operational readiness run them after bounded disk/Docker/Compose/service preflight without printing connection URLs. Hardened public tracking, recipient-bound training links, directory preview fencing, and secret-safe managed settings. It implemented the earlier two-phase Azure GUI/workflow/Terraform contract and workflow security controls. Its focused evidence is historical; Wave 30 later replaced that contract with exact live ACS readback/verification initiation and froze the reviewed three-stage connector digest. No production or commercial-parity claim is made.
- **Wave 16:** pinned all external local Compose and mock base images to immutable manifest digests, hash-locked the full 17-package mock runtime, froze normal workspace bootstrap/development/console dependency use, and made dependency audit and native CycloneDX 1.5 SBOM generation consume the full external production workspace closure. The corrected audit gate fails closed before scanning when export fails; pinned `pip-audit` 2.10.1 reported zero known vulnerabilities across 58 external packages on 2026-08-27. The SBOM contains 59 total components/58 external PURLs. Public OpenAPI/docs/metrics routes and the operator/tracking write-only metric registries are absent, audit verification retains aggregate state instead of raw problem details, GUI auth-mode discovery fails closed, and test-only `httpx2` restores official Starlette `TestClient` compatibility. Versioned bounded ciphertext and legacy/recovery keyring support are implemented. Managed active rotation is intentionally blocked: the active ID is immutable after first foundation, the active KEK remains in Terraform state/history, and `prevent_destroy` complicates teardown. Safe pre-stage/prove/promote and bulk re-encryption remain debt.
- **Wave 17:** completed warning-strict SQLite resource/outbox cleanup, duplicate `Content-Length` rejection, and the non-Azure GUI/RBAC wiring audit. All 104 then-current operator routes had explicit reviewed authority; browser/backend capability sets matched exactly; Help was aggregate-readable; author/reviewer template actions retained separate privileges; and visible actions avoided stale or unauthorized paths. An intermediate 1,261-pass/85-deselected warning-strict run excluded concurrent deployment/readiness work. The final Wave 17 tree hermetic command passed 1,379 with 85 deselected, 0 skipped, and 0 warnings in 59.05 seconds; `uv lock --check` and `git diff --check` passed. Docker remained unavailable, so no application-image, running-stack, registry, Azure/provider, browser, recovery, or external-witness evidence was claimed.
- **Wave 18:** unified generation request/response/storage/delivery limits and made generation idempotent across queue retries, locks, races, audit, and provider calls. Added server-side campaign/source/privacy/correction/rationale validation; current source-terms acknowledgement/revocation across API, worker fences, and GUI; bounded provider response readers for OIDC, setup assistance, generation, and GitHub orchestration; and capped non-reflective operator/tracking validation responses. Added migration `0026` for the governed training-resource library/least-privilege grants and migration `0027` for durable recipient-exclusion expiry/revocation history. At the Wave 18 close, only targeted live `0025`→`0026` preservation/write-bound/least-privilege evidence had passed; Wave 19 later closed the full current-head PostgreSQL gate. Wave 18 also completed response-derived training actions, reporting/alerts, exclusion management, server-side recipient pagination, and deterministic PostgreSQL fixture cleanup. At that point-in-time, the authorization inventory reached 111 operator routes; it is not the current route count. Its closing warning-strict hermetic gate passed 1,622 tests with 91 deselected, 0 skipped, and 0 warnings in 67.68 seconds; fresh-cache `uv lock --check` resolved 90 packages in 4 ms and `git diff --check` was clean. The broad quality/static/security/dependency/SBOM gates and 104-test focused bundle also passed with exact counts above. No KnowBe4 parity or production-readiness claim is made.
- **Wave 19:** restored Docker-backed qualification without deleting or restarting unrelated workloads. The warning-strict, no-skip PostgreSQL profile passed 83 tests with 1,634 deselected; the fresh base/historical-to-current-head gate passed 1 test and confirmed head `0027`; test-resource leaks were repaired. The expanded Redis profile passed 2 tests with 1,713 deselected and no skips. Four exact-current native ARM64 application images passed hardening/startup checks and Trivy at 0 HIGH / 0 CRITICAL vulnerabilities and 0 secrets. The mock image passed after repairing its Debian packaging defect, but later mock Graph source changes require a rerun. A cold AMD64 cross-build timed out, and no registry publication/attestation is claimed.
- **Wave 20:** historical read-only Azure inspection confirmed an authorized subscription/tenant, subscription Owner, `eastus2`, required provider readiness including `Microsoft.Communication`, and absence of a deployment backend, foundation resource group, Entra applications, and application resources; the GitHub token was invalid at that observation. The 2026-08-29 GitHub re-audit supersedes that token fact: auth/repository/Actions/workflow are valid and no billing-disabled signal exists, but zero protected configuration/rulesets/runs, disabled repository secret protections, and old remote source still block deployment. The 2026-08-29 Azure re-audit was DNS-blocked, so the historical Azure inventory is not current management-plane proof. No workflow dispatch/run or Azure workload mutation occurred. Azure script/preflight repairs passed 56 tests with 1 pre-existing live skip. Egress/content repairs passed 180 focused plus 35 downstream tests.
- **Wave 21:** repaired the disposable local bootstrap/audit state using a backup plus targeted reset/seed and corrected token-key, PID/log, mock Graph, and fixture defects. `verify-install` is green; the strict E2E profile passed all 7 tests with 0 skips and 0 warnings in 3.37 seconds. The repair is not a full restore qualification. Shared RoE/RBAC types, canonicalization, bounded signing, domain/window checks, denial minimization, and campaign/program/training invariants passed 374 owned/consumer tests plus static, security, and offline package gates. CI now explicitly builds `linux/amd64`, verifies immutable ACR digests and digest-bound evidence, prevents credential persistence/material in reviewed input, and removes ephemeral registry credentials; 23 tests, Actionlint, and Zizmor passed at workflow SHA-256 `03686ddd51aa301ff829e3c6a78ed5d3322fc63277e20cdbeeb7c42a1de3baaa`. Removing the dead clone adapter reduced the tree by 87 lines and passed 36 focused plus 5 downstream tests. All five native ARM64 images passed at the recorded snapshot with 30 focused tests and 0 HIGH / 0 CRITICAL / 0 secrets, but later source edits require a final-tree rerun. AMD64/registry remain unwitnessed. Browser automation was tool-blocked at this historical point; Wave 30 later added static accessibility-shell coverage without claiming live browser/WCAG evidence.
- **Wave 22:** completed focused local lanes for the Mailpit training/knowledge-check lifecycle, native-UUID outbox completion and reconciliation, Graph/Microsoft 365/ACS-event/reported-MIME boundaries, explicit ACS managed-identity client selection, recovered Terraform provider validation, server-derived campaign/pattern flags and privacy bounds, and GitHub protected-environment/workflow/run plus Redis-lease validation. Exact point-in-time counts are recorded above and overlap. The Mailpit canary made no external call; GitHub authentication remained invalid and no GitHub call or Azure apply occurred.
- **Wave 23:** repaired worker preflight/context cleanup, reminder-client lifetime, bounded and idempotent retention, delivery validation, cadence scheduling, and dead supervisor/helper paths. The final point-in-time hermetic worker lane passed 355 tests with 5 PostgreSQL tests deselected. This is not a broad-suite or provider-live result.
- **Wave 24:** bounded deterministic database pagination across user-facing collections and capped covering-RoE scheduling at 100 candidates; replaced application/worker runtime `assert` guards with explicit failures; and added shared/exclusive campaign locks that order scoped stop against delivery. Worker lifecycle/security passed 52 focused tests in 1.30 seconds; the isolated PostgreSQL lane passed 15 in 3.07 seconds, including 250 ms lock contention; an exploratory PostgreSQL ACS pacing proof reserved 3 and then 0 sends in one window. A separate isolated migrated-PostgreSQL scoped-kill persistence test passed 1 in 2.88 seconds at `0027`, then dropped its disposable database. The wave also removed the broken installed `kp-seed`, ignored reminder/Mailpit-TLS/queue-prefix settings, and remote full-stack stop endpoint/capability/marker across the browser, supervisor, and launcher; retained source `make seed`, GUI restart, host-signal launcher shutdown, and a fixed 72-hour training due policy; and made `make sign` require an immutable image digest, `COSIGN_KEY`, and `cosign`. The stop-removal lane passed 39 focused tests. Its subsequent warning-strict hermetic snapshot passed 1,899 tests with 98 deselected; later source changes superseded that count. No production, RSA, or commercial-parity claim is made.
- **Wave 29:** recovered the local deployment path without deleting or replacing state. Compose project and volume names are fixed; incomplete recovery credentials fail closed around existing/uninspectable volumes; preflight environments are command-specific; `prestart` and `ready` bracket mutation; cached exact platform images qualify offline; and Redis proves its configured UID/GID plus disposable data-directory writes. At the earlier 8.7 GiB snapshot both default preflight phases were green; at the then-current 5.6 GiB snapshot they blocked only on disk headroom while all other checks passed. Final acceptance passed hermetic 1,994/98 in 111.95 seconds, PostgreSQL 87, Redis 2 on DB15, restart verification, and 8 live E2Es, plus the recorded quality/security gates. It fixed the audit-store owner-fallback revocation defect, reconciled 36 stranded idempotent queue intents, and left the audit chain green. Wave 29 source edits made interim images stale; the release-image gate reported 5,922,200 KiB below 10 GiB and exited before temporary-directory creation or Docker. Wave 30 later completed the preservation-first external cutover/restore. Full current release qualification remains open.
- **Wave 36:** advanced the checked-in migration chain to `0030_default_privacy_notice` for a persisted safe default and database-enforced single-current invariant; separated privacy request operations from notice-load failure; required an approved managed AI `/propose` plus `/setup-assist` gateway; and made pattern approval record a durable request without claiming asynchronous generation completion. It reconciled GUI/API/Terraform/preflight ACS endpoint exactness, added bounded Container Apps trusted-proxy/right-to-left XFF handling with Uvicorn rewriting disabled, and made the managed health checkpoint require exactly one healthy current worker revision with every enabled role simultaneously ready twice and unchanged at final recheck. The release scanner now binds an expected source-manifest digest and exact Trivy executable/hash/cache, retains empty config/ignore/secret policy files, rejects ambient `TRIVY_*`, records fresh database/check-bundle metadata, and makes the verified cache immutable. The connector digest is `6868067ef5d58c799bc4a07dd832d4852d38dee73e6ff1af9a58c701ce85a4d3`. The final local hermetic suite passed 2,501/97 with 0 failures in 183.40 seconds. External `0030` profiles, exact-final images, live Azure telemetry/ingress, AI-provider, and every other cloud/browser/recovery/human gate remain open.

Wave 29's closing recovery audit added `--no-recreate`, pre-sync recovery-key
and credential validation, bounded and ambiguity-rejecting Docker evidence,
frozen migration/audit/seed execution, and PID-plus-readiness fast-path checks.
The release verifier now refuses pre-existing evidence tags and removes only
uniquely named resources it proved it created. Supervisor PID publication and
launcher publication are atomic/recoverable, and unconfirmed child shutdown
blocks restart while retaining evidence. Existing Entra application identity
and its exact eight-role contract are now validated before the first bootstrap
cloud mutation and revalidated at point of use. The closing local/Entra/release
focused lanes passed 71, 68 with one environment-only skip, and their recorded
release regressions respectively; the integrated skip- and warning-strict gate
supersedes their overlapping counts above. No live Azure or Docker mutation was
performed by those audits.

## Central gates

Every integrated wave must pass, in order:

1. Diff ownership, secret leakage, and migration review.
2. Ruff/format and strict type checking.
3. Unit tests with zero environment-dependent behavior.
4. PostgreSQL/Redis integration tests with zero unexplained skips.
5. Fresh-install and historical-upgrade migration tests.
6. Security, dependency, secret, IaC, and container scans.
7. Container-image startup and API contract tests.
8. Browser accessibility and complete user-journey tests.
9. Disposable Azure deployment and provider canaries when a task claims Azure/Microsoft 365 support.
10. RSA readiness exercise before any production pilot.

## Definition of production-ready

Production-ready means an authorized administrator can start from a documented bootstrap, complete deployment and upgrades in the GUI, connect Entra/Graph/ACS/Outlook reporting, select a frozen cohort, create and approve safe content, run a canary, launch with a persistent emergency stop, deliver without duplicates, complete assessed training, and export trustworthy outcomes. All P0 tasks and central gates must be complete; no live capability may be inferred from mocks, Terraform validation, skipped tests, or documentation.
